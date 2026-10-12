"""Daybook server: serves the app and a JSON API backed by SQLite.

Run:  python server.py
Uses only the Python standard library.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import socket
import sys
import sqlite3
import threading
import time
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
CONFIG_PATH = Path(os.environ.get("DAYBOOK_CONFIG", BASE / "config.json"))
CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8")) if CONFIG_PATH.exists() else {}
DB_PATH = Path(os.environ.get("DAYBOOK_DB", BASE / "daybook.db"))
HOST = os.environ.get("DAYBOOK_HOST", CONFIG.get("host", "0.0.0.0"))
PORT = int(os.environ.get("DAYBOOK_PORT") or os.environ.get("PORT") or CONFIG.get("port", 8000))
PRODUCTION = os.environ.get("DAYBOOK_ENV") == "production"
SMTP = dict(CONFIG.get("smtp") or {})
# cloud hosts pass secrets as environment variables instead of config.json
for key in ("host", "port", "username", "password", "from"):
    if os.environ.get(f"DAYBOOK_SMTP_{key.upper()}"):
        SMTP[key] = os.environ[f"DAYBOOK_SMTP_{key.upper()}"]
if SMTP.get("password"):
    SMTP["password"] = SMTP["password"].replace(" ", "")  # Google shows app passwords in groups of 4
EMAIL_ENABLED = bool(SMTP.get("host") and SMTP.get("username") and SMTP.get("password"))
if PRODUCTION and not EMAIL_ENABLED:
    # on-screen codes would let anyone reset any password, so never run that way in production
    raise SystemExit("DAYBOOK_ENV=production requires email settings (DAYBOOK_SMTP_*). Refusing to start.")
# pages the Android app is served from; it calls the API across origins
ALLOWED_ORIGINS = {"https://localhost", "http://localhost", "capacitor://localhost"}

SESSION_DAYS = 30
OTP_TTL = 5 * 60
OTP_RESEND = 30
OTP_MAX_ATTEMPTS = 5
PBKDF2_ITERATIONS = 200_000
MOODS = {"", "Great", "Good", "Calm", "Okay", "Low", "Rough"}

# ---------------------------------------------------------------- database
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("PRAGMA foreign_keys = ON")
db.execute("PRAGMA journal_mode = WAL")
lock = threading.Lock()

db.executescript(
    """
    CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY,
        name      TEXT NOT NULL,
        username  TEXT NOT NULL UNIQUE,
        email     TEXT NOT NULL UNIQUE,
        salt      TEXT NOT NULL,
        pw_hash   TEXT NOT NULL,
        verified  INTEGER NOT NULL DEFAULT 0,
        created   INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS otps (
        token        TEXT PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        purpose      TEXT NOT NULL,
        code_hash    TEXT NOT NULL,
        expires      INTEGER NOT NULL,
        resend_after INTEGER NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        remember     INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires    INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS entries (
        id       TEXT NOT NULL,
        user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        date     TEXT NOT NULL,
        title    TEXT NOT NULL DEFAULT '',
        body     TEXT NOT NULL DEFAULT '',
        mood     TEXT NOT NULL DEFAULT '',
        created  INTEGER NOT NULL,
        updated  INTEGER NOT NULL,
        PRIMARY KEY (user_id, id)
    );
    """
)
db.commit()


def q(sql, args=(), one=False):
    with lock:
        cur = db.execute(sql, args)
        rows = cur.fetchall()
        db.commit()
    return (rows[0] if rows else None) if one else rows


# ---------------------------------------------------------------- helpers
class ApiError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


def now():
    return int(time.time())


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS).hex()


def check_pw(pw, user):
    return hmac.compare_digest(hash_pw(pw, user["salt"]), user["pw_hash"])


def strength(pw):
    s = sum([len(pw) >= 8, bool(re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)),
             bool(re.search(r"\d", pw)), bool(re.search(r"[^A-Za-z0-9]", pw))])
    return min(s, 1) if len(pw) < 8 else s


def check_new_pw(pw):
    if not isinstance(pw, str) or strength(pw) < 2 or len(pw) > 200:
        raise ApiError(400, "Please choose a stronger password (8+ characters, mix letters, numbers & symbols)")


def mask(email):
    a, b = email.split("@", 1)
    return a[:2] + "•" * max(2, len(a) - 2) + "@" + b


def public_user(u):
    return {"name": u["name"], "username": u["username"], "email": u["email"]}


def find_user(ident):
    ident = (ident or "").strip().lower()
    return q("SELECT * FROM users WHERE email = ? OR username = ?", (ident, ident), one=True)


def new_session(user_id):
    token = secrets.token_urlsafe(32)
    q("INSERT INTO sessions VALUES (?, ?, ?)", (sha(token), user_id, now() + SESSION_DAYS * 86400))
    return token


# brute-force throttle for password attempts: key -> [failures, locked_until]
_fails = {}


def throttle_check(key):
    f = _fails.get(key)
    if f and f[1] > time.time():
        raise ApiError(429, f"Too many attempts. Try again in {int(f[1] - time.time()) + 1}s")


def throttle_fail(key):
    f = _fails.setdefault(key, [0, 0])
    f[0] += 1
    if f[0] >= 5:
        f[0], f[1] = 0, time.time() + 30


# ---------------------------------------------------------------- OTP + email
PURPOSE_TEXT = {"login": "sign in to", "signup": "verify your email for", "reset": "reset your password on"}


def send_email(to, code, purpose):
    msg = EmailMessage()
    msg["Subject"] = f"Your Daybook code: {code}"
    msg["From"] = SMTP.get("from") or SMTP["username"]
    msg["To"] = to
    msg.set_content(
        f"Your Daybook verification code is {code}\n\n"
        f"Use it to {PURPOSE_TEXT[purpose]} Daybook. It expires in 5 minutes.\n"
        "If you didn't request this, you can ignore this email."
    )
    msg.add_alternative(
        f"""<div style="font-family:Georgia,serif;max-width:420px;margin:auto;padding:32px;background:#0E0D12;color:#F3EFE6;border-radius:20px">
        <div style="font-size:22px">Daybook</div>
        <p style="font-family:Arial,sans-serif;color:#8E8A99">Use this code to {PURPOSE_TEXT[purpose]} Daybook:</p>
        <div style="font-family:Arial,sans-serif;font-size:34px;letter-spacing:10px;color:#D4AF6A;font-weight:bold;margin:18px 0">{code}</div>
        <p style="font-family:Arial,sans-serif;color:#8E8A99;font-size:13px">It expires in 5 minutes. If you didn't request this, ignore this email.</p></div>""",
        subtype="html",
    )
    port = int(SMTP.get("port", 587))
    if port == 465:
        with smtplib.SMTP_SSL(SMTP["host"], port, timeout=20) as s:
            s.login(SMTP["username"], SMTP["password"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP["host"], port, timeout=20) as s:
            s.starttls()
            s.login(SMTP["username"], SMTP["password"])
            s.send_message(msg)


def deliver_code(user, token, code, purpose):
    out = {"otpToken": token, "maskedEmail": mask(user["email"]), "resendIn": OTP_RESEND, "purpose": purpose}
    if EMAIL_ENABLED:
        try:
            send_email(user["email"], code, purpose)
        except Exception as e:  # surface delivery problems instead of failing silently
            print(f"[email] failed to send to {user['email']}: {e}")
            raise ApiError(502, "We couldn't send the email. Check the email settings in config.json.")
    else:
        print(f"[dev] {purpose} code for {user['email']}: {code}")
        out["devCode"] = code  # no email configured: the app shows the code on screen
    return out


def issue_otp(user, purpose, remember=True):
    q("DELETE FROM otps WHERE user_id = ? OR expires < ?", (user["id"], now()))
    token, code = secrets.token_urlsafe(24), f"{secrets.randbelow(10**6):06d}"
    q("INSERT INTO otps (token, user_id, purpose, code_hash, expires, resend_after, remember) VALUES (?,?,?,?,?,?,?)",
      (token, user["id"], purpose, sha(token + code), now() + OTP_TTL, now() + OTP_RESEND, int(bool(remember))))
    return deliver_code(user, token, code, purpose)


# ---------------------------------------------------------------- API
def api_signup(b, _):
    name = str(b.get("name", "")).strip()[:80]
    username = str(b.get("username", "")).strip().lower()
    email = str(b.get("email", "")).strip().lower()
    pw = b.get("password", "")
    if not name:
        raise ApiError(400, "Please enter your name")
    if not re.fullmatch(r"[a-z0-9_.]{3,20}", username):
        raise ApiError(400, "Username: 3–20 letters, numbers, _ or .")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]{2,}", email) or len(email) > 200:
        raise ApiError(400, "Please enter a valid email")
    check_new_pw(pw)
    # an unverified signup can be retried; a verified account cannot be overwritten
    for col, val, msg in (("email", email, "An account with this email already exists"),
                          ("username", username, "That username is taken")):
        existing = q(f"SELECT * FROM users WHERE {col} = ?", (val,), one=True)
        if existing and existing["verified"]:
            raise ApiError(409, msg)
        if existing:
            q("DELETE FROM users WHERE id = ?", (existing["id"],))
    salt = secrets.token_hex(16)
    q("INSERT INTO users (name, username, email, salt, pw_hash, created) VALUES (?,?,?,?,?,?)",
      (name, username, email, salt, hash_pw(pw, salt), now()))
    return issue_otp(find_user(email), "signup")


def api_login(b, _):
    ident = str(b.get("id", "")).strip().lower()
    pw = b.get("password", "")
    if not ident or not pw:
        raise ApiError(400, "Please enter your email/username and password")
    throttle_check(ident)
    user = find_user(ident)
    if not user or not check_pw(str(pw), user):
        throttle_fail(ident)
        raise ApiError(400, "Incorrect email/username or password")
    _fails.pop(ident, None)
    return issue_otp(user, "login" if user["verified"] else "signup", b.get("remember", True))


def api_forgot(b, _):
    user = find_user(str(b.get("id", "")))
    if not user:
        raise ApiError(404, "No account found with those details")
    return issue_otp(user, "reset")


def get_otp(token):
    row = q("SELECT * FROM otps WHERE token = ?", (str(token or ""),), one=True)
    if not row:
        raise ApiError(410, "This code is no longer valid. Please start again.", restart=True)
    return row


def api_otp_verify(b, _):
    row = get_otp(b.get("otpToken"))
    code = str(b.get("code", ""))
    if row["expires"] < now():
        raise ApiError(400, "Code expired — tap resend")
    if not hmac.compare_digest(sha(row["token"] + code), row["code_hash"]):
        attempts = row["attempts"] + 1
        if attempts >= OTP_MAX_ATTEMPTS:
            q("DELETE FROM otps WHERE token = ?", (row["token"],))
            raise ApiError(400, "Too many attempts. Please start again.", restart=True)
        q("UPDATE otps SET attempts = ? WHERE token = ?", (attempts, row["token"]))
        raise ApiError(400, f"Incorrect code · {OTP_MAX_ATTEMPTS - attempts} attempts left")
    q("DELETE FROM otps WHERE token = ?", (row["token"],))
    user = q("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
    if row["purpose"] == "reset":
        rt = secrets.token_urlsafe(32)
        q("INSERT INTO reset_tokens VALUES (?,?,?)", (sha(rt), user["id"], now() + 10 * 60))
        return {"purpose": "reset", "resetToken": rt}
    if row["purpose"] == "signup":
        q("UPDATE users SET verified = 1 WHERE id = ?", (user["id"],))
    return {"purpose": row["purpose"], "token": new_session(user["id"]),
            "remember": bool(row["remember"]), "user": public_user(user)}


def api_otp_resend(b, _):
    row = get_otp(b.get("otpToken"))
    if row["resend_after"] > now():
        raise ApiError(429, f"Please wait {row['resend_after'] - now()}s before resending")
    user = q("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
    return issue_otp(user, row["purpose"], row["remember"])


def api_reset(b, _):
    row = q("SELECT * FROM reset_tokens WHERE token_hash = ? AND expires > ?",
            (sha(str(b.get("resetToken", ""))), now()), one=True)
    if not row:
        raise ApiError(410, "Reset link expired. Please start again.", restart=True)
    pw = b.get("password", "")
    check_new_pw(pw)
    user = q("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
    if check_pw(pw, user):
        raise ApiError(400, "New password must differ from the old one")
    salt = secrets.token_hex(16)
    q("UPDATE users SET salt = ?, pw_hash = ?, verified = 1 WHERE id = ?", (salt, hash_pw(pw, salt), user["id"]))
    q("DELETE FROM reset_tokens WHERE user_id = ?", (user["id"],))
    q("DELETE FROM sessions WHERE user_id = ?", (user["id"],))  # sign out everywhere
    return {"ok": True}


def api_logout(_, ctx):
    q("DELETE FROM sessions WHERE token_hash = ?", (ctx["token_hash"],))
    return {"ok": True}


def api_me(_, ctx):
    return {"user": public_user(ctx["user"])}


def api_password_otp(_, ctx):
    return issue_otp(ctx["user"], "reset")


def entry_row(r):
    return {k: r[k] for k in ("id", "date", "title", "body", "mood", "created", "updated")}


def api_entries_list(_, ctx):
    rows = q("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC, created DESC", (ctx["user"]["id"],))
    return {"entries": [entry_row(r) for r in rows]}


def clean_entry(e):
    if not isinstance(e, dict):
        raise ApiError(400, "Invalid entry")
    eid, date = str(e.get("id", ""))[:40], str(e.get("date", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", eid) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ApiError(400, "Invalid entry")
    mood = str(e.get("mood", ""))
    ms = int(time.time() * 1000)
    return (eid, date, str(e.get("title", ""))[:200], str(e.get("body", ""))[:200_000],
            mood if mood in MOODS else "", int(e.get("created") or ms), int(e.get("updated") or ms))


def upsert(uid, c):
    q("""INSERT INTO entries (id, user_id, date, title, body, mood, created, updated) VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(user_id, id) DO UPDATE SET date=excluded.date, title=excluded.title, body=excluded.body,
         mood=excluded.mood, updated=excluded.updated""", (c[0], uid, *c[1:]))


def api_entries_save(b, ctx):
    c = clean_entry(b)
    upsert(ctx["user"]["id"], c)
    return {"ok": True}


def api_entries_import(b, ctx):
    items = b.get("entries") if isinstance(b, dict) else None
    if not isinstance(items, list):
        raise ApiError(400, "That file is not a valid Daybook backup")
    uid, n = ctx["user"]["id"], 0
    for e in items[:5000]:
        try:
            c = clean_entry(e)
        except ApiError:
            continue
        if not q("SELECT 1 FROM entries WHERE user_id = ? AND id = ?", (uid, c[0]), one=True):
            upsert(uid, c)
            n += 1
    return {"imported": n}


def api_entries_delete(eid, ctx):
    q("DELETE FROM entries WHERE user_id = ? AND id = ?", (ctx["user"]["id"], eid))
    return {"ok": True}


def api_account_delete(b, ctx):
    user = ctx["user"]
    key = "delete:" + user["email"]
    throttle_check(key)
    if not check_pw(str(b.get("password", "")), user):
        throttle_fail(key)
        raise ApiError(400, "Incorrect password")
    # entries, sessions and codes go with the user via ON DELETE CASCADE
    q("DELETE FROM users WHERE id = ?", (user["id"],))
    return {"ok": True}


ROUTES = {
    ("POST", "/api/signup"): (api_signup, False),
    ("POST", "/api/login"): (api_login, False),
    ("POST", "/api/forgot"): (api_forgot, False),
    ("POST", "/api/otp/verify"): (api_otp_verify, False),
    ("POST", "/api/otp/resend"): (api_otp_resend, False),
    ("POST", "/api/reset"): (api_reset, False),
    ("POST", "/api/logout"): (api_logout, True),
    ("POST", "/api/password/otp"): (api_password_otp, True),
    ("GET", "/api/me"): (api_me, True),
    ("GET", "/api/entries"): (api_entries_list, True),
    ("POST", "/api/entries"): (api_entries_save, True),
    ("POST", "/api/entries/import"): (api_entries_import, True),
    ("POST", "/api/account/delete"): (api_account_delete, True),
}

MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css",
        ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".webmanifest": "application/manifest+json"}


class Handler(BaseHTTPRequestHandler):
    server_version = "Daybook"

    def log_message(self, fmt, *args):
        if "/api/" in str(args[0] if args else ""):
            print(f"[{self.address_string()}] {fmt % args}")

    def send(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def cors_headers(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Vary", "Origin")

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def auth(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise ApiError(401, "Please sign in")
        th = sha(h[7:].strip())
        row = q("""SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires > ?""", (th, now()), one=True)
        if not row:
            raise ApiError(401, "Your session has ended. Please sign in again.")
        return {"user": row, "token_hash": th}

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 5_000_000:
            raise ApiError(413, "Request too large")
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            raise ApiError(400, "Invalid JSON")

    def handle_api(self, method):
        path = urlparse(self.path).path.rstrip("/")
        try:
            if method == "DELETE" and path.startswith("/api/entries/"):
                return self.send(200, api_entries_delete(unquote(path[len("/api/entries/"):]), self.auth()))
            route = ROUTES.get((method, path))
            if not route:
                raise ApiError(404, "Not found")
            fn, needs_auth = route
            ctx = self.auth() if needs_auth else None
            self.send(200, fn(self.body() if method == "POST" else {}, ctx))
        except ApiError as e:
            self.send(e.status, {"error": e.message, **e.extra})
        except Exception as e:
            print("[error]", repr(e))
            self.send(500, {"error": "Server error"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            return self.handle_api("GET")
        pages = {"/": "index.html", "": "index.html", "/privacy": "privacy.html"}
        rel = pages.get(path) or unquote(path.lstrip("/"))
        f = (STATIC / rel).resolve()
        if STATIC.resolve() not in f.parents or not f.is_file():
            return self.send(404, b"Not found", "text/plain")
        self.send(200, f.read_bytes(), MIME.get(f.suffix, "application/octet-stream"))

    def do_POST(self):
        self.handle_api("POST")

    def do_DELETE(self):
        self.handle_api("DELETE")


def lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no packets are sent; picks the LAN interface
            return s.getsockname()[0]
    except OSError:
        return None


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"\n  Daybook is running\n  Database : {DB_PATH}")
    print(f"  Email OTP: {'ON via ' + SMTP['host'] if EMAIL_ENABLED else 'OFF (dev mode: codes shown on screen and here)'}")
    print(f"  On this PC   : http://localhost:{PORT}")
    ip = lan_ip()
    if ip and HOST == "0.0.0.0":
        print(f"  On your phone: http://{ip}:{PORT}   (same Wi-Fi)")
    print("  Press Ctrl+C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
