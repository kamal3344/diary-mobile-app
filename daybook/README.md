# Daybook — your private daily diary

## Start it
Double-click **start.bat** (or run `python server.py`). The window shows two addresses:

- **On this PC:** http://localhost:8000
- **On your phone:** `http://<your-PC-IP>:8000`. Your phone must be on the same Wi-Fi. The first time, Windows may ask whether to allow Python on the network. Choose **Private networks** if you want to use it from your phone.

Keep the window open while you use the app. On your phone, use the browser menu and choose **Add to Home screen** to open it like an app.

## Your data
Everything is stored in **daybook.db** (SQLite) next to `server.py`:

| Table | What it holds |
|---|---|
| `users` | name, username, email, password hash (PBKDF2-SHA256 with 200,000 iterations and a per-user salt; the real password is never stored) |
| `sessions` | signed-in devices (tokens stored hashed, expire after 30 days) |
| `otps` | pending 6-digit codes (hashed, 5-minute expiry, 5 attempts) |
| `entries` | your diary pages |

Back up by copying `daybook.db`, or use **Export backup** inside the app.

## Real email codes
Without email settings the server runs in **developer mode**: codes appear on screen and in the server window.

To send real codes by email with Gmail:
1. Turn on 2-Step Verification for your Google account.
2. Create an **App password** at https://myaccount.google.com/apppasswords.
3. Copy `config.example.json` to `config.json` and fill in your Gmail address and the app password.
4. Restart the server. The window should say `Email OTP: ON`.

`config.json` contains a password, so don't share it or upload it anywhere.
