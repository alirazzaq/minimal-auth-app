# Minimal auth app

A minimal web app that registers users, stores their records in SQLite, and lets them log in.

No dependencies — Python 3 standard library only.

## Run

```bash
python3 app.py        # serves on http://127.0.0.1:8000
python3 app.py 9000   # custom port
```

## How it works

- `GET /` — home page; shows the logged-in user when a session cookie is present.
- `GET/POST /register` — creates an account (username 3-32 chars, password min 8 chars) and logs you in.
- `GET/POST /login` — verifies credentials and starts a session.
- `POST /logout` — ends the session.

Records are held in `users.db` (created next to `app.py` on first run):

- `users` — username plus a salted PBKDF2-HMAC-SHA256 password hash (never the plain password).
- `sessions` — opaque random tokens mapped to users; sent to the browser as an `HttpOnly; SameSite=Lax` cookie.
