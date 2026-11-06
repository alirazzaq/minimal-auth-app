import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
SESSION_COOKIE = "session"
PBKDF2_ITERATIONS = 200_000
USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db = get_db()
    try:
        db.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, "
            "created_at REAL NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "token TEXT PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES users(id), "
            "created_at REAL NOT NULL)"
        )
        db.commit()
    finally:
        db.close()


def db_query(sql, params=(), fetch=False):
    db = get_db()
    try:
        cur = db.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        db.commit()
        return rows
    finally:
        db.close()


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password, stored):
    salt_hex, hash_hex = stored.split("$")
    _, digest = hash_password(password, salt_hex)
    return hmac.compare_digest(digest, hash_hex)


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    db_query(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user_id, time.time()),
    )
    return token


PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 3rem auto; padding: 0 1rem; }}
label {{ display: block; margin: .8rem 0 .2rem; }}
input {{ width: 100%; box-sizing: border-box; padding: .5rem; }}
button {{ margin-top: 1rem; padding: .5rem 1.2rem; }}
.err {{ color: #b00020; }}
</style>
</head>
<body>{body}</body>
</html>"""


def home_page(username):
    if username:
        body = (
            f"<h1>Hello, {html.escape(username)}</h1>"
            "<form method='post' action='/logout'><button type='submit'>Log out</button></form>"
        )
    else:
        body = (
            "<h1>Minimal auth app</h1>"
            "<p><a href='/register'>Register</a> or <a href='/login'>log in</a></p>"
        )
    return PAGE.format(title="Home", body=body)


def register_page(error=""):
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    body = f"""
<h1>Register</h1>
{err}
<form method="post" action="/register">
<label for="u">Username</label>
<input id="u" name="username" required minlength="3" maxlength="32" autocomplete="username">
<label for="p">Password</label>
<input id="p" type="password" name="password" required minlength="8" autocomplete="new-password">
<button type="submit">Create account</button>
</form>
<p>Already have an account? <a href="/login">Log in</a></p>"""
    return PAGE.format(title="Register", body=body)


def login_page(error=""):
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    body = f"""
<h1>Log in</h1>
{err}
<form method="post" action="/login">
<label for="u">Username</label>
<input id="u" name="username" required autocomplete="username">
<label for="p">Password</label>
<input id="p" type="password" name="password" required autocomplete="current-password">
<button type="submit">Log in</button>
</form>
<p>No account yet? <a href="/register">Register</a></p>"""
    return PAGE.format(title="Log in", body=body)


class Handler(BaseHTTPRequestHandler):
    server_version = "MiniAuth/1.0"

    def _send(self, status, body, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, headers=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()

    def _form(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    def _current_username(self):
        token = self._cookie(SESSION_COOKIE)
        if not token:
            return None
        rows = db_query(
            "SELECT u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
            fetch=True,
        )
        return rows[0][0] if rows else None

    def _session_cookie(self, token):
        return ("Set-Cookie", f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, home_page(self._current_username()))
        elif path == "/register":
            self._send(200, register_page())
        elif path == "/login":
            self._send(200, login_page())
        else:
            self._send(404, PAGE.format(title="Not found", body="<h1>404</h1>"))

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._form()
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""

        if path == "/register":
            self._handle_register(username, password)
        elif path == "/login":
            self._handle_login(username, password)
        elif path == "/logout":
            token = self._cookie(SESSION_COOKIE)
            if token:
                db_query("DELETE FROM sessions WHERE token = ?", (token,))
            self._redirect(
                "/",
                [("Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")],
            )
        else:
            self._send(404, PAGE.format(title="Not found", body="<h1>404</h1>"))

    def _handle_register(self, username, password):
        if not USERNAME_RE.fullmatch(username):
            self._send(400, register_page("Username must be 3-32 chars: letters, digits, _ or -."))
            return
        if len(password) < 8:
            self._send(400, register_page("Password must be at least 8 characters."))
            return
        if db_query("SELECT id FROM users WHERE username = ?", (username,), fetch=True):
            self._send(409, register_page("Username already taken."))
            return
        salt_hex, digest_hex = hash_password(password)
        db_query(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, f"{salt_hex}${digest_hex}", time.time()),
        )
        user_id = db_query("SELECT id FROM users WHERE username = ?", (username,), fetch=True)[0][0]
        self._redirect("/", [self._session_cookie(create_session(user_id))])

    def _handle_login(self, username, password):
        rows = db_query(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,), fetch=True
        )
        if not rows or not verify_password(password, rows[0][1]):
            self._send(401, login_page("Invalid username or password."))
            return
        self._redirect("/", [self._session_cookie(create_session(rows[0][0]))])


def main():
    init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Serving on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
