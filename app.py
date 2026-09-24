from flask import Flask, request
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)

app.config["DATABASE"] = "login.db"


failed_attempts = {}
locked_accounts = {}


def get_db():
    return sqlite3.connect(app.config["DATABASE"])


def init_db():
    failed_attempts.clear()
    locked_accounts.clear()

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    password = generate_password_hash("Password123!")

    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("student", password)
    )

    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Check for empty fields
    if not username or not password:
        return "Username and password are required", 400

    username_key = username.lower()

    # Check if account is locked
    if username_key in locked_accounts:
        if time.time() < locked_accounts[username_key]:
            return "Account temporarily locked", 423
        else:
            del locked_accounts[username_key]
            failed_attempts[username_key] = 0

    conn = get_db()

    # Parameterized query prevents SQL injection
    user = conn.execute(
        "SELECT username, password FROM users WHERE LOWER(username) = ?",
        (username_key,)
    ).fetchone()

    conn.close()

    # Check username and password
    if user and check_password_hash(user[1], password):
        failed_attempts[username_key] = 0
        return "Login successful", 200

    # Record failed login attempt
    failed_attempts[username_key] = failed_attempts.get(username_key, 0) + 1

    # Lock account after 3 failed attempts
    if failed_attempts[username_key] >= 3:
        locked_accounts[username_key] = time.time() + 10
        return "Account temporarily locked", 423

    return "Invalid username or password", 401


if __name__ == "__main__":
    init_db()
    app.run(debug=True)