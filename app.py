import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)

csrf = CSRFProtect(app)

DATABASE = os.path.join(app.instance_path, "users.db")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


def get_db():
    if "db" not in g:
        os.makedirs(app.instance_path, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
        """
    )
    db.commit()


def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username))


def valid_password(password):
    # Minimum length; the hash is never stored or logged in plaintext.
    return len(password) >= 10 and len(password) <= 128


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash("Username must be 3–30 characters: letters, numbers, and underscores only.", "danger")
            return render_template("register.html")

        if not valid_password(password):
            flash("Password must be between 10 and 128 characters.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        db = get_db()
        try:
            # Parameterized query: user input is never concatenated into SQL.
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "danger")
            return render_template("register.html")

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # Do not reveal whether a username exists.
        generic_error = "Invalid username or password."

        if user is None:
            flash(generic_error, "danger")
            return render_template("login.html")

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if locked_until > datetime.now(timezone.utc):
                flash("Too many failed attempts. Please try again later.", "danger")
                return render_template("login.html")
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            db.commit()

        if not check_password_hash(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = (
                    datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                ).isoformat()

            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            flash(generic_error, "danger")
            return render_template("login.html")

        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        db.commit()

        # Rotate the session identifier/state after authentication.
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
