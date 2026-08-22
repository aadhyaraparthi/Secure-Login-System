# Secure Login System

A simple Flask web application demonstrating secure user registration, login, logout, password hashing with Werkzeug PBKDF2, input validation, parameterized SQLite queries, CSRF protection, secure session cookies, and account lockout after repeated failed logins.

## Features

- User registration and login
- Password hashing using Werkzeug's secure password hashing
- Input validation
- Parameterized SQL queries to prevent SQL injection
- CSRF tokens on state-changing forms
- Session management and logout
- Secure cookie configuration
- Basic brute-force protection / temporary account lockout
- Clean responsive UI
- SQLite database for easy local setup

> Educational project. For production, use HTTPS, a production WSGI server, a managed database, secret management, monitoring, and a mature identity/authentication service where appropriate.

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Set a strong `SECRET_KEY` in the environment before deployment:

```bash
# macOS/Linux
export SECRET_KEY="replace-with-a-long-random-secret"

# PowerShell
$env:SECRET_KEY="replace-with-a-long-random-secret"
```

## Project structure

```text
secure_login_system/
├── app.py
├── requirements.txt
├── .gitignore
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── static/
    └── style.css
```

## GitHub

```bash
git init
git add .
git commit -m "Add secure login system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```
