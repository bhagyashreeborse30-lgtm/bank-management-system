# NexaBank — Flask + SQLite Banking App

A clean, server-side rendered banking application built with Python Flask and SQLite.

## Features
- User registration & login (session-based auth)
- Dashboard with portfolio overview
- Deposit, Withdraw, Transfer funds
- Full transaction history
- Responsive dark UI

## Setup

```bash
# 1. Install dependencies
pip install flask

# 2. Run the app
python app.py
```

Open http://localhost:5000 in your browser.

The SQLite database (`bank.db`) is created automatically on first run.

## Structure
```
nexabank/
├── app.py                  # Flask routes + SQLite logic
├── requirements.txt
├── templates/
│   ├── base.html           # Shared navbar layout
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── accounts.html
│   ├── deposit.html
│   ├── withdraw.html
│   ├── transfer.html
│   └── transactions.html
└── static/
    └── css/
        └── style.css
```

## Notes
- No external dependencies beyond Flask
- All pages are server-side rendered (no JavaScript frameworks)
- Passwords hashed with PBKDF2-SHA256 + salt
- Sessions managed with Flask's built-in session (cookie-based)
