import sqlite3
import os
import secrets
import hashlib
import hmac
import time
import json
import base64
from functools import wraps
from flask import Flask, request, jsonify, redirect, url_for, render_template, session, flash

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', 'nexabank-secret-key-change-in-prod')

DB_PATH = 'bank.db'

# ─── DB helpers ───────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                email      TEXT    NOT NULL UNIQUE,
                password   TEXT    NOT NULL,
                created_at TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id        INTEGER NOT NULL REFERENCES users(id),
                account_number TEXT    NOT NULL UNIQUE,
                account_type   TEXT    NOT NULL DEFAULT 'savings',
                balance        REAL    NOT NULL DEFAULT 0.0,
                is_active      INTEGER NOT NULL DEFAULT 1,
                created_at     TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id    INTEGER NOT NULL REFERENCES accounts(id),
                type          TEXT    NOT NULL,
                amount        REAL    NOT NULL,
                balance_after REAL    NOT NULL,
                description   TEXT    DEFAULT '',
                to_account    TEXT    DEFAULT NULL,
                created_at    TEXT    DEFAULT (datetime('now'))
            );
        """)

# ─── Password helpers ─────────────────────────────────────────────────────────

def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
    return f'{salt}:{h.hex()}'


def verify_password(pw, stored):
    try:
        salt, h = stored.split(':')
        return hmac.compare_digest(
            hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000).hex(), h
        )
    except Exception:
        return False


def gen_account_number():
    suffix = str(int(time.time()))[-8:] + str(secrets.randbelow(100)).zfill(2)
    return f'ACC{suffix}'


def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    if 'user_id' not in session:
        return None
    with get_db() as conn:
        return dict(conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone() or {})

# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/')
@require_login
def dashboard():
    user = current_user()
    with get_db() as conn:
        accounts = [dict(r) for r in conn.execute(
            'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
        acc_ids = [a['id'] for a in accounts]
        txns = []
        if acc_ids:
            ph = ','.join('?' * len(acc_ids))
            txns = [dict(r) for r in conn.execute(
                f'SELECT t.*, a.account_number FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE t.account_id IN ({ph}) ORDER BY t.created_at DESC LIMIT 8',
                acc_ids).fetchall()]
    total = sum(a['balance'] for a in accounts)
    return render_template('dashboard.html', user=user, accounts=accounts, txns=txns, total=total)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/')
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if user and verify_password(password, user['password']):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect('/')
        error = 'Invalid email or password.'
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect('/')
    error = None
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        account_type = request.form.get('account_type', 'savings')
        if not all([name, email, password]):
            error = 'All fields are required.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            with get_db() as conn:
                if conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                    error = 'Email already registered.'
                else:
                    cur = conn.execute('INSERT INTO users (name, email, password) VALUES (?,?,?)',
                                       (name, email, hash_password(password)))
                    user_id = cur.lastrowid
                    conn.execute('INSERT INTO accounts (user_id, account_number, account_type, balance) VALUES (?,?,?,?)',
                                 (user_id, gen_account_number(), account_type, 0.0))
                    conn.commit()
                    session['user_id'] = user_id
                    session['user_name'] = name
                    return redirect('/')
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ─── Account routes ───────────────────────────────────────────────────────────

@app.route('/accounts')
@require_login
def accounts():
    user = current_user()
    with get_db() as conn:
        accs = [dict(r) for r in conn.execute(
            'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    return render_template('accounts.html', user=user, accounts=accs)


# ─── Transaction routes ───────────────────────────────────────────────────────

@app.route('/deposit', methods=['GET', 'POST'])
@require_login
def deposit():
    user = current_user()
    with get_db() as conn:
        accounts = [dict(r) for r in conn.execute(
            'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    success = error = None
    if request.method == 'POST':
        account_id = request.form.get('account_id')
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            amount = 0
        description = request.form.get('description', '').strip()
        if amount <= 0:
            error = 'Amount must be positive.'
        else:
            with get_db() as conn:
                acc = conn.execute('SELECT * FROM accounts WHERE id=? AND user_id=?',
                                   (account_id, user['id'])).fetchone()
                if not acc:
                    error = 'Account not found.'
                else:
                    new_bal = acc['balance'] + amount
                    conn.execute('UPDATE accounts SET balance=? WHERE id=?', (new_bal, account_id))
                    conn.execute('INSERT INTO transactions (account_id, type, amount, balance_after, description) VALUES (?,?,?,?,?)',
                                 (account_id, 'deposit', amount, new_bal, description))
                    conn.commit()
                    success = f'₹{amount:,.2f} deposited successfully!'
                    accounts = [dict(r) for r in conn.execute(
                        'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    return render_template('deposit.html', user=user, accounts=accounts, success=success, error=error)


@app.route('/withdraw', methods=['GET', 'POST'])
@require_login
def withdraw():
    user = current_user()
    with get_db() as conn:
        accounts = [dict(r) for r in conn.execute(
            'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    success = error = None
    if request.method == 'POST':
        account_id = request.form.get('account_id')
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            amount = 0
        description = request.form.get('description', '').strip()
        if amount <= 0:
            error = 'Amount must be positive.'
        else:
            with get_db() as conn:
                acc = conn.execute('SELECT * FROM accounts WHERE id=? AND user_id=?',
                                   (account_id, user['id'])).fetchone()
                if not acc:
                    error = 'Account not found.'
                elif acc['balance'] < amount:
                    error = 'Insufficient balance.'
                else:
                    new_bal = acc['balance'] - amount
                    conn.execute('UPDATE accounts SET balance=? WHERE id=?', (new_bal, account_id))
                    conn.execute('INSERT INTO transactions (account_id, type, amount, balance_after, description) VALUES (?,?,?,?,?)',
                                 (account_id, 'withdrawal', amount, new_bal, description))
                    conn.commit()
                    success = f'₹{amount:,.2f} withdrawn successfully!'
                    accounts = [dict(r) for r in conn.execute(
                        'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    return render_template('withdraw.html', user=user, accounts=accounts, success=success, error=error)


@app.route('/transfer', methods=['GET', 'POST'])
@require_login
def transfer():
    user = current_user()
    with get_db() as conn:
        accounts = [dict(r) for r in conn.execute(
            'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    success = error = None
    if request.method == 'POST':
        from_account_id = request.form.get('from_account_id')
        to_account_number = request.form.get('to_account_number', '').strip()
        try:
            amount = float(request.form.get('amount', 0))
        except ValueError:
            amount = 0
        description = request.form.get('description', '').strip()
        if amount <= 0:
            error = 'Amount must be positive.'
        elif not to_account_number:
            error = 'Destination account number required.'
        else:
            with get_db() as conn:
                from_acc = conn.execute('SELECT * FROM accounts WHERE id=? AND user_id=?',
                                        (from_account_id, user['id'])).fetchone()
                to_acc = conn.execute('SELECT * FROM accounts WHERE account_number=?',
                                      (to_account_number,)).fetchone()
                if not from_acc or not to_acc:
                    error = 'Account not found.'
                elif from_acc['id'] == to_acc['id']:
                    error = 'Cannot transfer to the same account.'
                elif from_acc['balance'] < amount:
                    error = 'Insufficient balance.'
                else:
                    new_from = from_acc['balance'] - amount
                    new_to = to_acc['balance'] + amount
                    conn.execute('UPDATE accounts SET balance=? WHERE id=?', (new_from, from_acc['id']))
                    conn.execute('UPDATE accounts SET balance=? WHERE id=?', (new_to, to_acc['id']))
                    conn.execute('INSERT INTO transactions (account_id, type, amount, balance_after, description, to_account) VALUES (?,?,?,?,?,?)',
                                 (from_acc['id'], 'transfer', amount, new_from, description, to_account_number))
                    conn.execute('INSERT INTO transactions (account_id, type, amount, balance_after, description) VALUES (?,?,?,?,?)',
                                 (to_acc['id'], 'deposit', amount, new_to, f'Transfer from {from_acc["account_number"]}'))
                    conn.commit()
                    success = f'₹{amount:,.2f} transferred to {to_account_number}!'
                    accounts = [dict(r) for r in conn.execute(
                        'SELECT * FROM accounts WHERE user_id=?', (user['id'],)).fetchall()]
    return render_template('transfer.html', user=user, accounts=accounts, success=success, error=error)


@app.route('/transactions')
@require_login
def transactions():
    user = current_user()
    with get_db() as conn:
        accs = conn.execute('SELECT id FROM accounts WHERE user_id=?', (user['id'],)).fetchall()
        acc_ids = [a['id'] for a in accs]
        txns = []
        if acc_ids:
            ph = ','.join('?' * len(acc_ids))
            txns = [dict(r) for r in conn.execute(
                f'SELECT t.*, a.account_number FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE t.account_id IN ({ph}) ORDER BY t.created_at DESC',
                acc_ids).fetchall()]
    return render_template('transactions.html', user=user, txns=txns)


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
