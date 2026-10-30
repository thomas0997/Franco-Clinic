"""Create and upgrade the clinic databases, and manage accounts.

The app calls create_schema() and ensure_admin() on startup, so a fresh install
only needs ADMIN_USERNAME and ADMIN_PASSWORD set once.

Command line (run from the app folder):
    python init_db.py                         create or upgrade the databases
    python init_db.py create-user NAME        add a staff account (asks for password)
    python init_db.py create-user NAME --admin
    python init_db.py make-admin NAME         give an existing account admin rights
    python init_db.py list-users
"""
import argparse
import getpass
import os
import sqlite3
import sys

from werkzeug.security import generate_password_hash

MIN_PASSWORD_LENGTH = 10


def _columns(db, table):
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def create_schema(patients_path, inventory_path):
    with sqlite3.connect(patients_path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            dob TEXT NOT NULL,
            address TEXT
        )""")
    with sqlite3.connect(inventory_path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS medicines (name TEXT PRIMARY KEY, quantity INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff'
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            medicine_name TEXT,
            change INTEGER,
            timestamp TEXT,
            user TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT,
            action TEXT NOT NULL,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT NOT NULL,
            ts REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_key ON login_attempts(key);
        """)
        # Upgrade older databases that predate roles.
        if "role" not in _columns(db, "users"):
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'")


def ensure_admin(inventory_path, username, password):
    """Create an admin account only when the users table is empty."""
    if not username or not password:
        return False
    with sqlite3.connect(inventory_path) as db:
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return False
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password)),
        )
    return True


def _main():
    data_dir = os.environ.get("DATA_DIR", os.path.abspath(os.path.dirname(__file__)))
    p = os.path.join(data_dir, "patients.db")
    i = os.path.join(data_dir, "inventory.db")
    create_schema(p, i)

    parser = argparse.ArgumentParser(description="Clinic database and account tools")
    sub = parser.add_subparsers(dest="cmd")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--admin", action="store_true")
    ma = sub.add_parser("make-admin")
    ma.add_argument("username")
    sub.add_parser("list-users")
    args = parser.parse_args()

    with sqlite3.connect(i) as db:
        if args.cmd == "create-user":
            password = getpass.getpass("Password: ")
            if len(password) < MIN_PASSWORD_LENGTH:
                sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            if password != getpass.getpass("Repeat password: "):
                sys.exit("Passwords don't match.")
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (args.username, generate_password_hash(password), "admin" if args.admin else "staff"),
                )
            except sqlite3.IntegrityError:
                sys.exit(f"User {args.username} already exists.")
            print(f"Created {'admin' if args.admin else 'staff'} account {args.username}")
        elif args.cmd == "make-admin":
            cur = db.execute("UPDATE users SET role = 'admin' WHERE username = ?", (args.username,))
            if not cur.rowcount:
                sys.exit(f"No user called {args.username}.")
            print(f"{args.username} is now an admin")
        elif args.cmd == "list-users":
            for name, role in db.execute("SELECT username, role FROM users ORDER BY id"):
                print(f"{name:20} {role}")
    print(f"Databases ready in {data_dir}")


if __name__ == "__main__":
    _main()
