"""Create the clinic databases and a first admin account.

The app calls create_schema() and ensure_admin() on startup, so on Render you
only need to set ADMIN_USERNAME and ADMIN_PASSWORD once.

Manual use: python init_db.py <username> <password>
"""
import os
import sqlite3
import sys

from werkzeug.security import generate_password_hash


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
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            medicine_name TEXT,
            change INTEGER,
            timestamp TEXT,
            user TEXT
        );
        """)


def ensure_admin(inventory_path, username, password):
    """Create an account only when the users table is empty."""
    if not username or not password:
        return False
    with sqlite3.connect(inventory_path) as db:
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return False
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
    return True


if __name__ == "__main__":
    data_dir = os.environ.get("DATA_DIR", os.path.abspath(os.path.dirname(__file__)))
    p = os.path.join(data_dir, "patients.db")
    i = os.path.join(data_dir, "inventory.db")
    create_schema(p, i)
    if len(sys.argv) == 3:
        with sqlite3.connect(i) as db:
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
                (sys.argv[1], generate_password_hash(sys.argv[2])),
            )
        print(f"Created user {sys.argv[1]}")
    print(f"Databases ready in {data_dir}")
