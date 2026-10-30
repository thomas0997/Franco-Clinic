import os
import re
import sqlite3
import sys
import tempfile

import pyotp
import pytest

# The app reads its settings at import time, so set them first.
DATA_DIR = tempfile.mkdtemp(prefix="clinic-test-")
os.environ.update(DATA_DIR=DATA_DIR, FLASK_INSECURE_COOKIES="1", SECRET_KEY="test-secret")
os.environ.pop("ADMIN_USERNAME", None)
os.environ.pop("ADMIN_PASSWORD", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as clinic  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

ADMIN_SECRET = pyotp.random_base32()
PASSWORD = "correct-horse-1"


def db(name="inventory.db"):
    conn = sqlite3.connect(os.path.join(DATA_DIR, name))
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture(autouse=True)
def fresh_data():
    """Every test starts with one admin (2FA on), one staff account and no records."""
    with db() as c:
        for table in ("users", "logs", "audit", "login_attempts", "medicines"):
            c.execute(f"DELETE FROM {table}")
        c.execute("INSERT INTO users (username, password_hash, role, totp_secret) VALUES (?, ?, 'admin', ?)",
                  ("admin", generate_password_hash(PASSWORD), ADMIN_SECRET))
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'staff')",
                  ("nurse", generate_password_hash(PASSWORD)))
    with db("patients.db") as c:
        c.execute("DELETE FROM patients")
        c.execute("DELETE FROM sqlite_sequence WHERE name='patients'")
        c.execute("INSERT INTO patients (firstName, lastName, dob, address) VALUES ('Maria', 'Santos', '03/14/1985', 'Sample Town')")
    yield


def csrf(client, path="/login"):
    page = client.get(path, follow_redirects=True).get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', page).group(1)


def current_code(secret, offset_steps=0):
    totp = pyotp.TOTP(secret)
    import time
    return totp.generate_otp(int(time.time()) // totp.interval + offset_steps)


class Session:
    def __init__(self, client):
        self.client = client
        self.token = None

    def login(self, username, password=PASSWORD, code=None):
        r = self.client.post("/login", data={"username": username, "password": password,
                                             "_csrf": csrf(self.client)})
        if r.headers.get("Location") == "/login/2fa":
            r = self.client.post("/login/2fa", data={"code": code or current_code(ADMIN_SECRET),
                                                     "_csrf": csrf(self.client, "/login/2fa")})
        if r.headers.get("Location") == "/index":
            self.token = csrf(self.client, "/index")
        return r

    def post(self, path, **data):
        return self.client.post(path, data={"_csrf": self.token, **data})


@pytest.fixture
def client():
    return clinic.app.test_client()


@pytest.fixture
def admin():
    s = Session(clinic.app.test_client())
    assert s.login("admin").headers["Location"] == "/index"
    return s


@pytest.fixture
def staff():
    s = Session(clinic.app.test_client())
    assert s.login("nurse").headers["Location"] == "/index"
    return s
