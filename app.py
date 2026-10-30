import csv
import io
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session)
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from init_db import MIN_PASSWORD_LENGTH, create_schema, ensure_admin

app = Flask(__name__)
log = logging.getLogger("clinic")
basedir = os.path.abspath(os.path.dirname(__file__))
# Where databases, sessions and the secret key live. Defaults to the app folder.
DATA_DIR = os.environ.get("DATA_DIR", basedir)
os.makedirs(DATA_DIR, exist_ok=True)

IDLE_TIMEOUT_SECONDS = 30 * 60          # sign out after 30 minutes of no activity
LOGIN_MAX_FAILURES = 5                  # failed logins allowed...
LOGIN_WINDOW_SECONDS = 15 * 60          # ...within this window before a lockout
MAX_FIELD_LENGTH = 200


# ---------- SECRET KEY ----------
# Uses the SECRET_KEY environment variable if set. Otherwise generates a random
# key once and keeps it in .secret_key in DATA_DIR (git-ignored).
def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(DATA_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()

app.secret_key = load_secret_key()

SECURE_COOKIES = os.environ.get("FLASK_INSECURE_COOKIES") != "1"
app.config.update(
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=os.path.join(DATA_DIR, "flask_session"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5 MB upload limit
)
Session(app)


# ---------- DATABASE ----------
PATIENTS_DB = os.path.join(DATA_DIR, "patients.db")
INVENTORY_DB = os.path.join(DATA_DIR, "inventory.db")

# Create or upgrade tables, and a first admin from ADMIN_USERNAME / ADMIN_PASSWORD
# if there are no users yet.
create_schema(PATIENTS_DB, INVENTORY_DB)
ensure_admin(INVENTORY_DB, os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD"))


def _connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def get_patient_db():
    if "patient_db" not in g:
        g.patient_db = _connect(PATIENTS_DB)
    return g.patient_db

def get_inventory_db():
    if "inventory_db" not in g:
        g.inventory_db = _connect(INVENTORY_DB)
    return g.inventory_db

@app.teardown_appcontext
def close_dbs(_exc):
    for name in ("patient_db", "inventory_db"):
        conn = g.pop(name, None)
        if conn is not None:
            conn.close()


def audit(action, detail=""):
    """Record who did what. The audit table is never edited or cleared by the app."""
    db = get_inventory_db()
    db.execute(
        "INSERT INTO audit (timestamp, user, action, detail) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(timespec="seconds"), session.get("name"), action, detail),
    )
    db.commit()


# ---------- CSRF PROTECTION ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token


def safe_referrer(default):
    """Only redirect back to pages on this site."""
    ref = request.referrer
    if ref and urlparse(ref).netloc == request.host:
        return ref
    return default


# ---------- REQUEST HOOKS ----------
@app.before_request
def load_user_and_check_session():
    g.user = None
    # Visiting the root URL always starts a fresh sign-in.
    if request.endpoint == "index":
        session.clear()
        return None

    if "name" in session:
        now = time.time()
        if now - session.get("last_seen", 0) > IDLE_TIMEOUT_SECONDS:
            session.clear()
            flash("You were signed out after 30 minutes of inactivity.", "error")
        else:
            user = get_inventory_db().execute(
                "SELECT id, username, role FROM users WHERE username = ?", (session["name"],)
            ).fetchone()
            if user is None:  # account was removed
                session.clear()
            else:
                g.user = user
                session["last_seen"] = now
    return None


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return None
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf") or ""
    if not expected or not secrets.compare_digest(sent, expected):
        if request.is_json:
            return jsonify({"error": "Session expired. Reload the page."}), 400
        flash("Your session expired. Try that again.", "error")
        return redirect(safe_referrer("/login"))
    return None


@app.context_processor
def inject_user():
    return {"current_user": g.get("user"), "is_admin": is_admin()}


CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if SECURE_COOKIES:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if "name" in session:
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(413)
def too_large(_e):
    flash("That file is over 5 MB. Split it or remove extra columns.", "error")
    return redirect("/upload")


# ---------- ACCESS CONTROL ----------
def is_admin():
    user = g.get("user")
    return bool(user and user["role"] == "admin")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.get("user") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(403)
def forbidden(_e):
    flash("Only an admin can do that.", "error")
    return redirect("/index")


# ---------- LOGIN RATE LIMITING ----------
def _client_ip():
    # PythonAnywhere puts the visitor's address in X-Real-IP.
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"

def _attempt_keys(username):
    return [f"user:{username.lower()}", f"ip:{_client_ip()}"]

def login_locked(username):
    db = get_inventory_db()
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (cutoff,))
    db.commit()
    for key in _attempt_keys(username):
        n = db.execute("SELECT COUNT(*) FROM login_attempts WHERE key = ?", (key,)).fetchone()[0]
        if n >= LOGIN_MAX_FAILURES:
            return True
    return False

def record_failed_login(username):
    db = get_inventory_db()
    now = time.time()
    db.executemany("INSERT INTO login_attempts (key, ts) VALUES (?, ?)",
                   [(k, now) for k in _attempt_keys(username)])
    db.commit()

def clear_failed_logins(username):
    db = get_inventory_db()
    db.execute("DELETE FROM login_attempts WHERE key = ?", (f"user:{username.lower()}",))
    db.commit()

# Compared against when the username doesn't exist, so a wrong username takes
# as long as a wrong password and doesn't reveal which accounts exist.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


# ---------- CSV HELPERS ----------
FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")

def csv_safe(value):
    """Stop spreadsheet apps from running a cell as a formula."""
    if isinstance(value, str) and value.startswith(FORMULA_CHARS):
        return "'" + value
    return value

def csv_unescape(value):
    """Undo csv_safe() when a file we exported is imported again."""
    value = (value or "").strip()
    if value.startswith("'") and value[1:].startswith(FORMULA_CHARS):
        return value[1:]
    return value

def read_csv_upload():
    """Return a DictReader for the uploaded file, or None after flashing why."""
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("Choose a CSV file first.", "error")
        return None
    if not file.filename.lower().endswith(".csv"):
        flash("That file isn't a CSV. Export it as .csv and try again.", "error")
        return None
    try:
        # utf-8-sig also handles the hidden marker Excel adds to the start of CSVs.
        text = file.stream.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("Couldn't read that file. Save it as 'CSV UTF-8' and try again.", "error")
        return None
    return csv.DictReader(io.StringIO(text))

def csv_download(header, rows, filename):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_safe(v) for v in row])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv",
                     as_attachment=True, download_name=filename)

def too_long(*values):
    return any(len(v or "") > MAX_FIELD_LENGTH for v in values)


def import_patients(reader):
    required = ["First Name", "Last Name", "D.O.B (MM/DD/YYYY)"]
    missing = [c for c in required if c not in (reader.fieldnames or [])]
    if missing:
        flash(f"The file is missing these columns: {', '.join(missing)}.", "error")
        return
    id_col = next((c for c in ("ID", "ID number") if c in reader.fieldnames), None)

    # Check every row before touching the database.
    rows, seen_ids = [], set()
    for line, row in enumerate(reader, start=2):
        first = csv_unescape(row.get("First Name"))
        last = csv_unescape(row.get("Last Name"))
        dob = csv_unescape(row.get("D.O.B (MM/DD/YYYY)"))
        address = csv_unescape(row.get("Address"))
        if not (first or last or dob or address):
            continue  # skip blank lines
        if not first or not last or not dob:
            flash(f"Row {line} is missing a first name, last name or date of birth. Nothing was imported.", "error")
            return
        if too_long(first, last, dob, address):
            flash(f"Row {line} has a value over {MAX_FIELD_LENGTH} characters. Nothing was imported.", "error")
            return
        pid = None
        raw_id = (row.get(id_col) or "").strip() if id_col else ""
        if raw_id:
            if not raw_id.isdigit() or raw_id in seen_ids:
                flash(f"Row {line} has an invalid or repeated ID. Nothing was imported.", "error")
                return
            seen_ids.add(raw_id)
            pid = int(raw_id)
        rows.append((pid, first, last, dob, address))

    if not rows:
        flash("That file has no patient rows. Nothing was changed.", "error")
        return

    db = get_patient_db()
    try:
        with db:  # one transaction: all rows go in, or none do
            db.execute("DELETE FROM patients")
            db.execute("DELETE FROM sqlite_sequence WHERE name='patients'")
            db.executemany("INSERT INTO patients (id, firstName, lastName, dob, address) VALUES (?, ?, ?, ?, ?)", rows)
    except sqlite3.Error:
        log.exception("patient import failed")
        flash("Import failed, so the existing patient list was kept.", "error")
        return
    audit("patients.import", f"{len(rows)} rows replaced the patient list")
    flash(f"Imported {len(rows)} patients. The old patient list was replaced.")


def import_inventory(reader):
    missing = [c for c in ("Name", "Quantity") if c not in (reader.fieldnames or [])]
    if missing:
        flash(f"The file is missing these columns: {', '.join(missing)}.", "error")
        return
    rows = {}
    for line, row in enumerate(reader, start=2):
        name = csv_unescape(row.get("Name"))
        qty = (row.get("Quantity") or "").strip()
        if not name and not qty:
            continue
        if not name or not qty.isdigit() or too_long(name):
            flash(f"Row {line} needs a medicine name and a whole-number quantity. Nothing was imported.", "error")
            return
        rows[name] = int(qty)

    if not rows:
        flash("That file has no medicine rows. Nothing was changed.", "error")
        return

    db = get_inventory_db()
    try:
        with db:
            db.execute("DELETE FROM medicines")
            db.executemany("INSERT INTO medicines (name, quantity) VALUES (?, ?)", rows.items())
    except sqlite3.Error:
        log.exception("inventory import failed")
        flash("Import failed, so the existing stock list was kept.", "error")
        return
    audit("inventory.import", f"{len(rows)} rows replaced the stock list")
    flash(f"Imported {len(rows)} medicines. The old stock list was replaced.")


# ---------- UPLOAD & EXPORT (admin only) ----------
@app.route("/upload", methods=["GET", "POST"])
@admin_required
def upload_csv():
    if request.method == "POST":
        action = request.form.get("action")

        if action in ("upload_patients", "upload_inventory"):
            reader = read_csv_upload()
            if reader is not None:
                if action == "upload_patients":
                    import_patients(reader)
                else:
                    import_inventory(reader)
            return redirect(request.url)

        if action == "export_inventory":
            meds = get_inventory_db().execute("SELECT name, quantity FROM medicines ORDER BY name").fetchall()
            audit("inventory.export", f"{len(meds)} rows")
            return csv_download(["Name", "Quantity"], meds, "inventory_export.csv")

        if action == "export_patients":
            patients = get_patient_db().execute(
                "SELECT id, firstName, lastName, dob, address FROM patients ORDER BY id").fetchall()
            audit("patients.export", f"{len(patients)} rows")
            return csv_download(["ID", "First Name", "Last Name", "D.O.B (MM/DD/YYYY)", "Address"],
                                patients, "patients_export.csv")

    return render_template("upload.html")


# ---------- AUTH ----------
@app.route("/reg1", methods=["GET", "POST"])
@admin_required
def register_user():
    db = get_inventory_db()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = "admin" if request.form.get("role") == "admin" else "staff"

        if not username or not password:
            flash("Enter a username and a password.", "error")
            return redirect("/reg1")
        if too_long(username):
            flash("That username is too long.", "error")
            return redirect("/reg1")
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Use a password with at least {MIN_PASSWORD_LENGTH} characters.", "error")
            return redirect("/reg1")

        existing = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("That username is taken. Pick another.", "error")
            return redirect("/reg1")

        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   (username, generate_password_hash(password), role))
        db.commit()
        audit("user.create", f"{username} ({role})")
        flash(f"Account created for {username}.")
        return redirect("/reg1")

    users = db.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    return render_template("reg1.html", users=users)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if login_locked(username):
            flash("Too many failed sign-ins. Wait 15 minutes and try again.", "error")
            return redirect("/login")

        user = get_inventory_db().execute(
            "SELECT username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

        if user and ok:
            clear_failed_logins(username)
            session.clear()  # new session ID, so an old one can't be reused
            session["name"] = user["username"]
            session["last_seen"] = time.time()
            audit("login")
            return redirect("/index")

        record_failed_login(username)
        flash("Wrong username or password.", "error")
        return redirect("/login")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


# ---------- MAIN ROUTES ----------
@app.route("/")
def index():
    return redirect("/login")

@app.route("/index")
@login_required
def main_dashboard():
    pdb = get_patient_db()
    idb = get_inventory_db()
    patient_count = pdb.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    med_count = idb.execute("SELECT COUNT(*) FROM medicines").fetchone()[0]
    low_stock = idb.execute("SELECT * FROM medicines WHERE quantity <= 5 ORDER BY quantity ASC, name ASC").fetchall()
    recent_logs = idb.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 6").fetchall()
    return render_template("index.html", name=session["name"], patient_count=patient_count,
                           med_count=med_count, low_stock=low_stock, recent_logs=recent_logs)

@app.route("/add")
@login_required
def add():
    return render_template("add.html")

@app.route("/patients")
@login_required
def patients_home():
    return render_template("patientslist.html")

@app.route("/search")
@login_required
def search():
    db = get_patient_db()
    query = (request.args.get("query") or "").strip()[:MAX_FIELD_LENGTH]
    patients = []
    if query:
        words = query.split()
        if len(words) == 2:
            patients = db.execute("SELECT * FROM patients WHERE firstName LIKE ? AND lastName LIKE ?",
                                  (f"%{words[0]}%", f"%{words[1]}%")).fetchall()
        else:
            patients = db.execute("SELECT * FROM patients WHERE firstName LIKE ? OR lastName LIKE ?",
                                  (f"%{query}%", f"%{query}%")).fetchall()
    return render_template("search.html", patients=patients, searched=bool(query))

def patient_form():
    return tuple((request.form.get(k) or "").strip() for k in ("firstName", "lastName", "dob", "address"))

@app.route("/register", methods=["POST"])
@login_required
def register():
    first, last, dob, address = patient_form()
    if not first or not last or not dob or too_long(first, last, dob, address):
        return render_template("failure.html")
    db = get_patient_db()
    # New patients always get a fresh ID; IDs of removed patients are never reused.
    cur = db.execute("INSERT INTO patients (firstName, lastName, dob, address) VALUES (?, ?, ?, ?)",
                     (first, last, dob, address))
    db.commit()
    audit("patient.add", f"#{cur.lastrowid} {first} {last}")
    return render_template("success.html")

@app.route("/remove/<int:id>", methods=["POST"])
@admin_required
def remove(id):
    db = get_patient_db()
    patient = db.execute("SELECT firstName, lastName FROM patients WHERE id = ?", (id,)).fetchone()
    if patient is None:
        abort(404)
    db.execute("DELETE FROM patients WHERE id = ?", (id,))
    db.commit()
    audit("patient.remove", f"#{id} {patient['firstName']} {patient['lastName']}")
    flash("Patient removed.")
    return redirect(safe_referrer("/search"))

@app.route("/view")
@login_required
def view():
    patients = get_patient_db().execute("SELECT * FROM patients").fetchall()
    return render_template("view.html", patients=patients)

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_patient(id):
    db = get_patient_db()
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (id,)).fetchone()
    if patient is None:
        abort(404)

    if request.method == "POST":
        first, last, dob, address = patient_form()
        if not first or not last or not dob or too_long(first, last, dob, address):
            flash("First name, last name and date of birth are required.", "error")
            return redirect(f"/edit/{id}")
        db.execute("UPDATE patients SET firstName = ?, lastName = ?, dob = ?, address = ? WHERE id = ?",
                   (first, last, dob, address, id))
        db.commit()
        changed = [label for label, old, new in (
            ("first name", patient["firstName"], first), ("last name", patient["lastName"], last),
            ("date of birth", patient["dob"], dob), ("address", patient["address"] or "", address),
        ) if old != new]
        audit("patient.edit", f"#{id} {first} {last}: {', '.join(changed) or 'no changes'}")
        flash(f"Saved changes to {first} {last}.")
        return redirect("/view")

    return render_template("edit.html", patient=patient)


# ---------- INVENTORY ----------
@app.route("/inventory")
@login_required
def inventory_menu():
    return render_template("inventory/index.html")

@app.route("/inventory/view")
@login_required
def inventory_view():
    sort = request.args.get("sort", "desc")
    order = "DESC" if sort == "desc" else "ASC"  # only these two values reach the query
    meds = get_inventory_db().execute(f"SELECT * FROM medicines ORDER BY quantity {order}").fetchall()
    return render_template("inventory/view.html", meds=meds, sort=sort)

@app.route("/inventory/logs")
@login_required
def inventory_logs():
    logs = get_inventory_db().execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    return render_template("inventory/logs.html", logs=logs)

@app.route("/inventory/logs/clear", methods=["POST"])
@admin_required
def clear_inventory_logs():
    db = get_inventory_db()
    n = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    db.execute("DELETE FROM logs")
    db.commit()
    audit("inventory.history_clear", f"{n} entries")
    flash("Stock history cleared.")
    return redirect("/inventory/logs")

@app.route("/inventory/add", methods=["GET", "POST"])
@login_required
def add_medicine():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        try:
            quantity = int(request.form.get("quantity") or 0)
        except ValueError:
            quantity = -1
        if not name or quantity < 0 or too_long(name):
            flash("Enter a medicine name and a quantity of 0 or more.", "error")
            return redirect(request.url)
        db = get_inventory_db()
        db.execute("INSERT OR REPLACE INTO medicines (name, quantity) VALUES (?, ?)", (name, quantity))
        db.execute("INSERT INTO logs (medicine_name, change, timestamp, user) VALUES (?, ?, ?, ?)",
                   (name, quantity, datetime.now().isoformat(), session["name"]))
        db.commit()
        return render_template("inventory/success.html")
    return render_template("inventory/add.html")

@app.route("/inventory/find", methods=["GET", "POST"])
@login_required
def inventory_find():
    meds = []
    searched = False
    if request.method == "POST":
        name = (request.form.get("query") or "")[:MAX_FIELD_LENGTH]
        meds = get_inventory_db().execute("SELECT * FROM medicines WHERE name LIKE ?", (f"%{name}%",)).fetchall()
        searched = True
    return render_template("inventory/find.html", meds=meds, searched=searched)

@app.route("/inventory/remove/<path:name>", methods=["POST"])
@admin_required
def remove_medicine(name):
    db = get_inventory_db()
    cur = db.execute("DELETE FROM medicines WHERE name = ?", (name,))
    db.commit()
    if not cur.rowcount:
        abort(404)
    # Its stock history is kept so past changes stay on record.
    audit("inventory.remove", name)
    flash(f"Removed {name} from inventory.")
    return redirect("/inventory/view")

@app.route("/inventory/ajax-update/<path:name>", methods=["POST"])
@login_required
def ajax_update_quantity(name):
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in ("add", "remove"):
        return jsonify({"error": "Unknown action"}), 400
    db = get_inventory_db()
    med = db.execute("SELECT * FROM medicines WHERE name = ?", (name,)).fetchone()
    if not med:
        return jsonify({"error": "Medicine not found"}), 404

    change = 1 if action == "add" else -1
    new_qty = max(0, med["quantity"] + change)
    db.execute("UPDATE medicines SET quantity = ? WHERE name = ?", (new_qty, name))

    username = session["name"]
    today = datetime.now().date().isoformat()
    existing_log = db.execute(
        "SELECT id, change FROM logs WHERE medicine_name = ? AND date(timestamp) = ? ORDER BY id DESC LIMIT 1",
        (name, today)
    ).fetchone()

    if existing_log:
        db.execute("UPDATE logs SET change = ?, timestamp = ?, user = ? WHERE id = ?",
                   (existing_log["change"] + change, datetime.now().isoformat(), username, existing_log["id"]))
    else:
        db.execute("INSERT INTO logs (medicine_name, change, timestamp, user) VALUES (?, ?, ?, ?)",
                   (name, change, datetime.now().isoformat(), username))
    db.commit()
    return jsonify({"quantity": new_qty})


# ---------- ADMIN ----------
@app.route("/admin/audit")
@admin_required
def audit_log():
    entries = get_inventory_db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 1000").fetchall()
    return render_template("audit.html", entries=entries)


# ---------- RUN (local development only) ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port)
