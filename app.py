import csv
import sqlite3
import os
import io
import secrets
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, flash, url_for, send_file, jsonify, session

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
# Where databases, sessions and the secret key live. On Render, point this at the
# persistent disk (e.g. /var/data). Locally and on PythonAnywhere it defaults to
# the app folder.
DATA_DIR = os.environ.get("DATA_DIR", basedir)
os.makedirs(DATA_DIR, exist_ok=True)


# ---------- SECRET KEY ----------
# Uses the SECRET_KEY environment variable if set. Otherwise generates a random
# key once and keeps it in .secret_key next to this file (git-ignored).
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

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(DATA_DIR, "flask_session")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_INSECURE_COOKIES") != "1"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit
Session(app)


# ---------- CSRF PROTECTION ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

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


def safe_referrer(default):
    """Only redirect back to pages on this site."""
    ref = request.referrer
    if ref and urlparse(ref).netloc == request.host:
        return ref
    return default


# ---------- SECURITY HEADERS ----------
@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if "name" in session:
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(413)
def too_large(_e):
    flash("That file is over 5 MB. Split it or remove extra columns.", "error")
    return redirect("/upload")

# ---------- DATABASE ----------
from init_db import create_schema, ensure_admin

PATIENTS_DB = os.path.join(DATA_DIR, "patients.db")
INVENTORY_DB = os.path.join(DATA_DIR, "inventory.db")

# Create empty tables on a fresh disk, and a first account from
# ADMIN_USERNAME / ADMIN_PASSWORD if there are no users yet.
create_schema(PATIENTS_DB, INVENTORY_DB)
ensure_admin(INVENTORY_DB, os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD"))

def get_patient_db():
    conn = sqlite3.connect(PATIENTS_DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_inventory_db():
    conn = sqlite3.connect(INVENTORY_DB)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- LOGIN REQUIRED DECORATOR ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "name" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#-- Upload

# ---------- UPLOAD & EXPORT ----------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_csv():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "upload_patients":
            file = request.files.get("file")
            if not file or file.filename == "":
                flash("Choose a CSV file first.", "error")
                return redirect(request.url)

            if not file.filename.endswith(".csv"):
                flash("That file isn't a CSV. Export it as .csv and try again.", "error")
                return redirect(request.url)

            try:
                stream = io.StringIO(file.stream.read().decode("UTF8"))
                reader = csv.DictReader(stream)

                db = get_patient_db()
                db.execute("DELETE FROM patients")
                db.execute("DELETE FROM sqlite_sequence WHERE name='patients'")
                db.commit()

                for row in reader:
                    db.execute(
                        "INSERT INTO patients (firstName, lastName, dob, address) VALUES (?, ?, ?, ?)",
                        (row["First Name"], row["Last Name"], row["D.O.B (MM/DD/YYYY)"], row["Address"])
                    )
                db.commit()
                flash("Patients imported. The old patient list was replaced.")
            except Exception as e:
                flash(f"Couldn't import patients: {e}", "error")
            return redirect(request.url)

        elif action == "upload_inventory":
            file = request.files.get("file")
            if not file or file.filename == "":
                flash("Choose a CSV file first.", "error")
                return redirect(request.url)

            if not file.filename.endswith(".csv"):
                flash("That file isn't a CSV. Export it as .csv and try again.", "error")
                return redirect(request.url)

            try:
                stream = io.StringIO(file.stream.read().decode("UTF8"))
                reader = csv.DictReader(stream)

                db = get_inventory_db()
                db.execute("DELETE FROM medicines")
                for row in reader:
                    name = row["Name"]
                    quantity = int(row["Quantity"])
                    db.execute("INSERT INTO medicines (name, quantity) VALUES (?, ?)", (name, quantity))
                db.commit()
                flash("Inventory imported. The old stock list was replaced.")
            except Exception as e:
                flash(f"Couldn't import inventory: {e}", "error")
            return redirect(request.url)

        elif action == "export_inventory":
            db = get_inventory_db()
            meds = db.execute("SELECT * FROM medicines").fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Name", "Quantity"])
            for med in meds:
                writer.writerow([med["name"], med["quantity"]])
            output.seek(0)

            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype="text/csv",
                as_attachment=True,
                download_name="inventory_export.csv"
            )

        elif action == "export_patients":
            db = get_patient_db()
            patients = db.execute("SELECT * FROM patients").fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "First Name", "Last Name", "D.O.B (MM/DD/YYYY)", "Address"])
            for p in patients:
                writer.writerow([p["id"], p["firstName"], p["lastName"], p["dob"], p["address"]])
            output.seek(0)

            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype="text/csv",
                as_attachment=True,
                download_name="patients_export.csv"
            )

    return render_template("upload.html")

#-- Upload

# ---------- UPLOAD & EXPORT ----------

# ---------- FORCE LOGOUT ON FIRST VISIT ----------
@app.before_request
def force_logout_on_visit():
    if request.endpoint == "index":
        session.clear()

# ---------- AUTH ----------
@app.route("/reg1", methods=["GET", "POST"])
@login_required
def register_user():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Enter a username and a password.", "error")
            return redirect("/reg1")

        if len(password) < 8:
            flash("Use a password with at least 8 characters.", "error")
            return redirect("/reg1")

        db = get_inventory_db()
        existing = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("That username is taken. Pick another.", "error")
            return redirect("/reg1")

        hash_pw = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_pw))
        db.commit()
        flash(f"Account created for {username}.")
        return redirect("/reg1")

    return render_template("reg1.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        db = get_inventory_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["name"] = user["username"]
            return redirect("/index")
        else:
            flash("Wrong username or password.", "error")
            return redirect("/login")

    return render_template("login.html")

@app.route("/logout")
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

@app.route("/add", methods=["GET", "POST"])
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
    query = request.args.get("query")
    patients = []
    if query:
        words = query.strip().split()
        if len(words) == 2:
            patients = db.execute("SELECT * FROM patients WHERE firstName LIKE ? AND lastName LIKE ?", (f"%{words[0]}%", f"%{words[1]}%")).fetchall()
        else:
            patients = db.execute("SELECT * FROM patients WHERE firstName LIKE ? OR lastName LIKE ?", (f"%{query}%", f"%{query}%")).fetchall()
    return render_template("search.html", patients=patients, searched=bool(query))

@app.route("/register", methods=["POST"])
@login_required
def register():
    db = get_patient_db()
    first = request.form.get("firstName")
    last = request.form.get("lastName")
    dob = request.form.get("dob")
    address = request.form.get("address")
    if not first or not last or not dob:
        return render_template("failure.html")
    missing_id = db.execute("SELECT MIN(t1.id + 1) AS next_id FROM patients t1 LEFT JOIN patients t2 ON t1.id + 1 = t2.id WHERE t2.id IS NULL").fetchone()["next_id"]
    next_id = missing_id if missing_id else (db.execute("SELECT MAX(id) AS max_id FROM patients").fetchone()["max_id"] or 0) + 1
    db.execute("INSERT INTO patients (id, firstName, lastName, dob, address) VALUES (?, ?, ?, ?, ?)", (next_id, first, last, dob, address))
    db.commit()
    return render_template("success.html")

@app.route("/results")
@login_required
def results():
    db = get_patient_db()
    patients = db.execute("SELECT * FROM patients").fetchall()
    return render_template("find.html", patients=patients)

@app.route("/remove/<int:id>", methods=["POST"])
@login_required
def remove(id):
    db = get_patient_db()
    db.execute("DELETE FROM patients WHERE id = ?", (id,))
    db.commit()
    flash("Patient removed.")
    return redirect(safe_referrer("/search"))

@app.route("/view")
@login_required
def view():
    db = get_patient_db()
    patients = db.execute("SELECT * FROM patients").fetchall()
    return render_template("view.html", patients=patients)

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_patient(id):
    db = get_patient_db()
    patient = db.execute("SELECT * FROM patients WHERE id = ?", (id,)).fetchone()

    if request.method == "POST":
        first = request.form.get("firstName")
        last = request.form.get("lastName")
        dob = request.form.get("dob")
        address = request.form.get("address")

        db.execute("UPDATE patients SET firstName = ?, lastName = ?, dob = ?, address = ? WHERE id = ?",
                   (first, last, dob, address, id))
        db.commit()
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
    order = "DESC" if sort == "desc" else "ASC"
    db = get_inventory_db()
    meds = db.execute(f"SELECT * FROM medicines ORDER BY quantity {order}").fetchall()
    return render_template("inventory/view.html", meds=meds, sort=sort)

@app.route("/inventory/logs")
@login_required
def inventory_logs():
    db = get_inventory_db()
    logs = db.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    return render_template("inventory/logs.html", logs=logs)

@app.route("/inventory/logs/clear", methods=["POST"])
@login_required
def clear_inventory_logs():
    db = get_inventory_db()
    db.execute("DELETE FROM logs")
    db.commit()
    flash("Stock history cleared.")
    return redirect("/inventory/logs")

@app.route("/inventory/add", methods=["GET", "POST"])
@login_required
def add_medicine():
    if request.method == "POST":
        name = request.form.get("name")
        try:
            quantity = int(request.form.get("quantity") or 0)
        except ValueError:
            quantity = -1
        user = session.get("name", "Unknown")
        if not name or quantity < 0:
            flash("Enter a medicine name and a quantity of 0 or more.", "error")
            return redirect(request.url)
        db = get_inventory_db()
        db.execute("INSERT OR REPLACE INTO medicines (name, quantity) VALUES (?, ?)", (name, quantity))
        db.execute("INSERT INTO logs (medicine_name, change, timestamp, user) VALUES (?, ?, ?, ?)", (name, quantity, datetime.now().isoformat(), user))
        db.commit()
        return render_template("inventory/success.html")
    return render_template("inventory/add.html")

@app.route("/inventory/find", methods=["GET", "POST"])
@login_required
def inventory_find():
    meds = []
    searched = False
    if request.method == "POST":
        name = request.form.get("query")
        db = get_inventory_db()
        meds = db.execute("SELECT * FROM medicines WHERE name LIKE ?", (f"%{name}%",)).fetchall()
        searched = True
    return render_template("inventory/find.html", meds=meds, searched=searched)

@app.route("/inventory/remove/<name>", methods=["POST"])
@login_required
def remove_medicine(name):
    db = get_inventory_db()
    db.execute("DELETE FROM medicines WHERE name = ?", (name,))
    db.execute("DELETE FROM logs WHERE medicine_name = ?", (name,))
    db.commit()
    flash(f"Removed {name} from inventory.")
    return redirect("/inventory/view")

@app.route("/inventory/ajax-update/<name>", methods=["POST"])
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

    username = session.get("name", "Unknown")
    today = datetime.now().date().isoformat()

    existing_log = db.execute(
        "SELECT id, change FROM logs WHERE medicine_name = ? AND date(timestamp) = ? ORDER BY id DESC LIMIT 1",
        (name, today)
    ).fetchone()

    if existing_log:
        new_change = existing_log["change"] + change
        db.execute(
            "UPDATE logs SET change = ?, timestamp = ?, user = ? WHERE id = ?",
            (new_change, datetime.now().isoformat(), username, existing_log["id"])
        )
    else:
        db.execute(
            "INSERT INTO logs (medicine_name, change, timestamp, user) VALUES (?, ?, ?, ?)",
            (name, change, datetime.now().isoformat(), username)
        )

    db.commit()
    return jsonify({"quantity": new_qty})

# ---------- RUN ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)