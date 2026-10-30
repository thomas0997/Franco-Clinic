import io
import time

import pyotp
import pytest

import app as clinic
from conftest import ADMIN_SECRET, DATA_DIR, Session, csrf, current_code, db


def patient_count():
    with db("patients.db") as c:
        return c.execute("SELECT COUNT(*) FROM patients").fetchone()[0]


def upload(session, action, text, filename="data.csv"):
    return session.client.post("/upload", content_type="multipart/form-data", data={
        "_csrf": session.token, "action": action, "file": (io.BytesIO(text.encode()), filename)})


# ---------- access control ----------
@pytest.mark.parametrize("path", ["/index", "/view", "/search?query=a", "/inventory/view",
                                  "/upload", "/reg1", "/admin/audit", "/account/2fa"])
def test_signed_out_users_are_sent_to_login(client, path):
    r = client.get(path)
    assert r.status_code == 302 and r.headers["Location"] == "/login"


def test_signed_out_user_cannot_export_patients(client):
    r = client.post("/upload", data={"action": "export_patients", "_csrf": csrf(client)})
    assert b"Santos" not in r.data


@pytest.mark.parametrize("path", ["/upload", "/reg1", "/admin/audit"])
def test_staff_cannot_open_admin_pages(staff, path):
    assert staff.client.get(path).headers["Location"] == "/index"


def test_staff_cannot_remove_patients(staff):
    staff.post("/remove/1")
    assert patient_count() == 1


def test_staff_menu_hides_admin_links(staff):
    page = staff.client.get("/index").get_data(as_text=True)
    assert 'href="/upload"' not in page and "Activity log" not in page


def test_admin_can_remove_patients(admin):
    admin.post("/remove/1")
    assert patient_count() == 0


# ---------- CSRF ----------
def test_post_without_csrf_token_is_rejected(admin):
    admin.client.post("/remove/1", data={})
    assert patient_count() == 1


def test_ajax_without_csrf_header_is_rejected(staff):
    with db() as c:
        c.execute("INSERT INTO medicines VALUES ('Paracetamol', 5)")
    r = staff.client.post("/inventory/ajax-update/Paracetamol", json={"action": "add"})
    assert r.status_code == 400


# ---------- login ----------
def test_wrong_password_fails(client):
    assert Session(client).login("nurse", "wrong-password").headers["Location"] == "/login"


def test_lockout_after_five_failures(client):
    s = Session(client)
    for _ in range(5):
        s.login("nurse", "wrong-password")
    assert s.login("nurse").headers["Location"] == "/login"


def test_logout_requires_post(staff):
    assert staff.client.get("/logout").status_code == 405
    staff.post("/logout")
    assert staff.client.get("/index").headers["Location"] == "/login"


def test_idle_session_expires(staff):
    with staff.client.session_transaction() as sess:
        sess["last_seen"] = time.time() - clinic.IDLE_TIMEOUT_SECONDS - 1
    assert staff.client.get("/index").headers["Location"] == "/login"


def test_new_accounts_need_long_passwords(admin):
    admin.post("/reg1", username="temp", password="short")
    with db() as c:
        assert c.execute("SELECT 1 FROM users WHERE username='temp'").fetchone() is None


# ---------- two-factor ----------
def test_admin_password_alone_is_not_enough(client):
    s = Session(client)
    r = client.post("/login", data={"username": "admin", "password": "correct-horse-1", "_csrf": csrf(client)})
    assert r.headers["Location"] == "/login/2fa"
    assert client.get("/index").headers["Location"] == "/login"


def test_wrong_2fa_code_fails(client):
    r = Session(client).login("admin", code="000000" if current_code(ADMIN_SECRET) != "000000" else "111111")
    assert r.headers["Location"] == "/login/2fa"


def test_2fa_code_cannot_be_reused(client):
    code = current_code(ADMIN_SECRET)
    assert Session(clinic.app.test_client()).login("admin", code=code).headers["Location"] == "/index"
    assert Session(client).login("admin", code=code).headers["Location"] == "/login/2fa"


def test_admin_without_2fa_must_set_it_up(client):
    with db() as c:
        c.execute("UPDATE users SET totp_secret = NULL WHERE username='admin'")
    s = Session(client)
    s.login("admin")
    assert client.get("/upload").headers["Location"] == "/account/2fa"
    with client.session_transaction() as sess:
        secret = sess["totp_setup"]
    client.post("/account/2fa", data={"_csrf": csrf(client, "/account/2fa"), "action": "enable",
                                      "code": pyotp.TOTP(secret).now()})
    assert client.get("/upload").status_code == 200


# ---------- XSS ----------
def test_medicine_names_are_escaped(staff):
    staff.post("/inventory/add", name="<script>alert(1)</script>", quantity="1")
    page = staff.client.get("/inventory/view").get_data(as_text=True)
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page


def test_csp_blocks_inline_scripts(client):
    assert "script-src 'self'" in client.get("/login").headers["Content-Security-Policy"]


# ---------- CSV import / export ----------
GOOD_CSV = ("First Name,Last Name,D.O.B (MM/DD/YYYY),Address\n"
            "Jose,Reyes,11/02/1972,Sample Town\n"
            '"=HYPERLINK(""http://evil"")",Cruz,07/29/1990,Example City\n')


def test_import_replaces_patients(admin):
    upload(admin, "upload_patients", GOOD_CSV)
    assert patient_count() == 2


def test_bad_import_changes_nothing(admin):
    upload(admin, "upload_patients", "First Name,Last Name,D.O.B (MM/DD/YYYY),Address\nA,B,1,\nC,,2,\n")
    assert patient_count() == 1


def test_wrong_columns_change_nothing(admin):
    upload(admin, "upload_patients", "Name,Birthday\nA,1\n")
    assert patient_count() == 1


def test_export_escapes_formulas_and_round_trips(admin):
    upload(admin, "upload_patients", GOOD_CSV)
    exported = admin.post("/upload", action="export_patients").data
    assert "'=HYPERLINK" in exported.decode("utf-8-sig")
    upload(admin, "upload_patients", exported.decode("utf-8-sig"))
    with db("patients.db") as c:
        names = [r[0] for r in c.execute("SELECT firstName FROM patients ORDER BY id")]
    assert names == ["Jose", '=HYPERLINK("http://evil")']


# ---------- records ----------
def test_patient_ids_are_not_reused(admin):
    admin.post("/register", firstName="New", lastName="Patient", dob="2000-01-01", address="")
    admin.post("/remove/2")
    admin.post("/register", firstName="Next", lastName="Patient", dob="2000-01-01", address="")
    with db("patients.db") as c:
        assert c.execute("SELECT MAX(id) FROM patients").fetchone()[0] == 3


def test_changes_are_audited(staff):
    staff.post("/edit/1", firstName="Mary", lastName="Santos", dob="03/14/1985", address="Sample Town")
    with db() as c:
        actions = [r[0] for r in c.execute("SELECT action FROM audit")]
    assert "login" in actions and "patient.edit" in actions


# ---------- backups ----------
def test_backup_creates_checked_copies_and_rotates(tmp_path):
    import backup
    for _ in range(3):
        target = backup.backup(DATA_DIR, keep=2)
        time.sleep(1.05)
    import os
    assert os.path.exists(os.path.join(target, "patients.db"))
    assert len(os.listdir(os.path.join(DATA_DIR, "backups"))) == 2


# ---------- every page renders ----------
@pytest.mark.parametrize("path", ["/index", "/add", "/patients", "/search?query=Maria", "/view", "/edit/1",
                                  "/inventory", "/inventory/view", "/inventory/logs", "/inventory/add",
                                  "/inventory/find", "/upload", "/reg1", "/admin/audit", "/account/2fa"])
def test_admin_pages_render(admin, path):
    assert admin.client.get(path).status_code == 200


def test_2fa_setup_page_shows_qr(staff):
    page = staff.client.get("/account/2fa").get_data(as_text=True)
    assert "data:image/svg+xml" in page
