# HelVinCo v2

A rebuild of my earlier clinic records system, written with security as the starting point.

HelVinCo is a web app for a small medical clinic. It manages patient records and medicine inventory. Version 1 was in daily use by the clinic's doctor and staff. Version 2 keeps the same features and redesigns how the app handles authentication, access control and data.

> **Status:** Rebuild in progress. This repo replaces the original project.

## Features

- **Patient records**: add, search, view, edit and remove
- **Medicine inventory**: stock levels, quick +/- adjustments, search, stock history
- **CSV import/export** so staff can bulk-edit records in Excel
- **Staff accounts** with admin and staff roles
- **Activity log** of sign-ins and every change to patients, accounts, imports and exports

## Security

- [x] Every page requires sign-in; there is no public sign-up (admins create accounts)
- [x] Role-based access: **admin** (import/export, remove records, clear stock history, manage accounts, view activity log) and **staff** (day-to-day patients and stock)
- [x] CSRF tokens on every form and AJAX request
- [x] Login lockout after 5 failed attempts in 15 minutes (per account and per IP); usernames can't be probed by timing
- [x] Passwords hashed with scrypt (Werkzeug), minimum 10 characters
- [x] Sessions: secret key from the environment, new session at sign-in, 30-minute idle timeout, `Secure`/`HttpOnly`/`SameSite` cookies, sign-out by POST only
- [x] Output escaped everywhere, with no template values inside inline JavaScript
- [x] Security headers: Content-Security-Policy, HSTS, X-Frame-Options, nosniff, Referrer-Policy
- [x] CSV imports are validated in full first, then applied in a single transaction (a bad file changes nothing); 5 MB limit
- [x] CSV exports are protected against spreadsheet formula injection
- [x] Append-only activity log that can't be edited or cleared from the app
- [x] Parameterised SQL everywhere; patient IDs are never reused
- [x] Pinned dependencies
- [ ] Automated backups
- [ ] Two-factor authentication for admins

## Tech stack

Python · Flask · SQLite · deployed on PythonAnywhere

## Running locally

```bash
git clone https://github.com/thomas0997/Franco-Clinic.git
cd Franco-Clinic
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export FLASK_INSECURE_COOKIES=1            # local http only, never in production
python init_db.py create-user yourname --admin
flask run
```

Import `sample_data/*.csv` from the Import & export page to try it with fake records.

## Managing accounts

```bash
python init_db.py create-user NAME            # staff account (asks for a password)
python init_db.py create-user NAME --admin    # admin account
python init_db.py make-admin NAME             # promote an existing account
python init_db.py list-users
```

Running `python init_db.py` with no arguments upgrades an existing database in place (adds roles, the activity log and login tracking) without touching patient or stock data.

## Configuration

See `.env.example`. `SECRET_KEY` and `DATA_DIR` are set in the host's environment, never committed.

## Data policy

This repository contains **no real patient data**. Databases, CSV files, session files and secrets are excluded by `.gitignore` and are never committed. `sample_data/` holds made-up records for testing only.

## Author

Thomas Franco: [GitHub](https://github.com/thomas0997) · [LinkedIn](https://linkedin.com/in/thomas-franco-730209400)
