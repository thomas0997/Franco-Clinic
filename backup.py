"""Back up the clinic databases.

Copies patients.db and inventory.db into DATA_DIR/backups/<timestamp>/ using
SQLite's online backup, which is safe while the app is running, then checks
each copy and deletes the oldest backups beyond the number to keep.

Usage (from the app folder):
    python backup.py            keep the newest 30 backups
    python backup.py --keep 60

On PythonAnywhere, add a daily Scheduled Task:
    cd ~/Franco-Clinic && python backup.py

These copies sit on the same server as the app. Download one regularly to
somewhere safe (an encrypted drive), since a backup on the same machine
doesn't protect against losing the account.
"""
import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime

DATABASES = ("patients.db", "inventory.db")


def backup(data_dir, keep):
    root = os.path.join(data_dir, "backups")
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    target = os.path.join(root, stamp)
    os.makedirs(target, exist_ok=False)
    os.chmod(root, 0o700)
    os.chmod(target, 0o700)

    for name in DATABASES:
        src_path = os.path.join(data_dir, name)
        if not os.path.exists(src_path):
            print(f"skip {name}: not found")
            continue
        dst_path = os.path.join(target, name)
        src = sqlite3.connect(src_path)
        dst = sqlite3.connect(dst_path)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        os.chmod(dst_path, 0o600)
        with sqlite3.connect(dst_path) as check:
            result = check.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            sys.exit(f"Backup of {name} failed its integrity check: {result}")
        print(f"backed up {name} -> {dst_path}")

    # Delete the oldest backups beyond `keep`.
    existing = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    for old in existing[:-keep] if keep > 0 else []:
        shutil.rmtree(os.path.join(root, old))
        print(f"removed old backup {old}")
    return target


def main():
    parser = argparse.ArgumentParser(description="Back up the clinic databases")
    parser.add_argument("--keep", type=int, default=30, help="number of backups to keep (default 30)")
    args = parser.parse_args()
    data_dir = os.environ.get("DATA_DIR", os.path.abspath(os.path.dirname(__file__)))
    backup(data_dir, args.keep)


if __name__ == "__main__":
    main()
