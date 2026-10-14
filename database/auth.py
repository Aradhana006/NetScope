"""Simple session-based user accounts (academic demo)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import re

from werkzeug.security import check_password_hash, generate_password_hash

_PASSWORD_MIN_LEN = 8
_PASSWORD_HAS_LETTER = re.compile(r"[A-Za-z]")
_PASSWORD_HAS_DIGIT = re.compile(r"\d")


def validate_password(password: str) -> str | None:
    """Return an error message if invalid, else None."""
    if not password or len(password) < _PASSWORD_MIN_LEN:
        return f"Password must be at least {_PASSWORD_MIN_LEN} characters."
    if not _PASSWORD_HAS_LETTER.search(password):
        return "Password must include at least one letter."
    if not _PASSWORD_HAS_DIGIT.search(password):
        return "Password must include at least one number."
    return None


def init_auth_tables(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def create_user(db_path: str, email: str, password: str, full_name: str, created_at: str) -> tuple[bool, str | None, int | None]:
    init_auth_tables(db_path)
    email = email.strip().lower()
    if not email or "@" not in email:
        return False, "Enter a valid email address.", None
    pwd_err = validate_password(password)
    if pwd_err:
        return False, pwd_err, None
    name = (full_name or email.split("@")[0]).strip()
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO users (email, full_name, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (email, name, generate_password_hash(password), created_at),
            )
            conn.commit()
            return True, None, int(cur.lastrowid)
    except sqlite3.IntegrityError:
        return False, "This email is already registered. Use Log in with the same email and password.", None


def authenticate(db_path: str, email: str, password: str) -> tuple[bool, str | None, dict | None]:
    init_auth_tables(db_path)
    email = email.strip().lower()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return False, "Invalid email or password.", None
    if not check_password_hash(row["password_hash"], password):
        return False, "Invalid email or password.", None
    return True, None, {"id": row["id"], "email": row["email"], "full_name": row["full_name"]}


def get_user(db_path: str, user_id: int) -> dict | None:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id, email, full_name FROM users WHERE id = ?", (int(user_id),)).fetchone()
    return dict(row) if row else None
