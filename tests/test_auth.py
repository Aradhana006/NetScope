"""User auth validation tests."""

import os
from unittest.mock import patch

from app import _load_secret_key, create_app
from database.auth import create_user, validate_password


def test_secret_key_ignores_empty_env():
    with patch.dict(os.environ, {"NETSCOPE_SECRET_KEY": ""}, clear=False):
        assert _load_secret_key()


def test_register_api_with_empty_secret_env(tmp_path):
    with patch.dict(os.environ, {"NETSCOPE_SECRET_KEY": ""}, clear=False):
        app = create_app()
        app.config["TESTING"] = True
        app.config["DATABASE_PATH"] = str(tmp_path / "reg.db")
        client = app.test_client()
        r = client.post(
            "/api/auth/register",
            json={"email": "new@example.com", "password": "Password1", "full_name": "New"},
        )
    assert r.status_code == 200
    assert r.is_json


def test_validate_password_rules():
    assert validate_password("short1") is not None
    assert validate_password("allletters") is not None
    assert validate_password("12345678") is not None
    assert validate_password("SecurePass1") is None


def test_create_user_rejects_weak_password(tmp_path):
    db = str(tmp_path / "auth.db")
    ok, err, _ = create_user(db, "a@b.com", "weak", "Test", "2026-01-01T00:00:00Z")
    assert ok is False
    assert err is not None


def test_create_user_duplicate_email(tmp_path):
    db = str(tmp_path / "auth.db")
    ok, _, _ = create_user(db, "dup@example.com", "Password1", "One", "2026-01-01T00:00:00Z")
    assert ok is True
    ok2, err2, _ = create_user(db, "dup@example.com", "Password2", "Two", "2026-01-01T00:00:00Z")
    assert ok2 is False
    assert "already registered" in (err2 or "").lower()
