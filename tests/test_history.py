"""Tests for SQLite history storage."""

from database.history import get_analysis, init_db, list_analyses, save_analysis


def test_save_list_and_get(tmp_path):
    db_path = str(tmp_path / "history.db")
    payload = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {"health_score": 88, "status": "Healthy", "suggestions": []},
        "dns": {},
    }
    row_id = save_analysis(payload, db_path, user_id=1)
    assert row_id == 1

    items = list_analyses(limit=10, db_path=db_path)
    assert len(items) == 1
    assert items[0]["target"] == "example.com"
    assert items[0]["health_score"] == 88

    loaded = get_analysis(row_id, db_path)
    assert loaded is not None
    assert loaded["target"] == "example.com"
