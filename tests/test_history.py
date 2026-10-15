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


def test_save_duplicate_idempotency(tmp_path):
    db_path = str(tmp_path / "history.db")
    payload = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {"health_score": 88, "status": "Healthy"},
    }
    # Submit first time
    id1 = save_analysis(payload, db_path, user_id=1)
    # Submit second time with identical data (e.g. rapid double submission)
    id2 = save_analysis(payload, db_path, user_id=1)

    assert id1 == id2
    # Exactly one record saved
    items = list_analyses(limit=10, db_path=db_path, user_id=1)
    assert len(items) == 1


def test_save_distinct_analyses_same_target(tmp_path):
    db_path = str(tmp_path / "history.db")
    payload1 = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {"health_score": 88, "status": "Healthy"},
    }
    payload2 = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:05:00+00:00",
        "diagnosis": {"health_score": 92, "status": "Healthy"},
    }
    id1 = save_analysis(payload1, db_path, user_id=1)
    id2 = save_analysis(payload2, db_path, user_id=1)

    assert id1 != id2
    items = list_analyses(limit=10, db_path=db_path, user_id=1)
    assert len(items) == 2



def test_guest_analysis_not_persisted(tmp_path):
    db_path = str(tmp_path / "history.db")
    payload = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {"health_score": 90, "status": "Healthy"},
    }
    # Guest has user_id=None
    result = save_analysis(payload, db_path, user_id=None)
    assert result is None

    items = list_analyses(limit=10, db_path=db_path)
    assert len(items) == 0


def test_user_history_isolation(tmp_path):
    db_path = str(tmp_path / "history.db")
    p1 = {"target": "user1.org", "timestamp": "2026-10-14T10:00:00+00:00", "diagnosis": {}}
    p2 = {"target": "user2.org", "timestamp": "2026-10-14T11:00:00+00:00", "diagnosis": {}}

    id1 = save_analysis(p1, db_path, user_id=1)
    id2 = save_analysis(p2, db_path, user_id=2)

    # User 1 cannot see User 2's records
    u1_items = list_analyses(limit=10, db_path=db_path, user_id=1)
    assert len(u1_items) == 1
    assert u1_items[0]["target"] == "user1.org"
    assert get_analysis(id2, db_path, user_id=1) is None

    # User 2 cannot see User 1's records
    u2_items = list_analyses(limit=10, db_path=db_path, user_id=2)
    assert len(u2_items) == 1
    assert u2_items[0]["target"] == "user2.org"
    assert get_analysis(id1, db_path, user_id=2) is None


def test_format_timestamp_ist():
    from database.history import format_timestamp_ist

    # 18:11:19.860540 UTC + 5h30m = 23:41:19.860540 IST
    utc_str = "2026-10-14T18:11:19.860540+00:00"
    ist = format_timestamp_ist(utc_str)
    assert "14 Oct 2026" in ist
    assert "11:41:19 PM IST" in ist

    # Trailing Z
    z_str = "2026-10-14T18:11:19Z"
    ist_z = format_timestamp_ist(z_str)
    assert "14 Oct 2026" in ist_z
    assert "11:41:19 PM IST" in ist_z

    # Non-UTC offset (e.g. +02:00)
    offset_str = "2026-10-14T20:11:19+02:00"
    ist_offset = format_timestamp_ist(offset_str)
    assert "14 Oct 2026" in ist_offset
    assert "11:41:19 PM IST" in ist_offset

    # Missing / None
    assert format_timestamp_ist(None) == "—"
    assert format_timestamp_ist("") == "—"

    # Malformed
    assert format_timestamp_ist("not-a-date") == "not-a-date"
