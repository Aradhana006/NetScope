"""
SQLite persistence for analysis history (Member 2).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.auth import init_auth_tables


def init_db(db_path: str) -> None:
    """Create analyses and user tables."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    init_auth_tables(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                health_score INTEGER,
                status TEXT,
                payload TEXT NOT NULL
            )
            """
        )
        cols = {row[1] for row in conn.execute("PRAGMA table_info(analyses)")}
        if "user_id" not in cols:
            conn.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER")
        conn.commit()


def save_analysis(result: dict, db_path: str, user_id: int | None = None) -> int:
    init_db(db_path)
    target = result.get("target", "")
    created_at = result.get("timestamp") or ""
    diagnosis = result.get("diagnosis") or {}
    health_score = diagnosis.get("health_score")
    status = diagnosis.get("status")
    payload = json.dumps(result)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses (user_id, target, created_at, health_score, status, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, target, created_at, health_score, status, payload),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_analyses(limit: int = 20, db_path: str = "", user_id: int | None = None) -> list[dict]:
    if not db_path:
        return []
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        if user_id is not None:
            rows = conn.execute(
                """
                SELECT id, target, created_at, health_score, status
                FROM analyses WHERE user_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (int(user_id), max(1, int(limit))),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, target, created_at, health_score, status
                FROM analyses
                ORDER BY id DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
    return [dict(row) for row in rows]


def get_analysis(analysis_id: int, db_path: str, user_id: int | None = None) -> dict | None:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        if user_id is not None:
            row = conn.execute(
                "SELECT payload FROM analyses WHERE id = ? AND user_id = ?",
                (int(analysis_id), int(user_id)),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT payload FROM analyses WHERE id = ?",
                (int(analysis_id),),
            ).fetchone()
    if not row:
        return None
    return json.loads(row[0])


def user_stats(db_path: str, user_id: int) -> dict:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE user_id = ?", (int(user_id),)
        ).fetchone()[0]
        issues = conn.execute(
            """
            SELECT COUNT(*) FROM analyses
            WHERE user_id = ? AND status IN ('Degraded', 'Unavailable')
            """,
            (int(user_id),),
        ).fetchone()[0]
        avg = conn.execute(
            "SELECT AVG(health_score) FROM analyses WHERE user_id = ? AND health_score IS NOT NULL",
            (int(user_id),),
        ).fetchone()[0]
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        this_week = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE user_id = ? AND created_at >= ?",
            (int(user_id), week_ago),
        ).fetchone()[0]
    return {
        "total_analyses": int(total or 0),
        "reports_saved": int(total or 0),
        "this_week": int(this_week or 0),
        "issues_found": int(issues or 0),
        "average_health": round(float(avg), 1) if avg is not None else None,
    }
