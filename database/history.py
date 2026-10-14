"""
SQLite persistence for analysis history (Member 2).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def init_db(db_path: str) -> None:
    """Create the analyses table if it does not exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TEXT NOT NULL,
                health_score INTEGER,
                status TEXT,
                payload TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_analysis(result: dict, db_path: str) -> int:
    """Persist a full analysis payload and return the row id."""
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
            INSERT INTO analyses (target, created_at, health_score, status, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target, created_at, health_score, status, payload),
        )
        conn.commit()
        return int(cursor.lastrowid)


def list_analyses(limit: int = 20, db_path: str = "") -> list[dict]:
    """Return recent analysis summaries."""
    if not db_path:
        return []
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, target, created_at, health_score, status
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def get_analysis(analysis_id: int, db_path: str) -> dict | None:
    """Load a full analysis payload by id."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT payload FROM analyses WHERE id = ?",
            (int(analysis_id),),
        ).fetchone()
    if not row:
        return None
    return json.loads(row[0])
