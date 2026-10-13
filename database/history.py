"""
Analysis history storage using SQLite (Member 2, later stage).

Planned responsibilities:
- Initialize schema (target, timestamp, JSON blobs per module, health score).
- save_analysis(result: dict) -> int  # returns row id
- list_analyses(limit: int = 20) -> list[dict]
- get_analysis(analysis_id: int) -> dict | None

Database file path should default to instance/netscope.db or similar under .gitignore.
"""

from __future__ import annotations


def init_db(db_path: str) -> None:
    """Create tables if they do not exist. To be implemented."""
    raise NotImplementedError("History database will be implemented in a later stage.")
