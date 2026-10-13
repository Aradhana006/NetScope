"""
Rule-based diagnostic engine (Member 2).

Combines module results into:
- health_score (0–100, educational heuristic)
- status: Healthy | Degraded | Unavailable
- suggestions: list of troubleshooting strings

Public API (to be implemented):

    build_diagnosis(
        target: str,
        dns: dict,
        connectivity: dict,
        tcp: dict,
        http: dict,
    ) -> dict
"""

from __future__ import annotations


def build_diagnosis(
    target: str,
    dns: dict,
    connectivity: dict,
    tcp: dict,
    http: dict,
) -> dict:
    """Aggregate diagnostic results into score and recommendations."""
    raise NotImplementedError(
        "Diagnostic scoring will be implemented after individual modules exist."
    )
