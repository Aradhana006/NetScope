"""
Compare saved analyses for DNS, packet loss, and HTTP timing changes.
"""

from __future__ import annotations


def _num(value) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _delta(a: float | None, b: float | None) -> float | None:
    if a is None or b is None:
        return None
    return round(b - a, 2)


def compare_analyses(baseline: dict, current: dict) -> dict:
    """
    Compare two full analysis payloads (baseline = older, current = newer).
    """
    base_dns = baseline.get("dns") or {}
    cur_dns = current.get("dns") or {}
    base_conn = baseline.get("connectivity") or {}
    cur_conn = current.get("connectivity") or {}
    base_http = baseline.get("http") or {}
    cur_http = current.get("http") or {}

    base_https = (base_http.get("https") or {}).get("response_time_ms")
    cur_https = (cur_http.get("https") or {}).get("response_time_ms")

    dns_a = _num(base_dns.get("response_time_ms"))
    dns_b = _num(cur_dns.get("response_time_ms"))
    loss_a = _num(base_conn.get("packet_loss_percent"))
    loss_b = _num(cur_conn.get("packet_loss_percent"))
    http_a = _num(base_https)
    http_b = _num(cur_https)

    score_a = (baseline.get("diagnosis") or {}).get("health_score")
    score_b = (current.get("diagnosis") or {}).get("health_score")

    notes: list[str] = []
    if dns_a is not None and dns_b is not None:
        d = dns_b - dns_a
        if abs(d) >= 20:
            notes.append(f"DNS lookup time changed by {d:+.1f} ms.")
    if loss_a is not None and loss_b is not None and loss_b > loss_a:
        notes.append(f"Packet loss increased from {loss_a}% to {loss_b}%.")
    if http_a is not None and http_b is not None:
        d = http_b - http_a
        if abs(d) >= 50:
            notes.append(f"HTTPS response time changed by {d:+.1f} ms.")

    if not notes:
        notes.append("No major metric shifts detected between selected runs.")

    return {
        "status": "success",
        "baseline": {
            "id": baseline.get("id"),
            "timestamp": baseline.get("timestamp"),
            "target": baseline.get("target"),
        },
        "current": {
            "id": current.get("id"),
            "timestamp": current.get("timestamp"),
            "target": current.get("target"),
        },
        "metrics": {
            "dns_response_time_ms": {"baseline": dns_a, "current": dns_b, "delta": _delta(dns_a, dns_b)},
            "packet_loss_percent": {"baseline": loss_a, "current": loss_b, "delta": _delta(loss_a, loss_b)},
            "https_response_time_ms": {"baseline": http_a, "current": http_b, "delta": _delta(http_a, http_b)},
            "health_score": {"baseline": score_a, "current": score_b, "delta": _delta(score_a, score_b)},
        },
        "summary": notes,
    }
