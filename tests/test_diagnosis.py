"""Tests for rule-based diagnosis engine."""

from diagnostics.diagnosis import build_diagnosis


def _base_modules():
    return {
        "dns": {"status": "success", "response_code": "NOERROR"},
        "connectivity": {
            "status": "success",
            "reachable": True,
            "packet_loss_percent": 0,
        },
        "tcp": {"status": "success", "ports": {"443": {"state": "open"}}},
        "http": {
            "status": "success",
            "https": {"available": True, "status_code": 200},
            "http": {"available": True, "status_code": 200},
        },
    }


def test_diagnosis_healthy_scenario():
    m = _base_modules()
    result = build_diagnosis("example.com", m["dns"], m["connectivity"], m["tcp"], m["http"])
    assert result["status"] == "Healthy"
    assert result["health_score"] >= 75


def test_diagnosis_unavailable_on_dns_failure():
    dns = {"status": "error", "response_code": "NXDOMAIN"}
    http = {
        "status": "error",
        "https": {"available": False, "status_code": None},
        "http": {"available": False, "status_code": None},
    }
    result = build_diagnosis(
        "missing.example",
        dns,
        {"status": "skipped"},
        {"status": "skipped", "ports": {}},
        http,
    )
    assert result["status"] == "Unavailable"
    assert result["health_score"] < 45


def test_diagnosis_ping_fail_https_ok():
    m = _base_modules()
    conn = {"status": "error", "reachable": False}
    result = build_diagnosis("example.com", m["dns"], conn, m["tcp"], m["http"])
    assert result["status"] in ("Degraded", "Healthy")
    assert any("ICMP" in s for s in result["suggestions"])


def test_diagnosis_skipped_modules_neutral():
    result = build_diagnosis(
        "example.com",
        {"status": "success", "response_code": "NOERROR"},
        {"status": "skipped"},
        {"status": "skipped", "ports": {}},
        {"status": "skipped", "http": {}, "https": {}},
    )
    assert "health_score" in result
    assert result["status"] in ("Healthy", "Degraded", "Unavailable")
