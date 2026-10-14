"""Flask API integration tests."""

from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app()
    app.config["TESTING"] = True
    app.config["DATABASE_PATH"] = str(tmp_path / "test.db")
    with app.test_client() as client:
        yield client


def test_dashboard_ok(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"NetScope" in response.data


def test_health_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"


def test_analyze_requires_json(client):
    response = client.post("/api/analyze", data="target=x")
    assert response.status_code == 400


def test_analyze_missing_target(client):
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400


def test_analyze_invalid_target(client):
    response = client.post("/api/analyze", json={"target": "!!!"})
    assert response.status_code == 400


@patch("app.build_diagnosis")
@patch("app.analyze_http")
@patch("app.analyze_tcp")
@patch("app.analyze_connectivity")
@patch("app.analyze_ip")
@patch("app.analyze_dns")
def test_analyze_response_keys(
    mock_dns, mock_ip, mock_conn, mock_tcp, mock_http, mock_diag, client
):
    mock_dns.return_value = {
        "status": "success",
        "response_code": "NOERROR",
        "response_time_ms": 10,
        "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
        "ttls": {},
        "errors": {},
        "error": None,
    }
    mock_ip.return_value = {
        "status": "success",
        "input_type": "hostname",
        "ipv4_available": False,
        "ipv6_available": False,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "address_family": "None",
        "error": None,
    }
    mock_conn.return_value = {"status": "skipped", "error": "pending"}
    mock_tcp.return_value = {"status": "skipped", "ports": {}, "error": "pending"}
    mock_http.return_value = {"status": "skipped", "http": {}, "https": {}, "error": "pending"}
    mock_diag.return_value = {
        "health_score": 80,
        "status": "Healthy",
        "suggestions": [],
    }

    response = client.post("/api/analyze", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.get_json()
    for key in ("target", "timestamp", "dns", "ip_analysis", "connectivity", "tcp", "http", "diagnosis"):
        assert key in data


@patch("app.build_diagnosis")
@patch("app.analyze_http")
@patch("app.analyze_tcp")
@patch("app.analyze_connectivity")
@patch("app.analyze_ip")
@patch("app.analyze_dns")
def test_history_and_report_endpoints(
    mock_dns, mock_ip, mock_conn, mock_tcp, mock_http, mock_diag, client
):
    mock_dns.return_value = {
        "status": "success",
        "response_code": "NOERROR",
        "response_time_ms": 1,
        "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
        "ttls": {},
        "errors": {},
        "error": None,
    }
    mock_ip.return_value = {
        "status": "success",
        "input_type": "hostname",
        "ipv4_available": False,
        "ipv6_available": False,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "address_family": "None",
        "error": None,
    }
    mock_conn.return_value = {"status": "skipped", "reachable": None, "rtt_samples_ms": []}
    mock_tcp.return_value = {"status": "skipped", "ports": {}}
    mock_http.return_value = {"status": "skipped", "http": {}, "https": {}}
    mock_diag.return_value = {"health_score": 70, "status": "Degraded", "suggestions": ["test"]}

    analyze_resp = client.post("/api/analyze", json={"target": "example.com"})
    assert analyze_resp.status_code == 200
    analysis_id = analyze_resp.get_json()["id"]

    history_resp = client.get("/api/history")
    assert history_resp.status_code == 200
    assert len(history_resp.get_json()["items"]) >= 1

    report_resp = client.get(f"/api/report/{analysis_id}")
    assert report_resp.status_code == 200
    assert report_resp.mimetype == "application/pdf"


@patch("app.analyze_dns")
def test_analyze_module_exception_handled(mock_dns, client):
    mock_dns.side_effect = RuntimeError("boom")
    response = client.post("/api/analyze", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["dns"]["status"] == "error"
