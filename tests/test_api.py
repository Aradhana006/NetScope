"""Basic API tests for the NetScope Flask application."""

from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint_returns_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "NetScope"


def test_dashboard_returns_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"NetScope" in response.data
    assert b"text/html" in response.content_type.encode()


def test_analyze_rejects_non_json(client):
    response = client.post("/api/analyze", data="target=example.com")
    assert response.status_code == 400


def test_analyze_rejects_invalid_target(client):
    response = client.post(
        "/api/analyze",
        json={"target": "bad host name!!"},
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


@patch("app.analyze_dns")
def test_analyze_returns_dns_section(mock_analyze_dns, client):
    mock_analyze_dns.return_value = {
        "status": "success",
        "response_time_ms": 12.5,
        "records": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
        "error": None,
    }

    response = client.post("/api/analyze", json={"target": "example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["target"] == "example.com"
    assert data["dns"]["status"] == "success"
    assert data["dns"]["records"]["A"] == ["93.184.216.34"]
    assert data["connectivity"]["status"] == "skipped"
    assert "timestamp" in data
