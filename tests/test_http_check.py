"""Tests for HTTP/HTTPS diagnostics."""

from unittest.mock import MagicMock, patch

import requests

from diagnostics.http_check import analyze_http


def _response(status_code=200, url="https://example.com/"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.url = url
    resp.iter_content = lambda chunk_size: iter([b""])
    return resp


@patch("diagnostics.http_check.requests.head")
def test_http_https_success(mock_head):
    mock_head.return_value = _response(200, "https://example.com/")
    result = analyze_http("example.com", timeout=2.0)
    assert result["status"] in ("success", "partial")
    assert result["https"]["available"] is True
    assert result["https"]["status_code"] == 200


@patch("diagnostics.http_check.requests.get")
@patch("diagnostics.http_check.requests.head")
def test_http_head_fallback_get(mock_head, mock_get):
    mock_head.return_value = _response(405)
    mock_get.return_value = _response(200, "http://example.com/")
    result = analyze_http("example.com", timeout=2.0)
    assert result["http"]["available"] is True


@patch("diagnostics.http_check.requests.head")
def test_https_tls_error(mock_head):
    mock_head.side_effect = requests.exceptions.SSLError("cert")
    result = analyze_http("example.com", timeout=2.0)
    assert result["status"] == "error"
    assert result["https"]["error"] is not None


@patch("diagnostics.http_check.requests.head")
def test_http_timeout(mock_head):
    mock_head.side_effect = requests.exceptions.Timeout()
    result = analyze_http("example.com", timeout=1.0)
    assert result["status"] == "error"
