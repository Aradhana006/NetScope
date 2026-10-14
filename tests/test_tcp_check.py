"""Tests for TCP port diagnostics."""

from unittest.mock import patch

from diagnostics.tcp_check import analyze_tcp


@patch("diagnostics.tcp_check.socket.create_connection")
@patch("diagnostics.tcp_check._resolve_target")
def test_tcp_open_ports(mock_resolve, mock_connect):
    mock_resolve.return_value = ("93.184.216.34", None)
    mock_connect.return_value.__enter__ = lambda s: s
    mock_connect.return_value.__exit__ = lambda *a: None

    result = analyze_tcp("example.com", ports=[80, 443], timeout=1.0)
    assert result["status"] in ("success", "partial")
    assert "80" in result["ports"]
    assert result["ports"]["80"]["state"] == "open"


@patch("diagnostics.tcp_check.socket.create_connection")
@patch("diagnostics.tcp_check._resolve_target")
def test_tcp_connection_refused(mock_resolve, mock_connect):
    mock_resolve.return_value = ("93.184.216.34", None)
    mock_connect.side_effect = ConnectionRefusedError()

    result = analyze_tcp("example.com", ports=[443], timeout=1.0)
    assert result["ports"]["443"]["state"] == "refused"


@patch("diagnostics.tcp_check._resolve_target")
def test_tcp_resolution_failure(mock_resolve):
    mock_resolve.return_value = (None, "Could not resolve host for TCP check.")
    result = analyze_tcp("invalid..host", ports=[80])
    assert result["status"] == "error"


def test_tcp_rejects_huge_port_list():
    ports = list(range(1, 50))
    result = analyze_tcp("127.0.0.1", ports=ports, timeout=0.1)
    assert len(result.get("ports", {})) <= 8
