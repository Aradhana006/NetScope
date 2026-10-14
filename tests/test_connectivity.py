"""Tests for ping connectivity module."""

from unittest.mock import MagicMock, patch

from diagnostics.connectivity import (
    analyze_connectivity,
    build_ping_command,
    parse_unix_ping_output,
    parse_windows_ping_output,
)


def test_build_ping_command_uses_separate_target_argv():
    cmd = build_ping_command("example.com", 4, 10.0)
    assert cmd[-1] == "example.com"
    assert "example.com" not in " ".join(cmd[:-1])


def test_parse_windows_ping_output():
    output = """
Reply from 8.8.8.8: bytes=32 time=10ms TTL=118
Reply from 8.8.8.8: bytes=32 time=12ms TTL=118
Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 12ms, Average = 11ms
"""
    samples, avg, loss = parse_windows_ping_output(output)
    assert samples == [10.0, 12.0]
    assert avg == 11.0
    assert loss == 50.0


def test_parse_unix_ping_output():
    output = """
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=9.80 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=10.10 ms
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 9.800/10.100/10.400/0.250 ms
"""
    samples, avg, loss = parse_unix_ping_output(output)
    assert len(samples) == 2
    assert avg == 10.1
    assert loss == 0.0


@patch("diagnostics.connectivity.subprocess.run")
def test_analyze_connectivity_success(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="Reply from 1.1.1.1: bytes=32 time=5ms TTL=55\nAverage = 5ms",
        stderr="",
    )
    result = analyze_connectivity("1.1.1.1", count=4, timeout=5.0)
    assert result["status"] == "success"
    assert result["reachable"] is True
    mock_run.assert_called_once()
    assert mock_run.call_args.kwargs.get("shell") is not True


@patch("diagnostics.connectivity.subprocess.run")
def test_analyze_connectivity_timeout(mock_run):
    import subprocess

    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["ping"], timeout=5)
    result = analyze_connectivity("1.1.1.1")
    assert result["status"] == "error"
    assert "timed out" in (result["error"] or "").lower()
