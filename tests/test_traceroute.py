from unittest.mock import MagicMock, patch

from diagnostics.traceroute_check import analyze_traceroute, build_traceroute_command


def test_traceroute_command_no_shell():
    cmd = build_traceroute_command("example.com", 10)
    assert cmd[-1] == "example.com"


@patch("diagnostics.traceroute_check.subprocess.run")
def test_traceroute_parses_windows_output(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="""Tracing route to example.com
  1     1 ms     1 ms     1 ms  192.168.1.1
  2     5 ms     6 ms     5 ms  10.0.0.1
""",
        stderr="",
    )
    result = analyze_traceroute("example.com", max_hops=5, timeout=10)
    assert result["status"] in ("success", "partial")
    assert len(result["hops"]) >= 1
