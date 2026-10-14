"""
Traceroute diagnostics (Member 2).

Shows hop-by-hop path and RTT — demonstrates routing and TTL decrements.
"""

from __future__ import annotations

import platform
import re
import subprocess
import time

MAX_HOPS = 15


def _traceroute_result(
    status: str,
    hops: list[dict],
    error: str | None,
    elapsed_ms: float | None = None,
) -> dict:
    return {
        "status": status,
        "hops": hops,
        "hop_count": len(hops),
        "elapsed_ms": round(elapsed_ms, 2) if elapsed_ms is not None else None,
        "error": error,
    }


def build_traceroute_command(target: str, max_hops: int) -> list[str]:
    hops = max(1, min(int(max_hops), MAX_HOPS))
    if platform.system().lower() == "windows":
        return ["tracert", "-h", str(hops), "-w", "2000", target]
    return ["traceroute", "-m", str(hops), "-q", "1", "-w", "2", target]


def parse_windows_tracert(output: str) -> list[dict]:
    hops: list[dict] = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(?:(\d+)\s+ms|\*)\s+(?:(\d+)\s+ms|\*)\s+(?:(\d+)\s+ms|\*)\s+(.+)", line)
        if not match:
            continue
        hop_no = int(match.group(1))
        times = []
        for g in (match.group(2), match.group(3), match.group(4)):
            if g and g.isdigit():
                times.append(float(g))
        addr = match.group(5).strip()
        if addr.lower().startswith("request timed out"):
            addr = "*"
        hops.append(
            {
                "hop": hop_no,
                "address": addr,
                "rtt_ms": times,
                "avg_rtt_ms": round(sum(times) / len(times), 2) if times else None,
            }
        )
    return hops


def parse_unix_traceroute(output: str) -> list[dict]:
    hops: list[dict] = []
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue
        hop_no = int(match.group(1))
        rest = match.group(2)
        times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", rest)]
        addr_match = re.search(r"\(([^)]+)\)|\s([\d.]+)\s", rest)
        addr = "*"
        if addr_match:
            addr = (addr_match.group(1) or addr_match.group(2) or "*").strip()
        hops.append(
            {
                "hop": hop_no,
                "address": addr,
                "rtt_ms": times,
                "avg_rtt_ms": round(sum(times) / len(times), 2) if times else None,
            }
        )
    return hops


def analyze_traceroute(
    target: str, max_hops: int = 15, timeout: float = 30.0
) -> dict:
    """Run traceroute with bounded hops and timeout (no shell)."""
    cmd = build_traceroute_command(target, max_hops)
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _traceroute_result("error", [], "Traceroute timed out.")
    except FileNotFoundError:
        return _traceroute_result(
            "error",
            [],
            "Traceroute utility not found on this system.",
        )
    except OSError as exc:
        return _traceroute_result("error", [], f"Could not run traceroute: {exc}")

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    if platform.system().lower() == "windows":
        hops = parse_windows_tracert(output)
    else:
        hops = parse_unix_traceroute(output)

    elapsed = (time.perf_counter() - start) * 1000
    if not hops:
        return _traceroute_result(
            "partial",
            [],
            "Traceroute finished but no hops could be parsed.",
            elapsed,
        )
    return _traceroute_result("success", hops, None, elapsed)
