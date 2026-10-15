"""
ICMP reachability and latency via the OS ping utility (Member 2).

Ping measures ICMP echo reachability. Many hosts block ICMP, so a failed ping does
not prove that a website or TCP service is unavailable.
"""

from __future__ import annotations

import platform
import re
import subprocess
import sys

MAX_PROBES = 4


def _connectivity_result(
    *,
    status: str,
    reachable: bool | None,
    average_rtt_ms: float | None,
    packet_loss_percent: float | None,
    probes_sent: int,
    rtt_samples_ms: list[float],
    error: str | None,
) -> dict:
    return {
        "status": status,
        "reachable": reachable,
        "average_rtt_ms": round(average_rtt_ms, 2) if average_rtt_ms is not None else None,
        "packet_loss_percent": (
            round(packet_loss_percent, 2) if packet_loss_percent is not None else None
        ),
        "probes_sent": probes_sent,
        "rtt_samples_ms": [round(x, 2) for x in rtt_samples_ms],
        "error": error,
    }


def build_ping_command(target: str, count: int, timeout: float) -> list[str]:
    """Build a safe ping argv list (no shell)."""
    count = max(1, min(int(count), MAX_PROBES))
    if platform.system().lower() == "windows":
        # -w on Windows is timeout per echo reply in ms; divide total timeout by count
        per_probe_ms = max(1000, int((timeout / count) * 1000))
        return ["ping", "-n", str(count), "-w", str(per_probe_ms), target]
    wait_sec = max(1, int(timeout / count))
    cmd = ["ping", "-c", str(count), "-W", str(wait_sec), target]
    if sys.platform == "darwin":
        cmd = ["ping", "-c", str(count), target]
    return cmd


def parse_windows_ping_output(output: str) -> tuple[list[float], float | None, float | None]:
    samples: list[float] = []
    for match in re.finditer(r"time[=<](\d+(?:\.\d+)?)\s*ms", output, re.I):
        samples.append(float(match.group(1)))

    loss_match = re.search(r"(\d+)%\s*loss", output, re.I)
    packet_loss = float(loss_match.group(1)) if loss_match else None

    avg_match = re.search(r"Average\s*=\s*(\d+(?:\.\d+)?)\s*ms", output, re.I)
    average = float(avg_match.group(1)) if avg_match else None
    if average is None and samples:
        average = sum(samples) / len(samples)
    return samples, average, packet_loss


def parse_unix_ping_output(output: str) -> tuple[list[float], float | None, float | None]:
    samples: list[float] = []
    for match in re.finditer(r"time=(\d+(?:\.\d+)?)\s*ms", output, re.I):
        samples.append(float(match.group(1)))

    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", output, re.I)
    packet_loss = float(loss_match.group(1)) if loss_match else None

    avg_match = re.search(
        r"(?:rtt min/avg/max/(?:mdev|stddev)\s*=\s*)[\d.]+/([\d.]+)/", output, re.I
    )
    average = float(avg_match.group(1)) if avg_match else None
    if average is None and samples:
        average = sum(samples) / len(samples)
    return samples, average, packet_loss


def analyze_connectivity(
    target: str, count: int = 4, timeout: float = 10.0
) -> dict:
    """Run ping-based connectivity checks."""
    probes = max(1, min(int(count), MAX_PROBES))
    cmd = build_ping_command(target, probes, timeout)

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if platform.system().lower() == "windows":
            samples, average, loss = parse_windows_ping_output(raw)
        else:
            samples, average, loss = parse_unix_ping_output(raw)
        if samples:
            return _connectivity_result(
                status="partial",
                reachable=True,
                average_rtt_ms=average,
                packet_loss_percent=loss if loss is not None else round((1.0 - len(samples) / probes) * 100, 2),
                probes_sent=probes,
                rtt_samples_ms=samples,
                error="Ping timed out after partial replies (ICMP may be degraded or firewalled).",
            )
        return _connectivity_result(
            status="error",
            reachable=False,
            average_rtt_ms=None,
            packet_loss_percent=100.0,
            probes_sent=probes,
            rtt_samples_ms=[],
            error="Ping command timed out (ICMP may be blocked or host unreachable).",
        )
    except OSError as exc:
        return _connectivity_result(
            status="error",
            reachable=None,
            average_rtt_ms=None,
            packet_loss_percent=None,
            probes_sent=probes,
            rtt_samples_ms=[],
            error=f"Could not execute ping: {exc}",
        )

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    if platform.system().lower() == "windows":
        samples, average, loss = parse_windows_ping_output(output)
    else:
        samples, average, loss = parse_unix_ping_output(output)

    if not samples and completed.returncode != 0:
        return _connectivity_result(
            status="error",
            reachable=False,
            average_rtt_ms=average,
            packet_loss_percent=loss if loss is not None else 100.0,
            probes_sent=probes,
            rtt_samples_ms=samples,
            error=(
                "Ping did not receive replies. ICMP is often blocked; "
                "check TCP/HTTP results before assuming the service is down."
            ),
        )

    if not samples:
        return _connectivity_result(
            status="partial",
            reachable=False,
            average_rtt_ms=None,
            packet_loss_percent=loss,
            probes_sent=probes,
            rtt_samples_ms=[],
            error="Ping completed but RTT samples could not be parsed.",
        )

    reachable = len(samples) > 0
    return _connectivity_result(
        status="success",
        reachable=reachable,
        average_rtt_ms=average,
        packet_loss_percent=loss if loss is not None else 0.0,
        probes_sent=probes,
        rtt_samples_ms=samples,
        error=None,
    )
