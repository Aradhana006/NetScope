"""
TCP port reachability using Python sockets (Member 2).

An open TCP port confirms a handshake completed; it does not guarantee that the
application protocol is healthy or returning correct content.
"""

from __future__ import annotations

import socket
import time
from typing import Iterable

DEFAULT_PORTS = (80, 443)
MAX_PORTS = 8
ALLOWED_PORT_RANGE = range(1, 65536)


def _normalize_ports(ports: list[int] | None) -> list[int]:
    if not ports:
        ports = list(DEFAULT_PORTS)
    cleaned: list[int] = []
    for port in ports:
        if port not in ALLOWED_PORT_RANGE:
            continue
        if port not in cleaned:
            cleaned.append(port)
        if len(cleaned) >= MAX_PORTS:
            break
    return cleaned or list(DEFAULT_PORTS)


def _resolve_target(target: str) -> tuple[str | None, str | None]:
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        if not infos:
            return None, "Could not resolve host for TCP check."
        return infos[0][4][0], None
    except socket.gaierror:
        return None, "Could not resolve host for TCP check."


def _check_port(host: str, port: int, timeout: float) -> dict:
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000
        return {"state": "open", "latency_ms": round(latency_ms, 2), "error": None}
    except ConnectionRefusedError:
        return {
            "state": "refused",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": "Connection refused",
        }
    except socket.timeout:
        return {"state": "timeout", "latency_ms": None, "error": "Connection timed out"}
    except OSError as exc:
        return {"state": "error", "latency_ms": None, "error": exc.strerror or str(exc)}
    finally:
        if sock:
            sock.close()


def analyze_tcp(
    target: str, ports: list[int] | None = None, timeout: float = 5.0
) -> dict:
    """Test TCP connectivity to selected ports."""
    port_list = _normalize_ports(ports)
    host, resolve_error = _resolve_target(target)
    if not host:
        return {"status": "error", "ports": {}, "error": resolve_error}

    results: dict[str, dict] = {}
    open_count = 0
    for port in port_list:
        entry = _check_port(host, port, timeout)
        results[str(port)] = entry
        if entry["state"] == "open":
            open_count += 1

    if open_count == 0:
        return {
            "status": "partial",
            "ports": results,
            "error": "No TCP ports accepted connections (firewall or service down).",
        }
    if open_count < len(port_list):
        return {"status": "partial", "ports": results, "error": None}
    return {"status": "success", "ports": results, "error": None}
