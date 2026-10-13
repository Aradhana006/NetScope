"""
Optional DNS transport experiment (Member 1).

Demonstrates that DNS messages can be exchanged over UDP and TCP using dnspython.
Kept separate from the primary ``analyze_dns`` response unless explicitly requested.
"""

from __future__ import annotations

import time

import dns.message
import dns.query
import dns.rdatatype

from validators import is_ip_address, validate_target

DEFAULT_DNS_SERVER = "8.8.8.8"


def compare_dns_udp_tcp(
    target: str,
    record_type: str = "A",
    nameserver: str = DEFAULT_DNS_SERVER,
    timeout: float = 3.0,
) -> dict:
    """
    Send the same DNS question over UDP and TCP and compare elapsed times.

    This is an educational experiment; UDP is not guaranteed to be faster than TCP.
    """
    ok, normalized, err = validate_target(target)
    if not ok:
        return {"status": "error", "error": err, "udp": None, "tcp": None}

    if is_ip_address(normalized or ""):
        return {
            "status": "error",
            "error": "Transport experiment requires a hostname, not an IP literal.",
            "udp": None,
            "tcp": None,
        }

    hostname = normalized or target
    rdtype = dns.rdatatype.from_text(record_type)
    query = dns.message.make_query(hostname, rdtype)

    results: dict = {
        "status": "success",
        "target": hostname,
        "record_type": record_type,
        "nameserver": nameserver,
        "udp": None,
        "tcp": None,
        "error": None,
    }

    # UDP
    try:
        t0 = time.perf_counter()
        udp_response = dns.query.udp(query, nameserver, timeout=timeout)
        udp_ms = (time.perf_counter() - t0) * 1000
        results["udp"] = {
            "response_code": dns.rcode.to_text(udp_response.rcode()),
            "response_time_ms": round(udp_ms, 2),
            "status": "success",
            "error": None,
        }
    except Exception as exc:
        results["udp"] = {
            "response_code": None,
            "response_time_ms": None,
            "status": "error",
            "error": exc.__class__.__name__,
        }
        results["status"] = "partial"

    # TCP
    try:
        t0 = time.perf_counter()
        tcp_response = dns.query.tcp(query, nameserver, timeout=timeout)
        tcp_ms = (time.perf_counter() - t0) * 1000
        results["tcp"] = {
            "response_code": dns.rcode.to_text(tcp_response.rcode()),
            "response_time_ms": round(tcp_ms, 2),
            "status": "success",
            "error": None,
        }
    except Exception as exc:
        results["tcp"] = {
            "response_code": None,
            "response_time_ms": None,
            "status": "error",
            "error": exc.__class__.__name__,
        }
        results["status"] = "partial"

    if results["udp"] and results["udp"]["status"] == "error" and results["tcp"] and results["tcp"]["status"] == "error":
        results["status"] = "error"
        results["error"] = "Both UDP and TCP DNS queries failed."

    return results
