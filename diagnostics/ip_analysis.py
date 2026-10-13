"""
IPv4 and IPv6 address analysis (Member 1).

Uses the ``ipaddress`` module to classify input and extract addresses from DNS A/AAAA
results. Address availability from DNS is not the same as network reachability.
"""

from __future__ import annotations

import ipaddress

from validators import is_ip_address, validate_target


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _parse_rr_addresses(records: dict[str, list[str]] | None) -> tuple[list[str], list[str]]:
    """Extract valid IPv4/IPv6 strings from DNS A and AAAA record values."""
    records = records or {}
    ipv4: list[str] = []
    ipv6: list[str] = []

    for value in records.get("A", []):
        try:
            ipv4.append(str(ipaddress.ip_address(value.strip())))
        except ValueError:
            continue

    for value in records.get("AAAA", []):
        try:
            ipv6.append(str(ipaddress.ip_address(value.strip())))
        except ValueError:
            continue

    return _dedupe_preserve_order(ipv4), _dedupe_preserve_order(ipv6)


def _address_family_label(ipv4_available: bool, ipv6_available: bool) -> str:
    if ipv4_available and ipv6_available:
        return "Dual-Stack"
    if ipv4_available:
        return "IPv4"
    if ipv6_available:
        return "IPv6"
    return "None"


def analyze_ip(target: str, dns_result: dict | None) -> dict:
    """
    Analyze IPv4/IPv6 availability for ``target``.

    Parameters:
        target: Hostname or IP literal (validated).
        dns_result: Output from ``analyze_dns`` (may be partial or empty for IP literals).

    Returns:
        Structured address-family summary (JSON-serializable).
    """
    ok, normalized, err = validate_target(target)
    if not ok:
        return {
            "status": "error",
            "input_type": "invalid",
            "ipv4_available": False,
            "ipv6_available": False,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "address_family": "None",
            "error": err,
        }

    target = normalized or target
    dns_result = dns_result or {}

    if is_ip_address(target):
        addr = ipaddress.ip_address(target)
        if addr.version == 4:
            return {
                "status": "success",
                "input_type": "ipv4",
                "ipv4_available": True,
                "ipv6_available": False,
                "ipv4_addresses": [str(addr)],
                "ipv6_addresses": [],
                "address_family": "IPv4",
                "error": None,
            }
        return {
            "status": "success",
            "input_type": "ipv6",
            "ipv4_available": False,
            "ipv6_available": True,
            "ipv4_addresses": [],
            "ipv6_addresses": [str(addr)],
            "address_family": "IPv6",
            "error": None,
        }

    ipv4, ipv6 = _parse_rr_addresses(dns_result.get("records"))
    ipv4_ok = len(ipv4) > 0
    ipv6_ok = len(ipv6) > 0

    status = "success"
    error = None
    if dns_result.get("status") == "error":
        status = "partial"
        error = "DNS resolution failed; no addresses extracted from records."
    elif not ipv4_ok and not ipv6_ok:
        status = "partial"
        error = "No A or AAAA records available to infer address families."

    return {
        "status": status,
        "input_type": "hostname",
        "ipv4_available": ipv4_ok,
        "ipv6_available": ipv6_ok,
        "ipv4_addresses": ipv4,
        "ipv6_addresses": ipv6,
        "address_family": _address_family_label(ipv4_ok, ipv6_ok),
        "error": error,
    }
