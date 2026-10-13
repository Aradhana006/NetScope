"""
DNS analysis module (Member 1).

Resolves A, AAAA, MX, NS, and CNAME using dnspython and returns structured JSON.
"""

from __future__ import annotations

import time
from typing import Any

import dns.exception
import dns.resolver

from validators import is_ip_address

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


def _empty_records() -> dict[str, list[str]]:
    return {rtype: [] for rtype in RECORD_TYPES}


def _format_record(rtype: str, rdata: Any) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if rtype in ("NS", "CNAME"):
        return rdata.to_text().rstrip(".")
    return rdata.to_text()


def _dns_success(
    response_time_ms: float,
    records: dict[str, list[str]],
    error: str | None = None,
    status: str = "success",
) -> dict:
    return {
        "status": status,
        "response_time_ms": round(response_time_ms, 2),
        "records": records,
        "error": error,
    }


def _dns_error(message: str, response_time_ms: float | None = None) -> dict:
    return {
        "status": "error",
        "response_time_ms": response_time_ms,
        "records": _empty_records(),
        "error": message,
    }


def analyze_dns(target: str, timeout: float = 5.0) -> dict:
    """
    Run DNS lookups for ``target``.

    Parameters:
        target: Hostname or IP (validated by the app layer).
        timeout: Per-query timeout in seconds (applied to resolver timeout/lifetime).

    Returns:
        Dict with keys: status, response_time_ms, records, error.
    """
    if is_ip_address(target):
        return _dns_success(
            0.0,
            _empty_records(),
            error=(
                "Resource record lookups apply to hostnames; "
                "target is an IP address (no A/AAAA/MX/NS/CNAME query performed)."
            ),
            status="partial",
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = _empty_records()
    start = time.perf_counter()
    had_answer = False
    last_error: str | None = None
    fatal = False

    for rtype in RECORD_TYPES:
        try:
            answer = resolver.resolve(target, rtype)
            for rdata in answer:
                records[rtype].append(_format_record(rtype, rdata))
            if records[rtype]:
                had_answer = True
        except dns.resolver.NXDOMAIN:
            elapsed = (time.perf_counter() - start) * 1000
            return _dns_error(f"Domain '{target}' does not exist (NXDOMAIN).", elapsed)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            last_error = "No nameservers responded for this query."
        except dns.exception.Timeout:
            last_error = "DNS lookup timed out."
            fatal = True
            break
        except dns.resolver.LifetimeTimeout:
            last_error = "DNS lookup timed out."
            fatal = True
            break
        except dns.exception.DNSException as exc:
            last_error = f"DNS error: {exc.__class__.__name__}."
        except OSError as exc:
            last_error = f"Network error during DNS lookup: {exc.strerror or exc}."
            fatal = True
            break

    elapsed = (time.perf_counter() - start) * 1000

    if fatal and not had_answer:
        return _dns_error(last_error or "DNS lookup failed.", elapsed)

    if not had_answer and last_error:
        return _dns_success(elapsed, records, error=last_error, status="partial")

    return _dns_success(elapsed, records)
