"""
DNS protocol analysis (Member 1).

Demonstrates DNS as a name-to-resource mapping system: queries for common RR types
(A, AAAA, MX, NS, CNAME), response codes (NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT),
and the difference between "no records of this type" versus total resolution failure.

DNS success does not prove network reachability to the resolved addresses.
"""

from __future__ import annotations

import time
from typing import Any

import dns.exception
import dns.resolver

from validators import is_ip_address, validate_target

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")


def _empty_records() -> dict[str, list[str]]:
    return {rtype: [] for rtype in RECORD_TYPES}


def _empty_ttls() -> dict[str, int | None]:
    return {rtype: None for rtype in RECORD_TYPES}


def _empty_errors() -> dict[str, str | None]:
    return {rtype: None for rtype in RECORD_TYPES}


def _format_record(rtype: str, rdata: Any) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if rtype in ("NS", "CNAME"):
        return rdata.to_text().rstrip(".")
    return rdata.to_text()


def _make_result(
    *,
    status: str,
    response_time_ms: float | None,
    response_code: str,
    records: dict[str, list[str]] | None = None,
    ttls: dict[str, int | None] | None = None,
    errors: dict[str, str | None] | None = None,
    error: str | None = None,
) -> dict:
    return {
        "status": status,
        "response_time_ms": round(response_time_ms, 2) if response_time_ms is not None else None,
        "response_code": response_code,
        "records": records if records is not None else _empty_records(),
        "ttls": ttls if ttls is not None else _empty_ttls(),
        "errors": errors if errors is not None else _empty_errors(),
        "error": error,
    }


def analyze_dns(target: str, timeout: float = 3.0) -> dict:
    """
    Query DNS for ``target`` (hostname) and return structured record data.

    IP literals skip RR lookups (``partial``) because DNS name queries apply to hostnames.
    Each RR type is queried independently so one failure does not block others.
    """
    ok, normalized, err = validate_target(target)
    if not ok:
        return _make_result(
            status="error",
            response_time_ms=None,
            response_code="INVALID",
            error=err,
        )

    target = normalized or target

    if is_ip_address(target):
        return _make_result(
            status="partial",
            response_time_ms=0.0,
            response_code="N/A",
            error=(
                "Target is an IP address; DNS resource-record lookups apply to hostnames. "
                "Use IP analysis for address family details."
            ),
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    records = _empty_records()
    ttls = _empty_ttls()
    errors = _empty_errors()
    start = time.perf_counter()

    overall_code = "NOERROR"
    had_any_rr = False
    query_errors: list[str] = []
    fatal_code: str | None = None

    for rtype in RECORD_TYPES:
        try:
            answer = resolver.resolve(target, rtype)
            rrset = answer.rrset
            if rrset is not None:
                ttls[rtype] = int(rrset.ttl)
            for rdata in answer:
                records[rtype].append(_format_record(rtype, rdata))
            if records[rtype]:
                had_any_rr = True
            else:
                errors[rtype] = "No records of this type (NOERROR)."
        except dns.resolver.NXDOMAIN:
            elapsed = (time.perf_counter() - start) * 1000
            return _make_result(
                status="error",
                response_time_ms=elapsed,
                response_code="NXDOMAIN",
                records=records,
                ttls=ttls,
                errors=errors,
                error=f"The domain name '{target}' does not exist (NXDOMAIN).",
            )
        except dns.resolver.NoAnswer:
            errors[rtype] = "No records of this type (NOERROR)."
        except dns.resolver.NoNameservers:
            errors[rtype] = "SERVFAIL: no nameservers available."
            query_errors.append(f"{rtype}: SERVFAIL (no nameservers)")
            overall_code = "SERVFAIL"
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            errors[rtype] = "TIMEOUT"
            query_errors.append(f"{rtype}: TIMEOUT")
            overall_code = "TIMEOUT"
        except dns.resolver.ServFail:
            errors[rtype] = "SERVFAIL"
            query_errors.append(f"{rtype}: SERVFAIL")
            overall_code = "SERVFAIL"
        except dns.exception.DNSException as exc:
            label = exc.__class__.__name__
            errors[rtype] = label
            query_errors.append(f"{rtype}: {label}")
        except OSError as exc:
            msg = exc.strerror or str(exc)
            errors[rtype] = f"Network error: {msg}"
            query_errors.append(f"{rtype}: network error")
            overall_code = "SERVFAIL"

    elapsed = (time.perf_counter() - start) * 1000

    if fatal_code:
        overall_code = fatal_code

    if overall_code in ("TIMEOUT", "SERVFAIL") and not had_any_rr:
        return _make_result(
            status="error",
            response_time_ms=elapsed,
            response_code=overall_code,
            records=records,
            ttls=ttls,
            errors=errors,
            error="; ".join(query_errors) if query_errors else "DNS resolution failed.",
        )

    if query_errors and not had_any_rr:
        return _make_result(
            status="partial",
            response_time_ms=elapsed,
            response_code=overall_code,
            records=records,
            ttls=ttls,
            errors=errors,
            error="Some queries failed; see per-type errors.",
        )

    if query_errors:
        return _make_result(
            status="partial",
            response_time_ms=elapsed,
            response_code="NOERROR",
            records=records,
            ttls=ttls,
            errors=errors,
            error="Some record types returned errors; others succeeded.",
        )

    return _make_result(
        status="success",
        response_time_ms=elapsed,
        response_code="NOERROR",
        records=records,
        ttls=ttls,
        errors=errors,
        error=None,
    )
