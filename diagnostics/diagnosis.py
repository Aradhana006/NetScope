"""
Rule-based diagnostic engine with explainable insights.

Scoring (0–100 heuristic): base 50; DNS ±20/−35; ping ±10; TCP 443 ±15; HTTPS ±20/−10.
Thresholds: >=75 Healthy, >=45 Degraded, else Unavailable.
"""

from __future__ import annotations


def _module_status(module: dict | None) -> str:
    if not isinstance(module, dict):
        return "skipped"
    return str(module.get("status") or "skipped")


def _https_ok(http: dict | None) -> bool:
    if not isinstance(http, dict):
        return False
    https = http.get("https") or {}
    code = https.get("status_code")
    return bool(https.get("available")) and code is not None and code < 500


def _insight(issue: str, evidence: str, likely_cause: str, next_step: str) -> dict:
    return {
        "issue": issue,
        "evidence": evidence,
        "likely_cause": likely_cause,
        "next_step": next_step,
    }


def _finding(
    check: str,
    result: str,
    title: str,
    evidence: str,
    likely_cause: str,
    next_step: str,
) -> dict:
    return {
        "check": check,
        "result": result,
        "title": title,
        "evidence": evidence,
        "likely_cause": likely_cause,
        "next_step": next_step,
    }


def build_findings(
    target: str,
    dns: dict,
    connectivity: dict,
    tcp: dict,
    http: dict,
) -> list[dict]:
    """One explainable row per core layer (DNS, ping, TCP 443, HTTPS)."""
    dns = dns or {}
    connectivity = connectivity or {}
    tcp = tcp or {}
    http = http or {}

    findings: list[dict] = []

    dns_status = _module_status(dns)
    dns_code = (dns.get("response_code") or "").upper()
    if dns_code == "N/A":
        findings.append(
            _finding(
                "DNS",
                "skipped",
                "DNS not applicable",
                "Target is an IP address; hostname DNS record lookups were skipped.",
                "—",
                "Refer to IP Analysis and Connectivity checks.",
            )
        )
    elif dns_status == "skipped":
        findings.append(
            _finding(
                "DNS",
                "skipped",
                "DNS not run",
                "This check was not included in the analysis run.",
                "—",
                "Run a full analysis to evaluate DNS.",
            )
        )
    elif dns_status == "error" or dns_code == "NXDOMAIN":
        findings.append(
            _finding(
                "DNS",
                "failed",
                "DNS resolution failed",
                f"Response code: {dns_code or 'error'} for {target}",
                "The name may be misspelled, expired, or missing from authoritative DNS.",
                "Confirm spelling, try another resolver, or check domain registration.",
            )
        )
    elif dns_status == "partial":
        findings.append(
            _finding(
                "DNS",
                "warning",
                "Partial DNS answers",
                "Some record types returned errors or timeouts.",
                "A subset of DNS servers or record types may be misconfigured.",
                "Inspect per-type query notes in the DNS table.",
            )
        )
    else:
        rt = dns.get("response_time_ms")
        findings.append(
            _finding(
                "DNS",
                "passed",
                "DNS resolution OK",
                f"Lookup completed in {rt} ms with {dns_code or 'NOERROR'}.",
                "Authoritative DNS returned answers for the queried name.",
                "Proceed to connectivity and HTTP checks for reachability.",
            )
        )

    conn_status = _module_status(connectivity)
    https_ok = _https_ok(http)
    if conn_status == "skipped":
        findings.append(
            _finding(
                "ICMP / Ping",
                "skipped",
                "Ping not run",
                "ICMP reachability was not measured in this run.",
                "—",
                "Enable connectivity checks to measure RTT and packet loss.",
            )
        )
    elif conn_status == "success" and connectivity.get("reachable"):
        loss = connectivity.get("packet_loss_percent")
        avg = connectivity.get("average_rtt_ms")
        if loss is not None and loss > 0:
            findings.append(
                _finding(
                    "ICMP / Ping",
                    "warning",
                    "Packet loss observed",
                    f"ICMP loss {loss}%, average RTT {avg} ms",
                    "Congestion, Wi‑Fi issues, or routing problems on the path.",
                    "Repeat tests, compare history, or trace route to locate the hop.",
                )
            )
        else:
            findings.append(
                _finding(
                    "ICMP / Ping",
                    "passed",
                    "ICMP reachability OK",
                    f"Replies received; average RTT {avg} ms, loss {loss if loss is not None else 0}%.",
                    "The path responded to echo-request within expected bounds.",
                    "Use TCP/HTTPS results to confirm application availability.",
                )
            )
    elif https_ok and conn_status in ("error", "partial"):
        findings.append(
            _finding(
                "ICMP / Ping",
                "inconclusive",
                "ICMP reachability inconclusive",
                connectivity.get("error") or "No ping replies received",
                "Firewalls often block echo-request (ping) while TCP/443 still works.",
                "Check TCP port 443 and HTTPS before concluding the site is down.",
            )
        )
    else:
        findings.append(
            _finding(
                "ICMP / Ping",
                "warning",
                "ICMP reachability inconclusive",
                connectivity.get("error") or "No ping replies received",
                "ICMP may be blocked, or the host may be unreachable at multiple layers.",
                "Check TCP port 443 and HTTPS; compare with a prior saved run if unsure.",
            )
        )

    ports = (tcp or {}).get("ports") or {}
    p443 = ports.get("443") or {}
    p443_state = p443.get("state")
    if _module_status(tcp) == "skipped":
        findings.append(
            _finding(
                "TCP 443",
                "skipped",
                "TCP check not run",
                "Port 443 was not probed in this run.",
                "—",
                "Run TCP checks to confirm the web port accepts connections.",
            )
        )
    elif p443_state == "open":
        findings.append(
            _finding(
                "TCP 443",
                "passed",
                "HTTPS port reachable",
                f"TCP 443 state: open ({p443.get('latency_ms')} ms)",
                "A host accepted the TCP handshake on the web port.",
                "Verify HTTPS status codes — an open port does not guarantee a healthy app.",
            )
        )
    elif p443_state in ("refused", "timeout", "error"):
        findings.append(
            _finding(
                "TCP 443",
                "warning",
                "HTTPS port not reachable",
                f"TCP 443 state: {p443_state}",
                "Service stopped, firewall drop, or wrong host/port.",
                "Confirm firewall rules and that the web server is listening on 443.",
            )
        )
    else:
        findings.append(
            _finding(
                "TCP 443",
                "warning",
                "TCP 443 state unknown",
                f"Port state: {p443_state or '—'}",
                "The probe did not complete cleanly.",
                "Retry the analysis or test from another network.",
            )
        )

    https = http.get("https") or {}
    if _module_status(http) == "skipped":
        findings.append(
            _finding(
                "HTTPS",
                "skipped",
                "HTTP(S) not run",
                "Application-layer HTTP checks were not included.",
                "—",
                "Run HTTP/HTTPS checks to validate the live service.",
            )
        )
    elif _https_ok(http):
        code = https.get("status_code")
        findings.append(
            _finding(
                "HTTPS",
                "passed",
                "HTTPS service responded",
                f"Status {code}, {https.get('response_time_ms')} ms",
                "Application layer responded over TLS.",
                "Use historical comparison if users report intermittent slowness.",
            )
        )
    elif https.get("status_code") and https.get("status_code") >= 500:
        findings.append(
            _finding(
                "HTTPS",
                "failed",
                "Server error over HTTPS",
                f"HTTP status {https.get('status_code')}",
                "Origin or application failure despite reachable TCP/TLS.",
                "Inspect server logs and upstream dependencies.",
            )
        )
    else:
        findings.append(
            _finding(
                "HTTPS",
                "warning",
                "HTTPS unavailable",
                https.get("error") or "No successful HTTPS response",
                "Certificate, TLS mismatch, or blocking proxy.",
                "Test from another network and validate certificate chain.",
            )
        )

    return findings


def build_diagnosis(
    target: str,
    dns: dict,
    connectivity: dict,
    tcp: dict,
    http: dict,
) -> dict:
    score = 50
    suggestions: list[str] = []
    insights: list[dict] = []

    dns = dns or {}
    connectivity = connectivity or {}
    tcp = tcp or {}
    http = http or {}

    dns_status = _module_status(dns)
    dns_code = (dns.get("response_code") or "").upper()

    if dns_code == "N/A":
        # Neutral: IP literals do not use hostname DNS record resolution
        pass
    elif dns_status == "error" or dns_code == "NXDOMAIN":
        score -= 35
        msg = "DNS resolution failed — verify the hostname or DNS configuration."
        suggestions.append(msg)
        insights.append(
            _insight(
                "DNS resolution failed",
                f"Response code: {dns_code or 'error'} for {target}",
                "The name may be misspelled, expired, or missing from authoritative DNS.",
                "Confirm spelling, try another resolver, or check domain registration.",
            )
        )
    elif dns_status == "success" and dns_code in ("NOERROR", ""):
        score += 20
        suggestions.append("DNS resolution succeeded.")
        insights.append(
            _insight(
                "DNS resolution OK",
                f"Lookup completed in {dns.get('response_time_ms')} ms with NOERROR.",
                "Authoritative DNS returned answers for the queried name.",
                "Proceed to connectivity and HTTP checks for reachability.",
            )
        )
    elif dns_status == "partial":
        score -= 5
        suggestions.append("DNS returned partial results — review per-record errors.")
        insights.append(
            _insight(
                "Partial DNS answers",
                "Some record types returned errors or timeouts.",
                "A subset of DNS servers or record types may be misconfigured.",
                "Inspect per-type query notes in the DNS table.",
            )
        )

    conn_status = _module_status(connectivity)
    if conn_status == "success" and connectivity.get("reachable"):
        score += 10
        loss = connectivity.get("packet_loss_percent")
        avg = connectivity.get("average_rtt_ms")
        if loss is not None and loss > 0:
            suggestions.append(f"Ping reports {loss}% packet loss — investigate network path.")
            insights.append(
                _insight(
                    "Packet loss observed",
                    f"ICMP loss {loss}%, average RTT {avg} ms",
                    "Congestion, Wi‑Fi issues, or routing problems on the path.",
                    "Repeat tests, compare history, or trace route to locate the hop.",
                )
            )
    elif conn_status in ("error", "partial"):
        score -= 10
        suggestions.append(
            "Ping did not confirm ICMP reachability. Many networks block ICMP; "
            "rely on TCP/HTTP results for service availability."
        )
        insights.append(
            _insight(
                "ICMP reachability inconclusive",
                connectivity.get("error") or "No ping replies received",
                "Firewalls often block echo-request (ping) while TCP/443 still works.",
                "Check TCP port 443 and HTTPS before concluding the site is down.",
            )
        )

    ports = (tcp or {}).get("ports") or {}
    p443 = ports.get("443") or {}
    p443_state = p443.get("state")
    if _module_status(tcp) != "skipped":
        if p443_state == "open":
            score += 15
            suggestions.append("TCP port 443 accepted a connection.")
            insights.append(
                _insight(
                    "HTTPS port reachable",
                    f"TCP 443 state: open ({p443.get('latency_ms')} ms)",
                    "A host accepted the TCP handshake on the web port.",
                    "Verify HTTPS status codes — an open port does not guarantee a healthy app.",
                )
            )
        elif p443_state in ("refused", "timeout", "error"):
            score -= 15
            suggestions.append("TCP port 443 is not accepting connections — HTTPS may fail.")
            insights.append(
                _insight(
                    "HTTPS port not reachable",
                    f"TCP 443 state: {p443_state}",
                    "Service stopped, firewall drop, or wrong host/port.",
                    "Confirm firewall rules and that the web server is listening on 443.",
                )
            )

    https = http.get("https") or {}
    http_block = http.get("http") or {}
    if _module_status(http) != "skipped":
        if _https_ok(http):
            code = https.get("status_code")
            score += 20
            suggestions.append(f"HTTPS responded with status {code}.")
            insights.append(
                _insight(
                    "HTTPS service responded",
                    f"Status {code}, {https.get('response_time_ms')} ms",
                    "Application layer responded over TLS.",
                    "Use historical comparison if users report intermittent slowness.",
                )
            )
        elif https.get("status_code") and https.get("status_code") >= 500:
            score -= 20
            suggestions.append("HTTPS returned a server error (5xx).")
            insights.append(
                _insight(
                    "Server error over HTTPS",
                    f"HTTP status {https.get('status_code')}",
                    "Origin or application failure despite reachable TCP/TLS.",
                    "Inspect server logs and upstream dependencies.",
                )
            )
        else:
            score -= 10
            suggestions.append("HTTPS unavailable or TLS error.")
            insights.append(
                _insight(
                    "HTTPS unavailable",
                    https.get("error") or "No successful HTTPS response",
                    "Certificate, TLS mismatch, or blocking proxy.",
                    "Test from another network and validate certificate chain.",
                )
            )

        if http_block.get("status_code") and http_block.get("status_code") >= 500 and _https_ok(http):
            score -= 5
            suggestions.append("HTTP returned 5xx while HTTPS works.")

    score = max(0, min(100, score))

    if dns_status == "error" and not _https_ok(http):
        status = "Unavailable"
    elif score >= 75:
        status = "Healthy"
    elif score >= 45:
        status = "Degraded"
    else:
        status = "Unavailable"

    if not suggestions:
        suggestions.append("Review individual diagnostic sections for details.")

    findings = build_findings(target, dns, connectivity, tcp, http)
    if not insights:
        insights = [
            _insight(f["title"], f["evidence"], f["likely_cause"], f["next_step"])
            for f in findings
            if f["result"] != "skipped"
        ]

    return {
        "health_score": score,
        "status": status,
        "suggestions": suggestions,
        "insights": insights,
        "findings": findings,
    }
