"""
Rule-based diagnostic engine (Member 2).

Scoring rules (educational heuristic, 0–100):
- Base score: 50
- DNS success (NOERROR): +20; DNS error/NXDOMAIN: -35
- DNS partial only: -5
- Ping success (reachable): +10; ping error/unreachable: -10 (not treated as full outage)
- TCP 443 open: +15; 443 refused/timeout: -15
- HTTPS available with 2xx/3xx: +20; HTTPS 5xx: -20; HTTPS unavailable: -10
- HTTP 5xx when HTTPS ok: -5
- Skipped modules: no change (neutral)
- Clamp 0–100; map >=75 Healthy, >=45 Degraded, else Unavailable
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


def build_diagnosis(
    target: str,
    dns: dict,
    connectivity: dict,
    tcp: dict,
    http: dict,
) -> dict:
    score = 50
    suggestions: list[str] = []

    dns = dns or {}
    connectivity = connectivity or {}
    tcp = tcp or {}
    http = http or {}

    dns_status = _module_status(dns)
    dns_code = (dns.get("response_code") or "").upper()

    if dns_status == "error" or dns_code == "NXDOMAIN":
        score -= 35
        suggestions.append("DNS resolution failed — verify the hostname or DNS configuration.")
    elif dns_status == "success" and dns_code in ("NOERROR", ""):
        score += 20
        suggestions.append("DNS resolution succeeded.")
    elif dns_status == "partial":
        score -= 5
        suggestions.append("DNS returned partial results — review per-record errors.")

    conn_status = _module_status(connectivity)
    if conn_status == "skipped":
        suggestions.append("Ping module was skipped.")
    elif conn_status == "success" and connectivity.get("reachable"):
        score += 10
        loss = connectivity.get("packet_loss_percent")
        if loss is not None and loss > 0:
            suggestions.append(f"Ping reports {loss}% packet loss — investigate network path.")
    elif conn_status in ("error", "partial"):
        score -= 10
        suggestions.append(
            "Ping did not confirm ICMP reachability. Many networks block ICMP; "
            "rely on TCP/HTTP results for service availability."
        )

    ports = (tcp or {}).get("ports") or {}
    p443 = ports.get("443") or {}
    p443_state = p443.get("state")
    if _module_status(tcp) != "skipped":
        if p443_state == "open":
            score += 15
            suggestions.append("TCP port 443 accepted a connection (TLS service may be reachable).")
        elif p443_state in ("refused", "timeout", "error"):
            score -= 15
            suggestions.append("TCP port 443 is not accepting connections — HTTPS may fail.")

    https = http.get("https") or {}
    http_block = http.get("http") or {}
    if _module_status(http) != "skipped":
        if _https_ok(http):
            code = https.get("status_code")
            score += 20
            suggestions.append(f"HTTPS responded with status {code}.")
        elif https.get("status_code") and https.get("status_code") >= 500:
            score -= 20
            suggestions.append("HTTPS returned a server error (5xx) — issue may be on the web server.")
        else:
            score -= 10
            suggestions.append("HTTPS is unavailable or returned an error — check TLS and firewall rules.")

        if http_block.get("status_code") and http_block.get("status_code") >= 500 and _https_ok(http):
            score -= 5
            suggestions.append("HTTP returned 5xx while HTTPS works — clients may prefer HTTPS.")

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

    return {
        "health_score": score,
        "status": status,
        "suggestions": suggestions,
    }
