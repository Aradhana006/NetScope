"""
HTTP and HTTPS availability checks using requests (Member 2).
"""

from __future__ import annotations

import ipaddress
import time

import requests
from requests.exceptions import RequestException, SSLError, Timeout

EMPTY_SCHEME = {
    "available": False,
    "status_code": None,
    "response_time_ms": None,
    "final_url": None,
    "error": None,
}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _build_url(scheme: str, target: str) -> str:
    host = target.strip()
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return f"{scheme}://{host}"


def _probe_url(url: str, timeout: float) -> dict:
    result = dict(EMPTY_SCHEME)
    connect_timeout = max(1.0, timeout / 2)
    read_timeout = max(1.0, timeout / 2)
    headers = {"User-Agent": "NetScope/1.0 (academic diagnostic)"}

    try:
        start = time.perf_counter()
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=(connect_timeout, read_timeout),
            headers=headers,
        )
        if response.status_code in (405, 501):
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=(connect_timeout, read_timeout),
                headers=headers,
                stream=True,
            )
            next(response.iter_content(256), None)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result.update(
            {
                "available": True,
                "status_code": response.status_code,
                "response_time_ms": round(elapsed_ms, 2),
                "final_url": response.url,
                "error": None,
            }
        )
        return result
    except SSLError as exc:
        result["error"] = f"TLS error: {exc.__class__.__name__}"
        return result
    except Timeout:
        result["error"] = "Request timed out"
        return result
    except RequestException as exc:
        result["error"] = f"Connection error: {exc.__class__.__name__}"
        return result


def analyze_http(target: str, timeout: float = 10.0) -> dict:
    """Check HTTP and HTTPS endpoints separately."""
    http_url = _build_url("http", target)
    https_url = _build_url("https", target)

    http_result = _probe_url(http_url, timeout)
    https_result = _probe_url(https_url, timeout)

    http_ok = http_result.get("available")
    https_ok = https_result.get("available")

    if http_ok or https_ok:
        status = "success" if (http_ok and https_ok) else "partial"
        return {
            "status": status,
            "http": http_result,
            "https": https_result,
            "error": None if status == "success" else "One scheme failed or is unavailable.",
        }

    return {
        "status": "error",
        "http": http_result,
        "https": https_result,
        "error": "Neither HTTP nor HTTPS responded successfully.",
    }
