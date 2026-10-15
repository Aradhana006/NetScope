"""
Input validation for user-supplied analysis targets.

Used by Flask routes before any subprocess or network diagnostic runs.
"""

from __future__ import annotations

import ipaddress
import re

MAX_TARGET_LENGTH = 253

# Hostname labels: practical check for FQDNs used in DNS (not full IDNA/punycode parser).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def normalize_target(raw: str) -> str:
    """Strip surrounding whitespace from user input."""
    return (raw or "").strip()


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


from urllib.parse import urlsplit


def validate_target(raw: str) -> tuple[bool, str | None, str | None]:
    """
    Validate a domain name or IP address.
    Also safely extracts hostnames from URL inputs (e.g. https://example.com/path).

    Returns:
        (True, normalized_target, None) on success.
        (False, None, error_message) on failure.
    """
    target = normalize_target(raw)

    if not target:
        return False, None, "Target is required."

    if len(target) > MAX_TARGET_LENGTH:
        return False, None, f"Target must be at most {MAX_TARGET_LENGTH} characters."

    # If user provided a URL scheme or path, safely extract the hostname
    if "://" in target or target.startswith("//"):
        try:
            parsed = urlsplit(target)
            if parsed.hostname:
                target = parsed.hostname
            else:
                return False, None, "Enter a valid domain name (e.g. example.com) or IP address."
        except Exception:
            return False, None, "Enter a valid domain name (e.g. example.com) or IP address."

    # If target has trailing slash or path (e.g. example.com/), strip trailing slashes
    if "/" in target:
        parts = target.split("/", 1)
        target = parts[0]

    # Bracketed IPv6 (e.g. [2001:db8::1])
    if target.startswith("[") and target.endswith("]"):
        target = target[1:-1]

    if is_ip_address(target):
        return True, target, None

    if _HOSTNAME_RE.match(target):
        return True, target.lower().rstrip("."), None

    return False, None, "Enter a valid domain name (e.g. example.com) or IP address."
