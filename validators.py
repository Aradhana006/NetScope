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


def validate_target(raw: str) -> tuple[bool, str | None, str | None]:
    """
    Validate a domain name or IP address.

    Returns:
        (True, normalized_target, None) on success.
        (False, None, error_message) on failure.
    """
    target = normalize_target(raw)

    if not target:
        return False, None, "Target is required."

    if len(target) > MAX_TARGET_LENGTH:
        return False, None, f"Target must be at most {MAX_TARGET_LENGTH} characters."

    if is_ip_address(target):
        return True, target, None

    if _HOSTNAME_RE.match(target):
        return True, target.lower().rstrip("."), None

    return False, None, "Enter a valid domain name (e.g. example.com) or IP address."
