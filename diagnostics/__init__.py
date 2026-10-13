"""
Independent network diagnostic modules.

Each module returns structured JSON-compatible dicts with consistent keys:
- ``status``: ``"success"`` | ``"error"`` | ``"partial"`` | ``"skipped"``
- ``error``: optional human-readable message when status is not success

Member 1: dns_check (initial implementation).
Member 2: connectivity, tcp_check, http_check, diagnosis; traceroute optional later.
"""
