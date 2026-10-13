"""Tests for DNS analysis module (mocked resolver)."""

from unittest.mock import MagicMock, patch

import dns.resolver

from diagnostics.dns_check import analyze_dns


def test_analyze_dns_ip_target_is_partial():
    result = analyze_dns("192.0.2.1")
    assert result["status"] == "partial"
    assert result["records"]["A"] == []
    assert result["error"] is not None


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_nxdomain(mock_resolver_cls):
    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

    result = analyze_dns("does-not-exist.example", timeout=1.0)

    assert result["status"] == "error"
    assert "NXDOMAIN" in result["error"]
    assert result["records"]["A"] == []


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_collects_a_record(mock_resolver_cls):
    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver

    a_rdata = MagicMock()
    a_rdata.to_text.return_value = "93.184.216.34"

    def resolve_side_effect(name, rtype):
        if rtype == "A":
            return [a_rdata]
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = resolve_side_effect

    result = analyze_dns("example.com", timeout=2.0)

    assert result["status"] == "success"
    assert result["records"]["A"] == ["93.184.216.34"]
    assert result["response_time_ms"] is not None
