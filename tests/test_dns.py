"""Tests for DNS analysis (mocked resolver — no live internet required)."""

from unittest.mock import MagicMock, patch

import dns.resolver

from diagnostics.dns_check import analyze_dns


def test_analyze_dns_invalid_target():
    result = analyze_dns("not valid!!")
    assert result["status"] == "error"
    assert result["response_code"] == "INVALID"


def test_analyze_dns_ip_literal_partial():
    result = analyze_dns("192.0.2.1")
    assert result["status"] == "partial"
    assert result["response_code"] == "N/A"
    assert result["records"]["A"] == []


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_nxdomain(mock_resolver_cls):
    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

    result = analyze_dns("missing.example", timeout=1.0)

    assert result["status"] == "error"
    assert result["response_code"] == "NXDOMAIN"
    assert "does not exist" in (result["error"] or "")


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_noanswer_for_mx(mock_resolver_cls):
    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver

    a_rdata = MagicMock()
    a_rdata.to_text.return_value = "93.184.216.34"
    a_answer = MagicMock()
    a_answer.rrset = MagicMock(ttl=300)
    a_answer.__iter__ = lambda self: iter([a_rdata])

    def resolve_side_effect(_name, rtype):
        if rtype == "A":
            return a_answer
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = resolve_side_effect

    result = analyze_dns("example.com")

    assert result["status"] == "success"
    assert result["response_code"] == "NOERROR"
    assert result["records"]["A"] == ["93.184.216.34"]
    assert result["ttls"]["A"] == 300
    assert result["errors"]["MX"] is not None


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_timeout(mock_resolver_cls):
    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver
    resolver.resolve.side_effect = dns.exception.Timeout()

    result = analyze_dns("example.com", timeout=0.1)

    assert result["status"] == "error"
    assert result["response_code"] == "TIMEOUT"


@patch("diagnostics.dns_check.dns.resolver.Resolver")
def test_analyze_dns_result_is_json_serializable(mock_resolver_cls):
    import json

    resolver = MagicMock()
    mock_resolver_cls.return_value = resolver
    resolver.resolve.side_effect = dns.resolver.NoAnswer()

    result = analyze_dns("example.com")
    json.dumps(result)
