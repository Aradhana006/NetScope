"""Tests for IPv4/IPv6 analysis."""

from diagnostics.ip_analysis import analyze_ip


def test_ipv4_literal():
    result = analyze_ip("192.0.2.1", {})
    assert result["status"] == "success"
    assert result["input_type"] == "ipv4"
    assert result["ipv4_available"] is True
    assert result["address_family"] == "IPv4"
    assert result["ipv4_addresses"] == ["192.0.2.1"]


def test_ipv6_literal():
    result = analyze_ip("2001:db8::1", {})
    assert result["input_type"] == "ipv6"
    assert result["ipv6_available"] is True
    assert result["address_family"] == "IPv6"


def test_hostname_ipv4_from_dns():
    dns = {
        "status": "success",
        "records": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
    }
    result = analyze_ip("example.com", dns)
    assert result["input_type"] == "hostname"
    assert result["ipv4_available"] is True
    assert result["ipv6_available"] is False
    assert result["ipv4_addresses"] == ["93.184.216.34"]


def test_hostname_dual_stack():
    dns = {
        "records": {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        }
    }
    result = analyze_ip("example.com", dns)
    assert result["address_family"] == "Dual-Stack"
    assert result["ipv4_available"] and result["ipv6_available"]


def test_duplicate_addresses_removed():
    dns = {"records": {"A": ["1.1.1.1", "1.1.1.1"], "AAAA": []}}
    result = analyze_ip("example.com", dns)
    assert result["ipv4_addresses"] == ["1.1.1.1"]


def test_empty_dns_partial():
    dns = {"status": "success", "records": {"A": [], "AAAA": []}}
    result = analyze_ip("example.com", dns)
    assert result["status"] == "partial"
    assert result["address_family"] == "None"


def test_invalid_target():
    result = analyze_ip("bad name!!", {})
    assert result["status"] == "error"
    assert result["input_type"] == "invalid"


def test_validate_target_urls_and_inputs():
    from validators import validate_target

    # Standard hostnames
    ok, target, err = validate_target("google.com")
    assert ok and target == "google.com" and err is None

    # URL with https and trailing slash
    ok, target, err = validate_target("https://example.com/")
    assert ok and target == "example.com" and err is None

    # URL with path and query parameters
    ok, target, err = validate_target("http://sub.domain.co.uk/path?arg=1#hash")
    assert ok and target == "sub.domain.co.uk" and err is None

    # IPv4 literal with trailing slash
    ok, target, err = validate_target("192.168.1.1/")
    assert ok and target == "192.168.1.1" and err is None

    # Bracketed IPv6 literal
    ok, target, err = validate_target("[2001:db8::1]")
    assert ok and target == "2001:db8::1" and err is None

    # Malformed / empty targets
    assert not validate_target("")[0]
    assert not validate_target("   ")[0]
    assert not validate_target("https:///")[0]
    assert not validate_target("-invalid-.com")[0]
