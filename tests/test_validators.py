"""Tests for target validation."""

from validators import validate_target


def test_validate_accepts_simple_hostname():
    ok, target, err = validate_target("  Example.COM.  ")
    assert ok is True
    assert target == "example.com"
    assert err is None


def test_validate_accepts_ipv4():
    ok, target, err = validate_target("8.8.8.8")
    assert ok is True
    assert target == "8.8.8.8"
    assert err is None


def test_validate_rejects_empty():
    ok, target, err = validate_target("   ")
    assert ok is False
    assert target is None
    assert "required" in err.lower()


def test_validate_rejects_invalid_hostname():
    ok, _, err = validate_target("not a valid host!!")
    assert ok is False
    assert err is not None
