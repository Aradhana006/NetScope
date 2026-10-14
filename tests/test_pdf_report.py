"""Tests for PDF report generation."""

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Table

from reports.pdf_report import _append_ip_analysis, _append_traceroute, generate_pdf_report


def test_generate_pdf_bytes():
    analysis = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {
            "health_score": 80,
            "status": "Healthy",
            "suggestions": ["DNS resolution succeeded."],
        },
        "dns": {"response_code": "NOERROR", "response_time_ms": 12, "records": {"A": ["1.1.1.1"]}},
        "connectivity": {"reachable": True, "average_rtt_ms": 10, "packet_loss_percent": 0},
        "tcp": {"ports": {"443": {"state": "open", "latency_ms": 5}}},
        "http": {"https": {"status_code": 200, "response_time_ms": 100}},
    }
    pdf = generate_pdf_report(analysis)
    assert pdf.startswith(b"%PDF")


def test_pdf_includes_ip_analysis_and_traceroute():
    analysis = {
        "target": "example.com",
        "timestamp": "2026-10-14T12:00:00+00:00",
        "diagnosis": {"health_score": 90, "status": "Healthy", "insights": []},
        "dns": {"records": {"A": ["93.184.216.34"]}},
        "ip_analysis": {
            "status": "success",
            "input_type": "hostname",
            "address_family": "IPv4",
            "ipv4_available": True,
            "ipv6_available": False,
            "ipv4_addresses": ["93.184.216.34", "93.184.216.35"],
            "ipv6_addresses": [],
        },
        "traceroute": {
            "status": "success",
            "hops": [
                {"hop": 1, "address": "192.168.1.1", "avg_rtt_ms": 2.1},
                {"hop": 2, "address": "10.0.0.1", "avg_rtt_ms": 8.4},
            ],
        },
    }
    minimal = generate_pdf_report(
        {
            "target": "example.com",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "diagnosis": {"health_score": 90, "status": "Healthy"},
            "dns": {"records": {}},
        }
    )
    full = generate_pdf_report(analysis)
    assert full.startswith(b"%PDF")
    assert len(full) > len(minimal) + 400

    styles = getSampleStyleSheet()
    ip_story: list = []
    _append_ip_analysis(
        ip_story,
        styles,
        {
            "ip_analysis": {
                "status": "success",
                "input_type": "hostname",
                "address_family": "IPv4",
                "ipv4_available": True,
                "ipv6_available": False,
                "ipv4_addresses": ["93.184.216.34", "93.184.216.35"],
                "ipv6_addresses": [],
            }
        },
    )
    ip_tables = [x for x in ip_story if isinstance(x, Table)]
    assert ip_tables
    assert "93.184.216.35" in str(ip_tables[-1]._cellvalues)

    tr_story: list = []
    _append_traceroute(
        tr_story,
        styles,
        {
            "traceroute": {
                "hops": [{"hop": 1, "address": "192.168.1.1", "avg_rtt_ms": 2.1}],
            }
        },
    )
    tr_tables = [x for x in tr_story if isinstance(x, Table)]
    assert tr_tables
    assert "192.168.1.1" in str(tr_tables[0]._cellvalues)
