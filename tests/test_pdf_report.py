"""Tests for PDF report generation."""

from reports.pdf_report import generate_pdf_report


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
