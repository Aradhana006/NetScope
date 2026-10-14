from diagnostics.history_compare import compare_analyses


def test_compare_detects_dns_delta():
    baseline = {
        "id": 1,
        "target": "example.com",
        "timestamp": "t1",
        "dns": {"response_time_ms": 10},
        "connectivity": {"packet_loss_percent": 0},
        "http": {"https": {"response_time_ms": 100}},
        "diagnosis": {"health_score": 80},
    }
    current = {
        "id": 2,
        "target": "example.com",
        "timestamp": "t2",
        "dns": {"response_time_ms": 40},
        "connectivity": {"packet_loss_percent": 5},
        "http": {"https": {"response_time_ms": 200}},
        "diagnosis": {"health_score": 70},
    }
    result = compare_analyses(baseline, current)
    assert result["metrics"]["dns_response_time_ms"]["delta"] == 30
    assert result["summary"]
