"""
NetScope Flask application entry point.

Member 1: routes, validation, orchestration, DNS + IP integration.
Diagnostic implementations live under diagnostics/ (Member 2 modules imported when ready).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from flask import Flask, jsonify, render_template, request

from diagnostics.dns_check import analyze_dns
from diagnostics.dns_transport import compare_dns_udp_tcp
from diagnostics.ip_analysis import analyze_ip
from validators import validate_target

# Member 2 integration boundary — real implementations replace NotImplementedError.
from diagnostics.connectivity import analyze_connectivity
from diagnostics.diagnosis import build_diagnosis
from diagnostics.http_check import analyze_http
from diagnostics.tcp_check import analyze_tcp


def _run_diagnostic(run: Callable[..., dict], *args, **kwargs) -> dict:
    """Call a diagnostic function; one failure must not crash the full analysis."""
    try:
        return run(*args, **kwargs)
    except NotImplementedError:
        return {
            "status": "skipped",
            "error": "Module not implemented yet (Member 2).",
        }
    except Exception:
        return {
            "status": "error",
            "error": "Diagnostic module failed unexpectedly.",
        }


def _skipped_connectivity() -> dict:
    return {
        "status": "skipped",
        "reachable": None,
        "average_rtt_ms": None,
        "packet_loss_percent": None,
        "probes_sent": None,
        "rtt_samples_ms": None,
        "error": "Connectivity module pending.",
    }


def _skipped_tcp() -> dict:
    return {
        "status": "skipped",
        "ports": {},
        "error": "TCP module pending.",
    }


def _skipped_http() -> dict:
    return {
        "status": "skipped",
        "http": {},
        "https": {},
        "error": "HTTP module pending.",
    }


def _pending_diagnosis() -> dict:
    return {
        "health_score": None,
        "status": "Pending",
        "suggestions": [
            "DNS and IP analysis are available. Full health scoring requires Member 2 modules.",
        ],
    }


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "service": "NetScope",
                "message": "Backend is running.",
            }
        )

    @app.post("/api/analyze")
    def analyze():
        if not request.is_json:
            return jsonify({"error": "Request body must be JSON."}), 400

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON payload."}), 400

        raw_target = payload.get("target", "")
        if raw_target is None or (isinstance(raw_target, str) and not raw_target.strip()):
            return jsonify({"error": "Target is required."}), 400

        ok, target, err = validate_target(raw_target)
        if not ok:
            return jsonify({"error": err}), 400

        dns_result = _run_diagnostic(analyze_dns, target)
        ip_result = _run_diagnostic(analyze_ip, target, dns_result)

        connectivity_result = _run_diagnostic(analyze_connectivity, target)
        if connectivity_result.get("status") == "skipped":
            connectivity_result = _skipped_connectivity()

        tcp_result = _run_diagnostic(analyze_tcp, target)
        if tcp_result.get("status") == "skipped":
            tcp_result = _skipped_tcp()

        http_result = _run_diagnostic(analyze_http, target)
        if http_result.get("status") == "skipped":
            http_result = _skipped_http()

        diagnosis = _run_diagnostic(
            build_diagnosis, target, dns_result, connectivity_result, tcp_result, http_result
        )
        if diagnosis.get("status") == "skipped":
            diagnosis = _pending_diagnosis()

        response = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns": dns_result,
            "ip_analysis": ip_result,
            "connectivity": connectivity_result,
            "tcp": tcp_result,
            "http": http_result,
            "diagnosis": diagnosis,
        }

        if payload.get("include_dns_transport") is True:
            response["dns_transport"] = _run_diagnostic(compare_dns_udp_tcp, target)

        return jsonify(response)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
