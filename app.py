"""
NetScope Flask application entry point.

Responsibilities:
- Serve the dashboard (GET /).
- Expose JSON API endpoints for analysis, history, and reports.
- Validate input and orchestrate calls into diagnostics/, database/, and reports/.

Diagnostic logic belongs in diagnostics/ — not in this file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from flask import Flask, jsonify, render_template, request

from diagnostics.dns_check import analyze_dns
from validators import validate_target


def _run_diagnostic(run: Callable[..., dict], *args, **kwargs) -> dict:
    """Call a diagnostic function; never let one module crash the whole analysis."""
    try:
        return run(*args, **kwargs)
    except NotImplementedError:
        return {
            "status": "skipped",
            "error": "This diagnostic module is not implemented yet.",
        }
    except Exception:
        return {
            "status": "error",
            "error": "This diagnostic module failed unexpectedly.",
        }


def _skipped_module(name: str) -> dict:
    return {
        "status": "skipped",
        "error": f"{name} will be added by Member 2.",
    }


def create_app() -> Flask:
    """Application factory for NetScope (used by tests and `flask run`)."""
    app = Flask(__name__)

    @app.get("/")
    def dashboard():
        """Serve the main diagnostic dashboard."""
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        """Lightweight health check for local development and automated tests."""
        return jsonify(
            {
                "status": "ok",
                "service": "NetScope",
                "message": "Backend is running.",
            }
        )

    @app.post("/api/analyze")
    def analyze():
        """
        Run diagnostics for a target hostname or IP.

        Member 1: DNS (implemented). Other modules return skipped until Member 2 integrates.
        """
        if not request.is_json:
            return jsonify({"error": "Request body must be JSON."}), 400

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Invalid JSON payload."}), 400

        ok, target, err = validate_target(payload.get("target", ""))
        if not ok:
            return jsonify({"error": err}), 400

        dns_result = _run_diagnostic(analyze_dns, target)

        # Member 2 modules — import when ready; skipped placeholders keep API shape stable.
        connectivity_result = _skipped_module("Connectivity (ping)")
        tcp_result = {
            "status": "skipped",
            "ports": {},
            "error": "TCP port checks will be added by Member 2.",
        }
        http_result = {
            "status": "skipped",
            "http": {},
            "https": {},
            "error": "HTTP/HTTPS checks will be added by Member 2.",
        }

        response = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns": dns_result,
            "connectivity": connectivity_result,
            "tcp": tcp_result,
            "http": http_result,
            "diagnosis": {
                "health_score": None,
                "status": "Pending",
                "suggestions": [
                    "DNS results are available; connectivity, TCP, and HTTP modules "
                    "will refine the health score when Member 2 completes them.",
                ],
            },
        }
        return jsonify(response)

    return app


app = create_app()

if __name__ == "__main__":
    # Local development only — do not expose as a public scanning service.
    app.run(debug=True, host="127.0.0.1", port=5000)
