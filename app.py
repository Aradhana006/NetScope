"""
NetScope Flask application entry point.

Member 1: DNS, IP, dashboard. Member 2: connectivity, TCP, HTTP, diagnosis, history, PDF.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Callable

from flask import Flask, jsonify, render_template, request, send_file

from database.history import get_analysis, init_db, list_analyses, save_analysis
from diagnostics.connectivity import analyze_connectivity
from diagnostics.diagnosis import build_diagnosis
from diagnostics.dns_check import analyze_dns
from diagnostics.dns_transport import compare_dns_udp_tcp
from diagnostics.http_check import analyze_http
from diagnostics.ip_analysis import analyze_ip
from diagnostics.tcp_check import analyze_tcp
from reports.pdf_report import generate_pdf_report
from validators import validate_target


def _run_diagnostic(run: Callable[..., dict], *args, **kwargs) -> dict:
    try:
        return run(*args, **kwargs)
    except NotImplementedError:
        return {"status": "skipped", "error": "Module not implemented yet."}
    except Exception:
        return {"status": "error", "error": "Diagnostic module failed unexpectedly."}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.setdefault("DATABASE_PATH", os.path.join("instance", "netscope.db"))

    @app.before_request
    def _ensure_db():
        if not app.config.get("_DB_READY"):
            init_db(app.config["DATABASE_PATH"])
            app.config["_DB_READY"] = True

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(
            {"status": "ok", "service": "NetScope", "message": "Backend is running."}
        )

    @app.get("/api/history")
    def history():
        limit = request.args.get("limit", default=20, type=int)
        rows = list_analyses(limit=limit, db_path=app.config["DATABASE_PATH"])
        return jsonify({"items": rows})

    @app.get("/api/report/<int:analysis_id>")
    def report(analysis_id: int):
        stored = get_analysis(analysis_id, app.config["DATABASE_PATH"])
        if not stored:
            return jsonify({"error": "Analysis not found."}), 404
        pdf_bytes = generate_pdf_report(stored)
        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"netscope-report-{analysis_id}.pdf",
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
        tcp_result = _run_diagnostic(analyze_tcp, target)
        http_result = _run_diagnostic(analyze_http, target)
        diagnosis = _run_diagnostic(
            build_diagnosis, target, dns_result, connectivity_result, tcp_result, http_result
        )

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

        if payload.get("save_history", True):
            analysis_id = save_analysis(response, app.config["DATABASE_PATH"])
            response["id"] = analysis_id

        return jsonify(response)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
