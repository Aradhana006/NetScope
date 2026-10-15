"""
NetScope Flask application entry point.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from io import BytesIO
from typing import Callable

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for

from database.auth import authenticate, create_user, get_user
from database.history import get_analysis, init_db, list_analyses, save_analysis, user_stats
from diagnostics.connectivity import analyze_connectivity
from diagnostics.diagnosis import build_diagnosis
from diagnostics.dns_check import analyze_dns
from diagnostics.dns_transport import compare_dns_udp_tcp
from diagnostics.history_compare import compare_analyses
from diagnostics.http_check import analyze_http
from diagnostics.ip_analysis import analyze_ip
from diagnostics.tcp_check import analyze_tcp
from diagnostics.traceroute_check import analyze_traceroute
from reports.pdf_report import generate_pdf_report
from validators import validate_target


def _run_diagnostic(run: Callable[..., dict], *args, **kwargs) -> dict:
    try:
        return run(*args, **kwargs)
    except NotImplementedError:
        return {"status": "skipped", "error": "Module not implemented yet."}
    except Exception:
        return {"status": "error", "error": "Diagnostic module failed unexpectedly."}


def _current_user_id() -> int | None:
    uid = session.get("user_id")
    return int(uid) if uid is not None else None


def _load_secret_key() -> str:
    """Use NETSCOPE_SECRET_KEY when set; ignore empty env values."""
    key = (os.environ.get("NETSCOPE_SECRET_KEY") or "").strip()
    return key or secrets.token_hex(32)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.setdefault("DATABASE_PATH", os.path.join("instance", "netscope.db"))
    app.config["SECRET_KEY"] = _load_secret_key()

    @app.before_request
    def _ensure_db():
        if not app.config.get("_DB_READY"):
            init_db(app.config["DATABASE_PATH"])
            app.config["_DB_READY"] = True

    @app.get("/")
    def landing():
        if _current_user_id():
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.get("/login")
    def login_page():
        uid = _current_user_id()
        user = get_user(app.config["DATABASE_PATH"], uid) if uid else None
        return render_template("login.html", current_user=user)

    @app.get("/signup")
    def signup_page():
        if _current_user_id():
            return redirect(url_for("dashboard"))
        return render_template("signup.html")

    @app.get("/dashboard")
    def dashboard():
        user = get_user(app.config["DATABASE_PATH"], _current_user_id()) if _current_user_id() else None
        return render_template("dashboard.html", user=user, is_guest=user is None)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "NetScope"})

    @app.get("/api/auth/me")
    def auth_me():
        uid = _current_user_id()
        if not uid:
            return jsonify({"logged_in": False, "is_guest": True, "user": None})
        user = get_user(app.config["DATABASE_PATH"], uid)
        return jsonify({"logged_in": True, "is_guest": False, "user": user})

    @app.post("/api/auth/register")
    def auth_register():
        data = request.get_json(silent=True) or {}
        ok, err, user_id = create_user(
            app.config["DATABASE_PATH"],
            data.get("email", ""),
            data.get("password", ""),
            data.get("full_name", ""),
            datetime.now(timezone.utc).isoformat(),
        )
        if not ok:
            return jsonify({"error": err}), 400
        session["user_id"] = user_id
        user = get_user(app.config["DATABASE_PATH"], user_id)
        return jsonify({"user": user})

    @app.post("/api/auth/login")
    def auth_login():
        data = request.get_json(silent=True) or {}
        ok, err, user = authenticate(
            app.config["DATABASE_PATH"],
            data.get("email", ""),
            data.get("password", ""),
        )
        if not ok:
            return jsonify({"error": err}), 401
        session["user_id"] = user["id"]
        return jsonify({"user": user})

    @app.post("/api/auth/logout")
    def auth_logout():
        session.clear()
        return jsonify({"status": "ok"})

    @app.get("/api/stats")
    def stats():
        uid = _current_user_id()
        if not uid:
            return jsonify({"error": "Login required for personal stats."}), 401
        return jsonify(user_stats(app.config["DATABASE_PATH"], uid))

    @app.get("/api/history")
    def history():
        uid = _current_user_id()
        if not uid:
            return jsonify({"items": [], "requires_login": True})
        limit = request.args.get("limit", default=20, type=int)
        return jsonify({"items": list_analyses(limit=limit, db_path=app.config["DATABASE_PATH"], user_id=uid)})

    @app.get("/api/history/<int:analysis_id>")
    def history_item(analysis_id: int):
        uid = _current_user_id()
        if not uid:
            return jsonify({"error": "Login required."}), 401
        stored = get_analysis(analysis_id, app.config["DATABASE_PATH"], user_id=uid)
        if not stored:
            return jsonify({"error": "Analysis not found."}), 404
        stored["id"] = analysis_id
        return jsonify(stored)

    @app.get("/api/compare")
    def compare():
        uid = _current_user_id()
        if not uid:
            return jsonify({"error": "Login required to compare history."}), 401
        baseline_id = request.args.get("baseline_id", type=int)
        current_id = request.args.get("current_id", type=int)
        if not baseline_id or not current_id:
            return jsonify({"error": "baseline_id and current_id are required."}), 400
        baseline = get_analysis(baseline_id, app.config["DATABASE_PATH"], user_id=uid)
        current = get_analysis(current_id, app.config["DATABASE_PATH"], user_id=uid)
        if not baseline or not current:
            return jsonify({"error": "One or both analyses were not found."}), 404
        baseline["id"] = baseline_id
        current["id"] = current_id
        return jsonify(compare_analyses(baseline, current))

    @app.get("/api/report/<int:analysis_id>")
    def report(analysis_id: int):
        uid = _current_user_id()
        if not uid:
            return jsonify({"error": "Login required."}), 401
        stored = get_analysis(analysis_id, app.config["DATABASE_PATH"], user_id=uid)
        if not stored:
            return jsonify({"error": "Analysis not found."}), 404
        stored["id"] = analysis_id
        pdf_bytes = generate_pdf_report(stored)
        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"netscope-report-{analysis_id}.pdf",
        )

    @app.post("/api/report/export")
    def report_export():
        """Allow guests to export the current analysis as PDF without saving."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid payload."}), 400
        pdf_bytes = generate_pdf_report(data)
        safe_target = "".join(c for c in str(data.get("target", "netscope")) if c.isalnum() or c in ".-_") or "netscope"
        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"netscope-report-{safe_target}.pdf",
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

        if payload.get("include_dns_transport", True):
            response["dns_transport"] = _run_diagnostic(compare_dns_udp_tcp, target)
        if payload.get("include_traceroute", False):
            response["traceroute"] = _run_diagnostic(analyze_traceroute, target)

        uid = _current_user_id()
        wants_save = payload.get("save_history", True)
        response["saved"] = False
        response["requires_login_to_save"] = False

        if wants_save and uid:
            response["id"] = save_analysis(response, app.config["DATABASE_PATH"], user_id=uid)
            response["saved"] = True
        elif wants_save and not uid:
            response["requires_login_to_save"] = True

        return jsonify(response)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
