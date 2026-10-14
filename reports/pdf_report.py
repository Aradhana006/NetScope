"""
PDF report generation using ReportLab (Member 2).
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas


def _write_lines(pdf: canvas.Canvas, x: float, y: float, lines: list[str], line_height: float = 14) -> float:
    for line in lines:
        if y < inch:
            pdf.showPage()
            y = letter[1] - inch
        pdf.drawString(x, y, line[:120])
        y -= line_height
    return y


def generate_pdf_report(analysis: dict, output_path: str | None = None) -> bytes:
    """Build a PDF report from an analysis dictionary."""
    analysis = analysis or {}
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - inch

    pdf.setTitle("NetScope Diagnostic Report")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(inch, y, "NetScope Diagnostic Report")
    y -= 24
    pdf.setFont("Helvetica", 11)

    lines = [
        f"Target: {analysis.get('target', '—')}",
        f"Timestamp (UTC): {analysis.get('timestamp', '—')}",
    ]
    diagnosis = analysis.get("diagnosis") or {}
    lines.append(f"Health score: {diagnosis.get('health_score', '—')}")
    lines.append(f"Status: {diagnosis.get('status', '—')}")
    y = _write_lines(pdf, inch, y, lines)
    y -= 8

    dns = analysis.get("dns") or {}
    y = _write_lines(pdf, inch, y, ["", "DNS"], line_height=16)
    y = _write_lines(
        pdf,
        inch,
        y,
        [
            f"Code: {dns.get('response_code', '—')}",
            f"Lookup time: {dns.get('response_time_ms', '—')} ms",
        ],
    )
    records = dns.get("records") or {}
    for rtype, values in records.items():
        for value in values or []:
            y = _write_lines(pdf, inch + 10, y, [f"{rtype}: {value}"])

    conn = analysis.get("connectivity") or {}
    y = _write_lines(
        pdf,
        inch,
        y,
        [
            "",
            "Connectivity",
            f"Reachable: {conn.get('reachable')}",
            f"Avg RTT: {conn.get('average_rtt_ms')} ms",
            f"Packet loss: {conn.get('packet_loss_percent')}%",
        ],
    )

    tcp = analysis.get("tcp") or {}
    y = _write_lines(pdf, inch, y, ["", "TCP ports"])
    for port, info in (tcp.get("ports") or {}).items():
        if isinstance(info, dict):
            y = _write_lines(pdf, inch + 10, y, [f"{port}: {info.get('state')} ({info.get('latency_ms')} ms)"])

    http = analysis.get("http") or {}
    for scheme in ("http", "https"):
        block = http.get(scheme) or {}
        if block:
            y = _write_lines(
                pdf,
                inch + 10,
                y,
                [
                    f"{scheme.upper()}: code={block.get('status_code')} "
                    f"time={block.get('response_time_ms')} ms"
                ],
            )

    suggestions = diagnosis.get("suggestions") or []
    y = _write_lines(pdf, inch, y, ["", "Suggestions"])
    for item in suggestions:
        y = _write_lines(pdf, inch + 10, y, [f"- {item}"])

    pdf.save()
    pdf_bytes = buffer.getvalue()
    if output_path:
        with open(output_path, "wb") as handle:
            handle.write(pdf_bytes)
    return pdf_bytes
