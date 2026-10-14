"""
PDF report generation — structured diagnostic report (ReportLab).
"""

from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _grid_table(rows: list[list[str]], col_widths: list[float]) -> Table:
    table = Table(rows, colWidths=col_widths)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0FE")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _append_ip_analysis(story: list, styles, analysis: dict) -> None:
    ip = analysis.get("ip_analysis") or {}
    if not ip or ip.get("status") == "skipped":
        return
    story.append(Paragraph("<b>IP addressing</b>", styles["Heading2"]))
    summary_rows = [
        ["Field", "Value"],
        ["Status", str(ip.get("status", "—"))],
        ["Input type", str(ip.get("input_type", "—"))],
        ["Address family", str(ip.get("address_family", "—"))],
        ["IPv4 available", "Yes" if ip.get("ipv4_available") else "No"],
        ["IPv6 available", "Yes" if ip.get("ipv6_available") else "No"],
    ]
    if ip.get("error"):
        summary_rows.append(["Note", str(ip.get("error"))])
    story.append(_grid_table(summary_rows, [1.6 * inch, 4.9 * inch]))
    story.append(Spacer(1, 0.12 * inch))

    addr_rows = [["Stack", "Address"]]
    for addr in ip.get("ipv4_addresses") or []:
        addr_rows.append(["IPv4", str(addr)])
    for addr in ip.get("ipv6_addresses") or []:
        addr_rows.append(["IPv6", str(addr)])
    if len(addr_rows) == 1:
        addr_rows.append(["—", "No addresses resolved"])
    story.append(_grid_table(addr_rows, [1 * inch, 5.5 * inch]))
    story.append(Spacer(1, 0.2 * inch))


def _append_traceroute(story: list, styles, analysis: dict) -> None:
    tr = analysis.get("traceroute") or {}
    hops = tr.get("hops") or []
    if not hops:
        return
    story.append(Paragraph("<b>Traceroute path</b>", styles["Heading2"]))
    if tr.get("error"):
        story.append(Paragraph(f"<i>{tr.get('error')}</i>", styles["Normal"]))
    hop_rows = [["Hop", "Address", "RTT (ms)"]]
    for hop in hops:
        rtt = hop.get("avg_rtt_ms")
        if rtt is None and hop.get("rtt_ms"):
            samples = hop.get("rtt_ms") or []
            rtt = ", ".join(str(x) for x in samples) if samples else "—"
        hop_rows.append([str(hop.get("hop", "—")), str(hop.get("address", "—")), str(rtt if rtt is not None else "—")])
    story.append(_grid_table(hop_rows, [0.7 * inch, 3.8 * inch, 1.5 * inch]))
    story.append(Spacer(1, 0.2 * inch))


def generate_pdf_report(analysis: dict, output_path: str | None = None) -> bytes:
    analysis = analysis or {}
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="NetScope Report")
    styles = getSampleStyleSheet()
    story = []

    target = analysis.get("target", "—")
    ts = analysis.get("timestamp", "—")
    diagnosis = analysis.get("diagnosis") or {}

    story.append(Paragraph("<b>NetScope Network Diagnostic Report</b>", styles["Title"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Timestamp (UTC):</b> {ts}", styles["Normal"]))
    story.append(
        Paragraph(
            f"<b>Health score:</b> {diagnosis.get('health_score', '—')} "
            f"(<b>Status:</b> {diagnosis.get('status', '—')})",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    findings = diagnosis.get("findings") or []
    if findings:
        finding_rows = [["Result", "Check", "Evidence", "Possible causes", "Next step"]]
        for f in findings:
            finding_rows.append(
                [
                    str(f.get("result", "—")).replace("_", " ").title(),
                    str(f.get("check", "—")),
                    str(f.get("evidence", "—")),
                    str(f.get("likely_cause", "—")),
                    str(f.get("next_step", "—")),
                ]
            )
        story.append(Paragraph("<b>Unified findings</b>", styles["Heading2"]))
        story.append(_grid_table(finding_rows, [0.95 * inch, 0.85 * inch, 1.55 * inch, 1.55 * inch, 1.55 * inch]))
        story.append(Spacer(1, 0.25 * inch))
    else:
        checks = _build_check_rows(analysis)
        table = Table([["Status", "Check", "Result"]] + checks, colWidths=[1.1 * inch, 2.2 * inch, 3.2 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0FE")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(Paragraph("<b>Summary of checks</b>", styles["Heading2"]))
        story.append(table)
        story.append(Spacer(1, 0.25 * inch))

    dns = analysis.get("dns") or {}
    story.append(Paragraph("<b>DNS records</b>", styles["Heading2"]))
    dns_rows = [["Type", "Value"]]
    for rtype, values in (dns.get("records") or {}).items():
        for val in values or []:
            dns_rows.append([rtype, val])
    if len(dns_rows) == 1:
        dns_rows.append(["—", "No records"])
    dns_table = Table(dns_rows, colWidths=[1 * inch, 5.5 * inch])
    dns_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
    story.append(dns_table)
    story.append(Spacer(1, 0.2 * inch))

    _append_ip_analysis(story, styles, analysis)
    _append_traceroute(story, styles, analysis)

    story.append(Paragraph("<b>Explainable diagnosis</b>", styles["Heading2"]))
    for item in diagnosis.get("insights") or []:
        story.append(
            Paragraph(
                f"<b>{item.get('issue')}</b><br/>"
                f"Evidence: {item.get('evidence')}<br/>"
                f"Likely cause: {item.get('likely_cause')}<br/>"
                f"Next step: {item.get('next_step')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.1 * inch))

    if not diagnosis.get("insights"):
        for s in diagnosis.get("suggestions") or []:
            story.append(Paragraph(f"• {s}", styles["Normal"]))

    transport = analysis.get("dns_transport")
    if transport:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("<b>DNS transport (UDP vs TCP)</b>", styles["Heading2"]))
        udp = transport.get("udp") or {}
        tcp = transport.get("tcp") or {}
        story.append(
            Paragraph(
                f"UDP: {udp.get('response_time_ms')} ms ({udp.get('response_code')}) · "
                f"TCP: {tcp.get('response_time_ms')} ms ({tcp.get('response_code')})",
                styles["Normal"],
            )
        )

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    if output_path:
        with open(output_path, "wb") as handle:
            handle.write(pdf_bytes)
    return pdf_bytes


def _build_check_rows(analysis: dict) -> list[list[str]]:
    rows: list[list[str]] = []
    dns = analysis.get("dns") or {}
    conn = analysis.get("connectivity") or {}
    tcp = analysis.get("tcp") or {}
    http = analysis.get("http") or {}

    rows.append(["Passed" if dns.get("status") == "success" else "Warn", "DNS lookup", dns.get("response_code", "—")])
    rows.append(
        [
            "Passed" if conn.get("reachable") else "Warn",
            "ICMP / Ping",
            f"RTT {conn.get('average_rtt_ms')} ms, loss {conn.get('packet_loss_percent')}%",
        ]
    )
    p443 = (tcp.get("ports") or {}).get("443") or {}
    rows.append(["Passed" if p443.get("state") == "open" else "Warn", "TCP 443", p443.get("state", "—")])
    https = http.get("https") or {}
    rows.append(
        [
            "Passed" if https.get("available") else "Warn",
            "HTTPS",
            str(https.get("status_code", "—")),
        ]
    )
    return rows
