"""
PDF report builder using ReportLab (Member 2, later stage).

Planned API:

    generate_pdf_report(analysis: dict, output_path: str | None = None) -> bytes

Returns PDF bytes for Flask ``send_file`` when ``output_path`` is None.
"""

from __future__ import annotations


def generate_pdf_report(analysis: dict, output_path: str | None = None) -> bytes:
    """Build a downloadable PDF from a stored or live analysis result."""
    raise NotImplementedError("PDF reporting will be implemented in a later stage.")
