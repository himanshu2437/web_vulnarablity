import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

SEVERITY_COLORS = {
    "high": colors.HexColor("#D32F2F"),
    "medium": colors.HexColor("#F57C00"),
    "low": colors.HexColor("#FBC02D"),
    "info": colors.HexColor("#388E3C"),
}

GRADE_COLORS = {
    "A": colors.HexColor("#2E7D32"),
    "B": colors.HexColor("#689F38"),
    "C": colors.HexColor("#F9A825"),
    "D": colors.HexColor("#EF6C00"),
    "F": colors.HexColor("#C62828"),
}


def generate_pdf_report(
    url: str, results: dict, score_summary: dict, output_dir: str = None
) -> str:
    """Create a readable PDF report and return its absolute path."""
    output_dir = output_dir or os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "reports"
    )
    os.makedirs(output_dir, exist_ok=True)

    safe_host = url.removeprefix("https://").removeprefix("http://")
    safe_host = "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in safe_host
    )
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vuln_report_{safe_host}_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=20, spaceAfter=6
    )
    section_style = ParagraphStyle(
        "SectionStyle", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8,
        textColor=colors.HexColor("#1A237E"),
    )
    body_style = styles["BodyText"]
    small_style = ParagraphStyle(
        "Small", parent=styles["BodyText"], fontSize=9, textColor=colors.grey
    )

    story = []

    story.append(Paragraph("Web Application Vulnerability Report", title_style))
    story.append(Paragraph(f"Target: {escape(url)}", body_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", small_style
    ))
    story.append(Spacer(1, 10))

    grade = score_summary["grade"]
    score = score_summary["score"]
    score_table = Table(
        [["Risk Score", "Risk Grade"], [f"{score} / 100", grade]],
        colWidths=[80 * mm, 80 * mm],
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 12),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (1, 1), (1, 1), GRADE_COLORS.get(grade, colors.grey)),
        ("TEXTCOLOR", (1, 1), (1, 1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "<i> "
        "Only scan systems you own or are authorized to test.</i>",
        small_style,
    ))

    story.append(Paragraph("1. HTTP Security Headers", section_style))
    headers = results["headers"]
    if headers.get("error"):
        story.append(Paragraph(f"Error: {escape(headers['error'])}", body_style))
    else:
        data = [["Header", "Status", "Severity"]]
        for h in headers["present"]:
            data.append([escape(h["header"]), "Present", "-"])
        for h in headers["missing"]:
            data.append([escape(h["header"]), "Missing", h["severity"].upper()])
        story.append(_make_table(data))


    story.append(Paragraph("2. SSL/TLS Certificate", section_style))
    ssl_r = results["ssl"]
    if ssl_r.get("error"):
        story.append(Paragraph(f"Error: {escape(ssl_r['error'])}", body_style))
    elif not ssl_r.get("has_ssl"):
        story.append(Paragraph("Site is not served over HTTPS.", body_style))
    else:
        data = [
            ["Protocol", ssl_r["protocol"] or "N/A"],
            ["Issuer", escape(ssl_r["issuer"] or "N/A")],
            ["Expires", f"{ssl_r['expires']} ({ssl_r['days_until_expiry']} days left)"],
        ]
        story.append(_make_table(data, header=False))
        for issue in ssl_r["issues"]:
            story.append(Paragraph(f"Warning: {escape(issue)}", body_style))


    story.append(Paragraph("3. Open Ports", section_style))
    ports = results["ports"]
    if ports.get("error"):
        story.append(Paragraph(f"Error: {escape(ports['error'])}", body_style))
    elif not ports["open"]:
        story.append(Paragraph("No common ports found open.", body_style))
    else:
        data = [["Port", "Service", "Note"]]
        for p in ports["open"]:
            data.append([str(p["port"]), escape(p["service"]), escape(p["note"])])
        story.append(_make_table(data))

    
    story.append(Paragraph("4. Exposed Sensitive Paths", section_style))
    paths = results["paths"]
    if not paths["exposed"]:
        story.append(Paragraph("No sensitive paths exposed from the checklist.", body_style))
    else:
        data = [["Path", "Severity", "Description"]]
        for p in paths["exposed"]:
            data.append(
                [escape(p["path"]), p["severity"].upper(), escape(p["description"])]
            )
        story.append(_make_table(data))

    
    story.append(PageBreak())
    story.append(Paragraph("5. Score Breakdown", section_style))
    if score_summary["deductions"]:
        for d in score_summary["deductions"]:
            story.append(Paragraph(f"- {escape(d)}", body_style))
    else:
        story.append(Paragraph("No deductions — clean scan!", body_style))

    doc.build(story)
    return filepath


def _make_table(data, header=True):
    table = Table(data, hAlign="LEFT", colWidths=None)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949AB")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    table.setStyle(TableStyle(style))
    return table
