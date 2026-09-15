import re
from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = HexColor("#1c1914")
MUTED = HexColor("#5c564c")
RULE = HexColor("#c9c1b2")
PASS = HexColor("#1f5c3a")
FAIL = HexColor("#8b1e1e")
ERROR = HexColor("#6b5420")
WASH = HexColor("#efe8d8")

STATUS_COLOUR = {"pass": PASS, "fail": FAIL, "error": ERROR}


def pdf_filename(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path or "scan"
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", host).strip("-") or "scan"
    return f"fapi-scan-{safe}.pdf"


def render_scan_pdf(report: dict) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"FAPI Lens scan of {report.get('target', '')}",
        author="FAPI Lens",
    )
    styles = _styles()
    story = [_header(report, styles), Spacer(1, 8), _summary(report, styles), Spacer(1, 10)]
    story.extend(_findings(report, styles))
    document.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return buffer.getvalue()


def _page_chrome(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(18 * mm, A4[1] - 12 * mm, A4[0] - 18 * mm, A4[1] - 12 * mm)
    canvas.line(18 * mm, 12 * mm, A4[0] - 18 * mm, 12 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Times-Roman", 8)
    canvas.drawString(18 * mm, A4[1] - 10 * mm, "FAPI LENS")
    canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 10 * mm, "FAPI 2.0")
    canvas.drawString(18 * mm, 8 * mm, "Authorisation-server scan report")
    canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, str(doc.page))
    canvas.restoreState()


def _styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle(
            "title",
            fontName="Times-Bold",
            fontSize=16,
            leading=20,
            textColor=INK,
            spaceAfter=4,
        ),
        "lead": ParagraphStyle(
            "lead",
            fontName="Times-Italic",
            fontSize=12,
            leading=16,
            textColor=INK,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Times-Roman",
            fontSize=9.5,
            leading=13,
            textColor=INK,
            alignment=TA_JUSTIFY,
        ),
        "muted": ParagraphStyle(
            "muted",
            fontName="Times-Roman",
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Times-Bold",
            fontSize=8,
            leading=11,
            textColor=MUTED,
        ),
        "heading": ParagraphStyle(
            "heading",
            fontName="Times-Bold",
            fontSize=12,
            leading=16,
            textColor=INK,
            spaceBefore=4,
            spaceAfter=4,
        ),
        "check": ParagraphStyle(
            "check",
            fontName="Times-Bold",
            fontSize=11,
            leading=14,
            textColor=INK,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=MUTED,
        ),
        "right": ParagraphStyle(
            "right",
            fontName="Times-Roman",
            fontSize=8.5,
            leading=11,
            textColor=MUTED,
            alignment=TA_RIGHT,
        ),
        "cell": ParagraphStyle(
            "cell",
            fontName="Times-Roman",
            fontSize=8.5,
            leading=11,
            textColor=INK,
            alignment=TA_LEFT,
        ),
        "cell_head": ParagraphStyle(
            "cell_head",
            fontName="Times-Bold",
            fontSize=8,
            leading=10,
            textColor=INK,
        ),
    }


def _header(report: dict, styles: dict[str, ParagraphStyle]):
    summary = report.get("summary") or {}
    verdict = _verdict(summary)
    data = [
        [Paragraph("Authorisation-server scan", styles["title"])],
        [Paragraph(_xml(verdict), styles["lead"])],
        [
            Paragraph(
                f"Target: {_xml(report.get('target', ''))}<br/>"
                f"Metadata: {_xml(report.get('metadata_url', ''))}<br/>"
                f"Started: {_xml(report.get('started_at', ''))}<br/>"
                f"Finished: {_xml(report.get('finished_at', ''))} · "
                f"{int(report.get('duration_ms') or 0)} ms",
                styles["muted"],
            )
        ],
    ]
    table = Table(data, colWidths=[174 * mm])
    table.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _summary(report: dict, styles: dict[str, ParagraphStyle]):
    summary = report.get("summary") or {}
    rows = [
        [
            Paragraph("Pass", styles["cell_head"]),
            Paragraph("Fail", styles["cell_head"]),
            Paragraph("Error", styles["cell_head"]),
            Paragraph("Total", styles["cell_head"]),
        ],
        [
            Paragraph(str(summary.get("pass", 0)), styles["cell"]),
            Paragraph(str(summary.get("fail", 0)), styles["cell"]),
            Paragraph(str(summary.get("error", 0)), styles["cell"]),
            Paragraph(str(summary.get("total", 0)), styles["cell"]),
        ],
    ]
    table = Table(rows, colWidths=[43.5 * mm] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), WASH),
                ("LINEABOVE", (0, 0), (-1, 0), 0.6, INK),
                ("LINEBELOW", (0, -1), (-1, -1), 0.6, INK),
                ("LINEBELOW", (0, 0), (-1, 0), 0.3, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _findings(report: dict, styles: dict[str, ParagraphStyle]):
    titles = {
        item.get("check_id"): item.get("title")
        for item in report.get("checks") or []
        if isinstance(item, dict)
    }
    flowables = [Paragraph("Findings", styles["heading"])]
    overview_rows = [
        [
            Paragraph("#", styles["cell_head"]),
            Paragraph("Check", styles["cell_head"]),
            Paragraph("Status", styles["cell_head"]),
            Paragraph("Severity", styles["cell_head"]),
        ]
    ]
    results = [item for item in report.get("results") or [] if isinstance(item, dict)]
    for index, result in enumerate(results, start=1):
        check_id = str(result.get("check_id", ""))
        title = titles.get(check_id) or result.get("description") or check_id
        overview_rows.append(
            [
                Paragraph(str(index), styles["cell"]),
                Paragraph(_xml(f"{check_id} — {title}"), styles["cell"]),
                Paragraph(_xml(_status_label(result.get("status"))), styles["cell"]),
                Paragraph(_xml(str(result.get("severity", "")).title()), styles["cell"]),
            ]
        )
    overview = Table(overview_rows, colWidths=[12 * mm, 110 * mm, 26 * mm, 26 * mm])
    overview.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), WASH),
                ("LINEABOVE", (0, 0), (-1, 0), 0.6, INK),
                ("LINEBELOW", (0, -1), (-1, -1), 0.4, RULE),
                ("LINEBELOW", (0, 0), (-1, 0), 0.3, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    flowables.append(overview)
    flowables.append(Spacer(1, 10))
    for index, result in enumerate(results, start=1):
        flowables.append(_finding_block(index, result, titles, styles))
        flowables.append(Spacer(1, 8))
    return flowables


def _finding_block(index: int, result: dict, titles: dict, styles: dict[str, ParagraphStyle]):
    check_id = str(result.get("check_id", ""))
    title = titles.get(check_id) or result.get("description") or check_id
    status = str(result.get("status", "error"))
    heading = Paragraph(
        f"{index}. {_xml(check_id)} — {_xml(title)}  "
        f"<font color='{_hex(STATUS_COLOUR.get(status, ERROR))}'>"
        f"{_xml(_status_label(status))}</font>",
        styles["check"],
    )
    body = [
        [Paragraph("Detail", styles["label"]), Paragraph(_xml(result.get("detail", "")), styles["body"])],
        [Paragraph("Remedy", styles["label"]), Paragraph(_xml(result.get("remedy", "")), styles["body"])],
        [Paragraph("Endpoint", styles["label"]), Paragraph(_xml(result.get("endpoint", "")), styles["mono"])],
        [Paragraph("Reference", styles["label"]), Paragraph(_xml(result.get("reference", "")), styles["muted"])],
    ]
    table = Table(body, colWidths=[24 * mm, 150 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return KeepTogether([heading, Spacer(1, 3), table])


def _verdict(summary: dict) -> str:
    if int(summary.get("fail") or 0) > 0:
        return "Non-conformant"
    if int(summary.get("error") or 0) > 0:
        return "Incomplete"
    return "Conformant"


def _status_label(status) -> str:
    value = str(status or "error")
    return {"pass": "Pass", "fail": "Fail", "error": "Error"}.get(value, value.title())


def _xml(value) -> str:
    return escape(str(value or "")).replace("\n", "<br/>")


def _hex(colour: HexColor) -> str:
    return f"#{int(colour.red * 255):02x}{int(colour.green * 255):02x}{int(colour.blue * 255):02x}"
