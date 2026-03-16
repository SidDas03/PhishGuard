"""
PDF Report Generator — Professional scan report using reportlab
"""
import os, json, re
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, KeepTogether)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Colour palette
C_BG      = colors.HexColor("#0e1520")
C_PANEL   = colors.HexColor("#111820")
C_ACCENT  = colors.HexColor("#00e5ff")
C_RED     = colors.HexColor("#ff2d55")
C_ORANGE  = colors.HexColor("#ff8c00")
C_YELLOW  = colors.HexColor("#ffd60a")
C_GREEN   = colors.HexColor("#00c853")
C_WHITE   = colors.HexColor("#ffffff")
C_LIGHT   = colors.HexColor("#c8d8e8")
C_MUTED   = colors.HexColor("#6a8aaa")
C_DARK    = colors.HexColor("#1a2535")

def risk_color(score):
    if score >= 85: return C_RED
    if score >= 65: return C_ORANGE
    if score >= 45: return C_YELLOW
    if score >= 25: return C_ACCENT
    return C_GREEN

def risk_label(score):
    if score >= 85: return "CONFIRMED PHISHING"
    if score >= 65: return "LIKELY PHISHING"
    if score >= 45: return "SUSPICIOUS"
    if score >= 25: return "POTENTIALLY UNSAFE"
    return "LIKELY SAFE"


def generate_report(scan: dict) -> str:
    """Generate PDF report and return file path."""
    scan_id  = scan.get("scan_id", "UNKNOWN")
    out_path = os.path.join(REPORTS_DIR, f"PhishGuard_{scan_id}.pdf")

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"PhishGuard Report — {scan_id}",
        author="PhishGuard v5",
        subject="Phishing Detection Report",
    )

    styles = getSampleStyleSheet()
    W = A4[0] - 36*mm   # usable width

    def style(name, **kw):
        base = styles[name]
        s = ParagraphStyle(name+str(id(kw)), parent=base)
        for k, v in kw.items():
            setattr(s, k, v)
        return s

    story = []

    # ── Header ──────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph('<font color="#00e5ff"><b>PhishGuard</b></font> '
                  '<font color="#6a8aaa">v5 — Threat Intelligence Report</font>',
                  style("Normal", fontSize=14, textColor=C_WHITE)),
        Paragraph(f'<font color="#6a8aaa">Scan ID: <b>{scan_id}</b><br/>'
                  f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</font>',
                  style("Normal", fontSize=8, textColor=C_MUTED, alignment=TA_RIGHT)),
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.65, W*0.35])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PANEL),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING",  (0,0), (-1,-1), 12),
        ("RIGHTPADDING", (0,0), (-1,-1), 12),
        ("LINEBELOW",    (0,0), (-1,-1), 1, C_ACCENT),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 6*mm))

    # ── URL & Score ──────────────────────────────────────────────────────────
    score   = scan.get("risk_score", 0)
    rc      = risk_color(score)
    rl      = risk_label(score)
    url     = scan.get("url", "—")
    rec     = scan.get("recommendation", "")
    # strip emoji from recommendation for PDF
    rec_clean = re.sub(r'[^\x00-\x7F]+', '', rec).strip()

    score_data = [[
        Paragraph(f'<font color="{rc.hexval()}"><b>{score}</b></font>',
                  style("Normal", fontSize=42, textColor=rc, alignment=TA_CENTER)),
        [
            Paragraph(f'<font color="{rc.hexval()}"><b>{rl}</b></font>',
                      style("Normal", fontSize=16, textColor=rc)),
            Spacer(1, 3*mm),
            Paragraph(f'<font color="#c8d8e8">{rec_clean}</font>',
                      style("Normal", fontSize=9, textColor=C_LIGHT)),
            Spacer(1, 3*mm),
            Paragraph(f'<font color="#6a8aaa">Confidence: <b>{scan.get("confidence","—")}%</b>'
                      f'   |   Duration: <b>{scan.get("scan_duration_ms","—")}ms</b></font>',
                      style("Normal", fontSize=8, textColor=C_MUTED)),
        ]
    ]]
    score_tbl = Table(score_data, colWidths=[28*mm, W-28*mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PANEL),
        ("BOX",          (0,0), (-1,-1), 1, C_DARK),
        ("LINEAFTER",    (0,0), (0,-1),  1, C_DARK),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (0,-1),  8),
        ("RIGHTPADDING", (0,0), (0,-1),  8),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING",  (1,0), (1,-1),  12),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 3*mm))

    # URL box
    url_tbl = Table([[
        Paragraph(f'<font color="#6a8aaa">TARGET URL: </font>'
                  f'<font color="#c8d8e8"><b>{url[:120]}{"..." if len(url)>120 else ""}</b></font>',
                  style("Normal", fontSize=8, textColor=C_LIGHT))
    ]], colWidths=[W])
    url_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_DARK),
        ("TOPPADDING",   (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ("LEFTPADDING",  (0,0),(-1,-1), 10),
        ("BOX",          (0,0),(-1,-1), 1, C_PANEL),
    ]))
    story.append(url_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Module Scores ────────────────────────────────────────────────────────
    story.append(Paragraph('<font color="#6a8aaa"><b>MODULE SCORES</b></font>',
                           style("Normal", fontSize=8, textColor=C_MUTED)))
    story.append(Spacer(1, 2*mm))

    checks = scan.get("checks", {})
    mod_map = [
        ("url_analysis",        "URL Analysis"),
        ("domain_intelligence", "Domain Intelligence"),
        ("ssl_inspection",      "SSL Inspection"),
        ("ml_detection",        "ML Detection"),
        ("content_analysis",    "Content Analysis"),
        ("threat_intelligence", "Threat Intelligence"),
    ]
    mod_rows = []
    for key, label in mod_map:
        s = checks.get(key, {}).get("score", 0)
        if isinstance(s, float): s = round(s, 1)
        col = risk_color(s)
        bar_w = int((s / 100) * 80)
        bar   = "█" * (bar_w // 5) + "░" * (16 - bar_w // 5)
        mod_rows.append([
            Paragraph(f'<font color="#c8d8e8">{label}</font>',
                      style("Normal", fontSize=8)),
            Paragraph(f'<font color="{col.hexval()}">{bar}</font>',
                      style("Normal", fontSize=6, fontName="Courier")),
            Paragraph(f'<font color="{col.hexval()}"><b>{s}</b></font>',
                      style("Normal", fontSize=9, alignment=TA_RIGHT)),
        ])

    mod_tbl = Table(mod_rows, colWidths=[45*mm, W-70*mm, 20*mm])
    mod_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PANEL),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_PANEL, C_DARK]),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("BOX",          (0,0), (-1,-1), 1, C_DARK),
    ]))
    story.append(mod_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Indicators ───────────────────────────────────────────────────────────
    indicators = scan.get("indicators", [])
    if indicators:
        story.append(Paragraph(
            f'<font color="#6a8aaa"><b>DETECTION INDICATORS ({len(indicators)} TRIGGERS)</b></font>',
            style("Normal", fontSize=8, textColor=C_MUTED)))
        story.append(Spacer(1, 2*mm))

        ind_rows = [
            [Paragraph('<b><font color="#6a8aaa">SEV</font></b>',
                       style("Normal", fontSize=7, alignment=TA_CENTER)),
             Paragraph('<b><font color="#6a8aaa">CHECK</font></b>',
                       style("Normal", fontSize=7)),
             Paragraph('<b><font color="#6a8aaa">DETAIL</font></b>',
                       style("Normal", fontSize=7)),
             Paragraph('<b><font color="#6a8aaa">SOURCE</font></b>',
                       style("Normal", fontSize=7))],
        ]
        for ind in indicators:
            sev = ind.get("severity", 0)
            sc  = risk_color(sev * 2.5)
            ind_rows.append([
                Paragraph(f'<font color="{sc.hexval()}"><b>{sev}</b></font>',
                          style("Normal", fontSize=8, alignment=TA_CENTER)),
                Paragraph(f'<font color="#c8d8e8">{ind.get("check","")[:50]}</font>',
                          style("Normal", fontSize=7)),
                Paragraph(f'<font color="#6a8aaa">{ind.get("detail","")[:80]}</font>',
                          style("Normal", fontSize=7)),
                Paragraph(f'<font color="#3a5070">{ind.get("source","")}</font>',
                          style("Normal", fontSize=6)),
            ])

        ind_tbl = Table(ind_rows, colWidths=[12*mm, 45*mm, W-80*mm, 20*mm])
        ind_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0,0), (-1, 0),  C_BG),
            ("ROWBACKGROUNDS",(0,1), (-1,-1),  [C_PANEL, C_DARK]),
            ("TOPPADDING",    (0,0), (-1,-1),  5),
            ("BOTTOMPADDING", (0,0), (-1,-1),  5),
            ("LEFTPADDING",   (0,0), (-1,-1),  6),
            ("RIGHTPADDING",  (0,0), (-1,-1),  6),
            ("BOX",           (0,0), (-1,-1),  1, C_DARK),
            ("LINEBELOW",     (0,0), (-1, 0),  1, C_BG),
            ("ALIGN",         (0,0), (0,-1),   "CENTER"),
        ]))
        story.append(ind_tbl)
        story.append(Spacer(1, 5*mm))

    # ── ML Details ───────────────────────────────────────────────────────────
    ml = checks.get("ml_detection", {})
    if ml.get("phishing_probability") is not None:
        story.append(Paragraph('<font color="#6a8aaa"><b>ML DETECTION DETAILS</b></font>',
                               style("Normal", fontSize=8, textColor=C_MUTED)))
        story.append(Spacer(1, 2*mm))

        ml_rows = [
            ["Random Forest",     f'{ml.get("rf_probability",0)*100:.1f}%'],
            ["Gradient Boosting", f'{ml.get("gb_probability",0)*100:.1f}%'],
            ["Ensemble Result",   f'{ml.get("phishing_probability",0)*100:.1f}%'],
            ["Classification",    ml.get("classification","—")],
        ]
        ml_data = [[
            Paragraph(f'<font color="#6a8aaa">{r[0]}</font>', style("Normal", fontSize=8)),
            Paragraph(f'<font color="#c8d8e8"><b>{r[1]}</b></font>',
                      style("Normal", fontSize=8, alignment=TA_RIGHT)),
        ] for r in ml_rows]

        ml_tbl = Table(ml_data, colWidths=[60*mm, W-60*mm])
        ml_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_PANEL),
            ("ROWBACKGROUNDS",(0,0), (-1,-1), [C_PANEL, C_DARK]),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("BOX",           (0,0), (-1,-1), 1, C_DARK),
        ]))
        story.append(ml_tbl)
        story.append(Spacer(1, 5*mm))

    # ── Footer ───────────────────────────────────────────────────────────────
    story.append(HRFlowable(width=W, color=C_DARK))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        '<font color="#3a5070">Generated by PhishGuard v5 — Intelligent Phishing Detection Platform. '
        'This report is for informational purposes only.</font>',
        style("Normal", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER)))

    doc.build(story)
    return out_path
