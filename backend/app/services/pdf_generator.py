"""
PDF report generator for Splunk Sentinel investigation reports.
Uses ReportLab to produce structured incident reports.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Color palette matching Sentinel dark theme
DARK_BG = colors.HexColor("#0f1117")
ACCENT_BLUE = colors.HexColor("#3b82f6")
SUCCESS_GREEN = colors.HexColor("#10b981")
WARNING_AMBER = colors.HexColor("#f59e0b")
DANGER_RED = colors.HexColor("#ef4444")
MUTED_GRAY = colors.HexColor("#6b7280")
WHITE = colors.white
SURFACE = colors.HexColor("#1a1f2e")

SEVERITY_COLORS = {
    "CRITICAL": DANGER_RED,
    "HIGH": WARNING_AMBER,
    "MEDIUM": ACCENT_BLUE,
    "LOW": SUCCESS_GREEN,
}

CONFIDENCE_TIER_COLORS = {
    "AUTO_EXECUTE": DANGER_RED,
    "ANALYST_REVIEW": WARNING_AMBER,
    "MONITOR": ACCENT_BLUE,
    "ESCALATE_TO_HUMAN": MUTED_GRAY,
}


def get_confidence_tier(confidence: float) -> str:
    if confidence >= 0.90:
        return "AUTO_EXECUTE"
    elif confidence >= 0.70:
        return "ANALYST_REVIEW"
    elif confidence >= 0.60:
        return "MONITOR"
    else:
        return "ESCALATE_TO_HUMAN"


def generate_pdf(state: dict) -> str:
    """
    Generate a PDF incident report from the investigation state.
    Returns the path to the generated PDF.
    """
    investigation_id = state.get("investigation_id", "unknown")
    pdf_path = REPORTS_DIR / f"{investigation_id}.pdf"

    final_report = state.get("final_report", {})
    kill_chain = state.get("kill_chain", [])
    ttp_mappings = state.get("ttp_mappings", [])
    patient_zero = state.get("patient_zero", {})
    blast_radius = state.get("blast_radius", {})
    spl_audit_log = state.get("spl_audit_log", [])
    confidence = float(
        final_report.get("investigation_confidence", 0.0)
    )
    confidence_tier = get_confidence_tier(confidence)
    severity = state.get("severity", "UNKNOWN")
    classification = state.get("attack_classification", "UNKNOWN")

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=WHITE,
        backColor=DARK_BG,
        spaceAfter=6,
        alignment=TA_LEFT,
    )
    heading_style = ParagraphStyle(
        "SentinelHeading",
        parent=styles["Heading1"],
        fontSize=12,
        textColor=ACCENT_BLUE,
        spaceBefore=12,
        spaceAfter=6,
        borderPad=4,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#d1d5db"),
        spaceAfter=4,
        leading=14,
    )
    mono_style = ParagraphStyle(
        "SentinelMono",
        parent=styles["Code"],
        fontSize=7,
        textColor=SUCCESS_GREEN,
        backColor=SURFACE,
        spaceAfter=2,
        leftIndent=8,
        borderPad=4,
    )
    muted_style = ParagraphStyle(
        "SentinelMuted",
        parent=styles["Normal"],
        fontSize=8,
        textColor=MUTED_GRAY,
        spaceAfter=2,
    )

    story = []

    # ── COVER SECTION ────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("🛡️ Splunk Sentinel", title_style))
    story.append(Paragraph(
        "Automated Incident Investigation Report", heading_style
    ))
    story.append(HRFlowable(
        width="100%", thickness=1, color=ACCENT_BLUE, spaceAfter=8
    ))

    # Meta table
    severity_color = SEVERITY_COLORS.get(severity, MUTED_GRAY)
    tier_color = CONFIDENCE_TIER_COLORS.get(confidence_tier, MUTED_GRAY)

    meta_data = [
        ["Investigation ID", investigation_id],
        ["Generated", datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )],
        ["Classification", classification],
        ["Severity", severity],
        ["Confidence", f"{round(confidence * 100)}%"],
        ["Action Tier", confidence_tier],
        ["Kill Chain Stages", str(len(kill_chain))],
        ["Patient Zero", patient_zero.get("ip_address", "Not identified")],
        ["Containment Priority", blast_radius.get(
            "containment_priority", "UNKNOWN"
        )],
    ]

    meta_table = Table(meta_data, colWidths=[50 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED_GRAY),
        ("TEXTCOLOR", (1, 0), (1, -1), WHITE),
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SURFACE, DARK_BG]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6 * mm))

    # ── EXECUTIVE SUMMARY ────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))
    exec_summary = final_report.get("executive_summary", "Not available.")
    story.append(Paragraph(exec_summary, body_style))

    attack_overview = final_report.get("attack_overview", "")
    if attack_overview:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("Attack Overview", heading_style))
        story.append(Paragraph(attack_overview, body_style))

    story.append(Spacer(1, 4 * mm))

    # ── KILL CHAIN TIMELINE ──────────────────────────────────────────
    story.append(Paragraph("Kill Chain Timeline", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    if kill_chain:
        kc_headers = [
            "Stage", "Tactic", "Technique",
            "Timestamp", "Confidence", "Asset"
        ]
        kc_data = [kc_headers]
        for stage in kill_chain:
            kc_data.append([
                stage.get("stage_name", "")[:25],
                stage.get("mitre_tactic", ""),
                stage.get("mitre_technique", ""),
                stage.get("timestamp", "")[:16],
                stage.get("confidence", ""),
                str(stage.get("affected_assets", [""]))[0:30],
            ])

        kc_table = Table(
            kc_data,
            colWidths=[35*mm, 20*mm, 22*mm, 32*mm, 22*mm, 35*mm]
        )
        kc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SURFACE, DARK_BG]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        story.append(kc_table)
    else:
        story.append(Paragraph("No kill chain stages identified.", muted_style))

    story.append(Spacer(1, 4 * mm))

    # ── KEY FINDINGS ─────────────────────────────────────────────────
    story.append(Paragraph("Key Findings", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    key_findings = final_report.get("key_findings", [])
    for i, finding in enumerate(key_findings, 1):
        conf = finding.get("confidence", 0)
        conf_pct = f"{round(conf * 100)}%"
        story.append(Paragraph(
            f"<b>{i}. {finding.get('finding', '')}</b>",
            body_style
        ))
        story.append(Paragraph(
            f"Evidence: {finding.get('evidence', '')}",
            muted_style
        ))
        story.append(Paragraph(
            f"Confidence: {conf_pct} | Source: "
            f"{finding.get('source', '')}",
            muted_style
        ))
        story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 4 * mm))

    # ── RECOMMENDED ACTIONS ──────────────────────────────────────────
    story.append(Paragraph("Recommended Actions", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    recommended_actions = final_report.get("recommended_actions", [])
    priority_colors = {
        "IMMEDIATE": DANGER_RED,
        "SHORT_TERM": WARNING_AMBER,
        "LONG_TERM": SUCCESS_GREEN,
    }

    if recommended_actions:
        act_data = [["Priority", "Action", "MITRE Technique"]]
        for action in recommended_actions:
            act_data.append([
                action.get("priority", ""),
                action.get("action", "")[:80],
                action.get("mitre_technique", ""),
            ])

        act_table = Table(
            act_data, colWidths=[30*mm, 100*mm, 40*mm]
        )
        act_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SURFACE, DARK_BG]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        story.append(act_table)

    story.append(Spacer(1, 4 * mm))

    # ── MITRE ATT&CK TABLE ───────────────────────────────────────────
    story.append(Paragraph("MITRE ATT&CK Techniques", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    if ttp_mappings:
        ttp_data = [["Technique ID", "Name", "Tactic", "Confidence"]]
        seen_ids = set()
        for ttp in ttp_mappings:
            tid = ttp.get("technique_id", "")
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            ttp_data.append([
                tid,
                ttp.get("technique_name", "")[:40],
                ttp.get("stage_name", ""),
                f"{round(ttp.get('confidence', 0) * 100)}%",
            ])

        ttp_table = Table(
            ttp_data, colWidths=[25*mm, 80*mm, 45*mm, 20*mm]
        )
        ttp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TEXTCOLOR", (0, 0), (0, -1), ACCENT_BLUE),
            ("TEXTCOLOR", (1, 1), (-1, -1), colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SURFACE, DARK_BG]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]))
        story.append(ttp_table)
    else:
        story.append(Paragraph("No MITRE techniques mapped.", muted_style))

    story.append(Spacer(1, 4 * mm))

    # ── PATIENT ZERO & BLAST RADIUS ──────────────────────────────────
    story.append(Paragraph("Patient Zero & Blast Radius", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    pz_data = [
        ["Patient Zero IP", patient_zero.get("ip_address", "Unknown")],
        ["First Seen", patient_zero.get("first_seen", "Unknown")],
        ["Role", patient_zero.get("role", "Unknown")],
        ["Evidence", str(patient_zero.get("evidence", ""))[:80]],
        ["Confidence", str(patient_zero.get("confidence", ""))],
        ["Affected IPs", str(
            blast_radius.get("total_affected_ips", 0)
        )],
        ["Data at Risk", str(
            blast_radius.get("data_at_risk", "Unknown")
        )[:80]],
        ["Containment", blast_radius.get("containment_priority", "")],
    ]

    pz_table = Table(pz_data, colWidths=[45*mm, 125*mm])
    pz_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED_GRAY),
        ("TEXTCOLOR", (1, 0), (1, -1), WHITE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SURFACE, DARK_BG]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#374151")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(pz_table)
    story.append(Spacer(1, 4 * mm))

    # ── SPL AUDIT LOG (last 5) ───────────────────────────────────────
    story.append(Paragraph("SPL Audit Log (Last 5 Queries)", heading_style))
    story.append(HRFlowable(
        width="100%", thickness=0.5,
        color=colors.HexColor("#374151"), spaceAfter=4
    ))

    import json as _json
    for entry in spl_audit_log[-5:]:
        try:
            parsed = _json.loads(entry) if isinstance(entry, str) else entry
            spl_text = parsed.get("spl", str(entry))[:120]
            was_corrected = parsed.get("was_corrected", False)
            rows = parsed.get("rows_returned", "?")
            prefix = "✓" if not was_corrected else "⟳ corrected"
            story.append(Paragraph(
                f"{prefix} | rows={rows} | {spl_text}",
                mono_style
            ))
        except Exception:
            story.append(Paragraph(str(entry)[:120], mono_style))

    story.append(Spacer(1, 4 * mm))

    # ── FOOTER ───────────────────────────────────────────────────────
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=ACCENT_BLUE, spaceAfter=4
    ))
    story.append(Paragraph(
        f"Generated by Splunk Sentinel — Autonomous SOC Investigation "
        f"Platform | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        muted_style
    ))
    story.append(Paragraph(
        "github.com/Asembris/splunk-sentinel",
        muted_style
    ))

    doc.build(story)
    logger.info("[PDF] Report generated | path=%s", pdf_path)
    return str(pdf_path)
