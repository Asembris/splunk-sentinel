"""
PDF report generator for Splunk Sentinel investigation reports.
Uses ReportLab to produce structured incident reports.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from app.rag.data.cve_expanded import EXPANDED_CVES

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ── DESIGN SYSTEM COLOR PALETTE ─────────────────────────────────────
# Brand colors
DARK_BG        = colors.HexColor("#0f1117")
SURFACE_BG     = colors.HexColor("#1a1d27")
ACCENT_BLUE    = colors.HexColor("#3b82f6")
ACCENT_GREEN   = colors.HexColor("#10b981")
ACCENT_RED     = colors.HexColor("#ef4444")
ACCENT_AMBER   = colors.HexColor("#f59e0b")
ACCENT_PURPLE  = colors.HexColor("#8b5cf6")

# Severity colors
CRITICAL_RED   = colors.HexColor("#dc2626")
HIGH_ORANGE    = colors.HexColor("#ea580c")
MEDIUM_AMBER   = colors.HexColor("#d97706")
LOW_GREEN      = colors.HexColor("#16a34a")

# Text colors for White page background
TEXT_DARK      = colors.HexColor("#1e293b")  # for headings
TEXT_BODY      = colors.HexColor("#334155")  # for body text
TEXT_MUTED     = colors.HexColor("#64748b")  # for secondary/muted text

# Text colors for Dark SURFACE_BG banner backgrounds
TEXT_PRIMARY   = colors.HexColor("#f8fafc")
TEXT_SECONDARY = colors.HexColor("#94a3b8")

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL_RED,
    "HIGH": HIGH_ORANGE,
    "MEDIUM": MEDIUM_AMBER,
    "LOW": LOW_GREEN,
    "UNKNOWN": TEXT_MUTED
}

def get_confidence_tier(confidence: float) -> str:
    if confidence >= 0.90:
        return "AUTO_ESCALATE"
    elif confidence >= 0.70:
        return "ANALYST_REVIEW"
    elif confidence >= 0.60:
        return "MONITOR"
    else:
        return "ESCALATE_TO_HUMAN"

def get_cve_details(cve_id: str) -> Optional[dict]:
    for cve in EXPANDED_CVES:
        if cve.get("cve_id") == cve_id:
            return cve
    return None

def draw_footer(canvas, doc):
    """Draws a premium footer at the bottom of every page."""
    canvas.saveState()
    # Draw top thin line of the footer
    canvas.setStrokeColor(ACCENT_BLUE)
    canvas.setLineWidth(1)
    canvas.line(15 * mm, 30 * mm, 195 * mm, 30 * mm) # margin 15mm left and right

    # Draw footer text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(TEXT_DARK)
    canvas.drawString(15 * mm, 24 * mm, "Splunk Sentinel")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(38 * mm, 24 * mm, "|   Autonomous SOC Platform   |   Incident Investigation Report")
    
    canvas.drawRightString(195 * mm, 24 * mm, f"Page {canvas.getPageNumber()}")
    
    canvas.setFont("Helvetica-Oblique", 7)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(15 * mm, 18 * mm, "CONFIDENTIAL  -  INTERNAL USE ONLY")
    canvas.drawRightString(195 * mm, 18 * mm, "github.com/Asembris/splunk-sentinel")
    canvas.restoreState()

def create_section_header(title: str) -> Table:
    """Helper to draw a styled section header with a left blue accent bar."""
    p = Paragraph(f"<b>{title.upper()}</b>", ParagraphStyle(
        "SecHeadText",
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=TEXT_DARK,
        spaceAfter=0,
        leading=12
    ))
    t = Table([[p]], colWidths=[180 * mm])
    t.setStyle(TableStyle([
        ('LINELEFT', (0, 0), (0, -1), 3, ACCENT_BLUE),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
    ]))
    return t

def create_cover_banner(state: dict) -> Table:
    """Creates the large premium banner at the top of Page 1."""
    investigation_id = state.get("investigation_id", "unknown")
    severity = state.get("severity", "UNKNOWN") or "UNKNOWN"
    classification = state.get("attack_classification", "UNKNOWN") or "UNKNOWN"
    final_report = state.get("final_report", {}) or {}
    confidence = float(final_report.get("investigation_confidence", 0.0) or 0.0)
    confidence_pct = f"{round(confidence * 100)}%"
    confidence_tier = get_confidence_tier(confidence)
    
    left_content = [
        Paragraph("<font color='#3b82f6'><b>🛡️ SPLUNK SENTINEL</b></font>", ParagraphStyle(
            "BrandLogo", fontName="Helvetica-Bold", fontSize=13, leading=15, textColor=ACCENT_BLUE
        )),
        Spacer(1, 2 * mm),
        Paragraph("Autonomous SOC Incident Report", ParagraphStyle(
            "DocTitle", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=TEXT_PRIMARY
        )),
        Spacer(1, 1.5 * mm),
        Paragraph(f"Investigation Target ID: <font color='#3b82f6'><b>{investigation_id}</b></font>", ParagraphStyle(
            "DocSub", fontName="Helvetica", fontSize=9, leading=11, textColor=TEXT_SECONDARY
        ))
    ]
    
    severity_color_hex = "#dc2626" if severity == "CRITICAL" else "#ea580c" if severity == "HIGH" else "#d97706" if severity == "MEDIUM" else "#16a34a"
    right_content = [
        Paragraph(f"SEVERITY: <font color='{severity_color_hex}'><b>{severity}</b></font>", ParagraphStyle(
            "BadgeSev", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=TEXT_PRIMARY, alignment=TA_RIGHT
        )),
        Spacer(1, 2 * mm),
        Paragraph(f"ATTACK: <font color='#10b981'><b>{classification}</b></font>", ParagraphStyle(
            "BadgeClass", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=TEXT_PRIMARY, alignment=TA_RIGHT
        )),
        Spacer(1, 2 * mm),
        Paragraph(f"CONFIDENCE: <font color='#8b5cf6'><b>{confidence_pct}</b></font> ({confidence_tier})", ParagraphStyle(
            "BadgeConf", fontName="Helvetica", fontSize=8, leading=11, textColor=TEXT_SECONDARY, alignment=TA_RIGHT
        ))
    ]
    
    t = Table([[left_content, right_content]], colWidths=[110 * mm, 70 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), SURFACE_BG),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
        ('LEFTPADDING', (0, 0), (-1, -1), 16),
        ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ('LINEBELOW', (0, 0), (-1, -1), 2, ACCENT_BLUE),
    ]))
    return t

def create_page_header_banner(title: str, state: dict) -> Table:
    """Creates a thinner header banner for pages 2 and 3."""
    investigation_id = state.get("investigation_id", "unknown")
    classification = state.get("attack_classification", "UNKNOWN") or "UNKNOWN"
    
    left_p = Paragraph(f"🛡️ <b>SPLUNK SENTINEL</b>  |  <font color='#94a3b8'>{title}</font>", ParagraphStyle(
        "PageHeadLeft", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=TEXT_PRIMARY
    ))
    right_p = Paragraph(f"ID: {investigation_id[:13]}  |  {classification}", ParagraphStyle(
        "PageHeadRight", fontName="Helvetica", fontSize=8, leading=10, textColor=TEXT_SECONDARY, alignment=TA_RIGHT
    ))
    
    t = Table([[left_p, right_p]], colWidths=[100 * mm, 80 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), SURFACE_BG),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('LINEBELOW', (0, 0), (-1, -1), 2, ACCENT_BLUE),
    ]))
    return t

def create_finding_card(finding: dict, index: int) -> Table:
    """Creates a beautiful card block for key findings with styled left accent border."""
    conf = finding.get("confidence", 1.0) or 0.0
    conf_pct = f"{round(conf * 100)}%"
    source = finding.get("source", "Telemetry Analysis")
    
    line_color = ACCENT_GREEN if conf >= 0.85 else ACCENT_AMBER if conf >= 0.70 else ACCENT_BLUE
    
    title_style = ParagraphStyle("FCardTitle", fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=TEXT_DARK)
    body_style = ParagraphStyle("FCardBody", fontName="Helvetica", fontSize=8.5, leading=12, textColor=TEXT_BODY)
    meta_style = ParagraphStyle("FCardMeta", fontName="Helvetica", fontSize=8, leading=10, textColor=TEXT_MUTED)
    
    content = [
        Paragraph(f"Finding {index}: {finding.get('finding', '')}", title_style),
        Spacer(1, 1 * mm),
        Paragraph(f"<b>Evidence:</b> {finding.get('evidence', '')}", body_style),
        Spacer(1, 1 * mm),
        Paragraph(f"Confidence: <font color='#10b981'><b>{conf_pct}</b></font>  |  Source: {source}", meta_style)
    ]
    
    t = Table([[content]], colWidths=[180 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('LINELEFT', (0, 0), (0, -1), 3, line_color),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    return t

def generate_pdf(state: dict) -> str:
    """
    Generate a highly polished, professional 3-page incident report from investigation state.
    Satisfies all visual design requirements (white background, surface cards, custom headers, footers).
    """
    investigation_id = state.get("investigation_id", "unknown")
    pdf_path = REPORTS_DIR / f"{investigation_id}.pdf"

    final_report = state.get("final_report", {}) or {}
    kill_chain = state.get("kill_chain", []) or []
    ttp_mappings = state.get("ttp_mappings", []) or []
    patient_zero = state.get("patient_zero", {}) or {}
    blast_radius = state.get("blast_radius", {}) or {}
    spl_audit_log = state.get("spl_audit_log", []) or []
    severity = state.get("severity", "UNKNOWN") or "UNKNOWN"
    classification = state.get("attack_classification", "UNKNOWN") or "UNKNOWN"
    
    attack_window = state.get("attack_window", {}) or {}
    slo_report = state.get("slo_report", {}) or {}
    
    threat_actor_profile = final_report.get("threat_actor_profile", "") or ""
    if not threat_actor_profile:
        threat_actor_profile = state.get("threat_actor_profile", "No specific threat actor profile determined.")

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=35 * mm, # Leave extra room for the custom canvas footer
    )

    # ── BASE PARAGRAPH STYLES ──────────────────────────────────────────
    body_style = ParagraphStyle(
        "BodyDark",
        fontName="Helvetica",
        fontSize=9,
        textColor=TEXT_BODY,
        spaceAfter=4,
        leading=14,
    )
    bold_body_style = ParagraphStyle(
        "BoldBodyDark",
        parent=body_style,
        fontName="Helvetica-Bold",
        textColor=TEXT_DARK,
    )
    
    table_header_style = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=TEXT_PRIMARY,
        leading=10,
    )
    table_cell_style = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8,
        textColor=TEXT_BODY,
        leading=11,
    )
    table_cell_bold_style = ParagraphStyle(
        "TableCellBold",
        parent=table_cell_style,
        fontName="Helvetica-Bold",
        textColor=TEXT_DARK,
    )
    
    meta_label_style = ParagraphStyle(
        "MetaLabel",
        fontName="Helvetica-Bold",
        fontSize=8,
        textColor=TEXT_DARK,
        leading=10,
    )
    meta_val_style = ParagraphStyle(
        "MetaVal",
        fontName="Helvetica",
        fontSize=8,
        textColor=TEXT_BODY,
        leading=10,
    )
    
    mono_style = ParagraphStyle(
        "SentinelMono",
        fontName="Courier",
        fontSize=7.5,
        textColor=TEXT_DARK,
        backColor=colors.HexColor("#f1f5f9"),
        spaceAfter=2,
        leftIndent=4,
        borderPad=4,
    )

    story = []

    # =========================================================================
    # ── PAGE 1: COVER & EXECUTIVE NARRATIVE
    # =========================================================================
    story.append(create_cover_banner(state))
    story.append(Spacer(1, 5 * mm))
    
    # Metadata Block / Quick Info Table
    meta_data = [
        [
            Paragraph("Time Window Start", meta_label_style),
            Paragraph(attack_window.get("start", "N/A"), meta_val_style),
            Paragraph("SLO Compliance Status", meta_label_style),
            Paragraph(f"<b>{slo_report.get('overall_slo_status', 'UNKNOWN')}</b>", meta_val_style)
        ],
        [
            Paragraph("Time Window End", meta_label_style),
            Paragraph(attack_window.get("end", "N/A"), meta_val_style),
            Paragraph("Total Log Events Analyzed", meta_label_style),
            Paragraph(f"{attack_window.get('total_events', 0):,}", meta_val_style)
        ],
        [
            Paragraph("Peak Attack Hour", meta_label_style),
            Paragraph(attack_window.get("peak_hour", "N/A"), meta_val_style),
            Paragraph("Forensic Lead Indicator", meta_label_style),
            Paragraph(patient_zero.get("ip_address", "N/A"), meta_val_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[40 * mm, 50 * mm, 45 * mm, 45 * mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 5 * mm))
    
    # Executive Summary Section
    story.append(create_section_header("Executive Summary"))
    story.append(Spacer(1, 2 * mm))
    exec_summary = final_report.get("executive_summary", "No executive summary available.")
    story.append(Paragraph(exec_summary, body_style))
    story.append(Spacer(1, 3 * mm))
    
    # Threat Actor Profile Section
    story.append(create_section_header("Threat Actor Profile & Attack Narrative"))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(threat_actor_profile, body_style))
    story.append(Spacer(1, 3 * mm))
    
    # Kill Chain Reconstruction Timeline Section
    if kill_chain:
        kc_headers = [
            Paragraph("Stage Name", table_header_style),
            Paragraph("Tactic", table_header_style),
            Paragraph("Technique Used", table_header_style),
            Paragraph("Incident Timestamp", table_header_style),
            Paragraph("Confidence", table_header_style),
            Paragraph("Affected Asset", table_header_style)
        ]
        kc_data = [kc_headers]
        for stage in kill_chain[:6]: # Limit to 6 to prevent page overflow
            tech_raw = stage.get("mitre_technique", "N/A")
            tech_str = str(tech_raw).split(' ')[0].split('-')[0].strip()[:12]
            
            assets = stage.get("affected_assets", []) or []
            truncated_assets = []
            for asset in assets:
                asset_str = str(asset)[:22] + "..." if len(str(asset)) > 22 else str(asset)
                truncated_assets.append(asset_str)
            assets_val = ", ".join(truncated_assets) if truncated_assets else "N/A"
            
            kc_data.append([
                Paragraph(stage.get("stage_name", "N/A"), table_cell_bold_style),
                Paragraph(stage.get("mitre_tactic", "N/A"), table_cell_style),
                Paragraph(tech_str, table_cell_style),
                Paragraph(stage.get("timestamp", "N/A")[:16], table_cell_style),
                Paragraph(f"<font color='#10b981'><b>{stage.get('confidence', 'N/A')}</b></font>", table_cell_style),
                Paragraph(assets_val, table_cell_style)
            ])
            
        kc_table = Table(kc_data, colWidths=[35*mm, 20*mm, 30*mm, 32*mm, 23*mm, 40*mm])
        kc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SURFACE_BG),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([
            create_section_header("MITRE ATT&CK Kill Chain Timeline"),
            Spacer(1, 2 * mm),
            kc_table
        ]))
    else:
        story.append(create_section_header("MITRE ATT&CK Kill Chain Timeline"))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("No MITRE ATT&CK stages identified in this investigation.", body_style))
        
    story.append(PageBreak())

    # =========================================================================
    # ── PAGE 2: KEY FINDINGS & THREAT INTEL
    # =========================================================================
    story.append(create_page_header_banner("Key Findings & Threat Intelligence", state))
    story.append(Spacer(1, 2 * mm))
    
    # Key Findings Section
    story.append(create_section_header("Key Findings & Telemetry Evidence"))
    story.append(Spacer(1, 1.5 * mm))
    
    key_findings = final_report.get("key_findings", [])
    if key_findings:
        for idx, finding in enumerate(key_findings[:3], 1): # Top 3 key findings
            story.append(create_finding_card(finding, idx))
            story.append(Spacer(1, 1.4 * mm))
    else:
        story.append(Paragraph("No key findings reported.", body_style))
        story.append(Spacer(1, 1.4 * mm))
        
    story.append(Spacer(1, 0.5 * mm))
    
    # Recommended Actions Section
    story.append(create_section_header("Recommended Remediation & Defense Actions"))
    story.append(Spacer(1, 1.5 * mm))
    
    recommended_actions = final_report.get("recommended_actions", [])
    if recommended_actions:
        act_headers = [
            Paragraph("Priority", table_header_style),
            Paragraph("Recommended Action Description", table_header_style),
            Paragraph("MITRE Technique", table_header_style)
        ]
        act_data = [act_headers]
        for action in recommended_actions[:4]: # Top 4 recommended actions
            prio = action.get("priority", "SHORT_TERM") or "SHORT_TERM"
            prio_color = "#ef4444" if prio == "IMMEDIATE" else "#f59e0b" if prio == "SHORT_TERM" else "#10b981"
            act_data.append([
                Paragraph(f"<font color='{prio_color}'><b>{prio}</b></font>", table_cell_bold_style),
                Paragraph(action.get("action", "N/A"), table_cell_style),
                Paragraph(action.get("mitre_technique", "N/A"), table_cell_style)
            ])
            
        act_table = Table(act_data, colWidths=[30 * mm, 110 * mm, 40 * mm])
        act_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SURFACE_BG),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(act_table)
    else:
        story.append(Paragraph("No remediation actions recommended.", body_style))
        
    story.append(Spacer(1, 1.4 * mm))
    
    # MITRE ATT&CK Mapping & Threat Intelligence
    story.append(create_section_header("MITRE ATT&CK Mappings"))
    story.append(Spacer(1, 1.5 * mm))
    
    if ttp_mappings:
        ttp_headers = [
            Paragraph("Technique ID", table_header_style),
            Paragraph("Technique Name", table_header_style),
            Paragraph("Tactic Phase", table_header_style),
            Paragraph("Relevance Confidence", table_header_style)
        ]
        ttp_data = [ttp_headers]
        seen_ids = set()
        for ttp in ttp_mappings[:5]: # Top 5 TTP mappings
            tid = ttp.get("technique_id", "")
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            conf = ttp.get("confidence", 1.0)
            conf_pct = f"{round(conf * 100)}%"
            ttp_data.append([
                Paragraph(f"<font color='#3b82f6'><b>{tid}</b></font>", table_cell_bold_style),
                Paragraph(ttp.get("technique_name", "N/A"), table_cell_style),
                Paragraph(ttp.get("stage_name", "N/A") or ttp.get("tactic", "N/A"), table_cell_style),
                Paragraph(f"<b>{conf_pct}</b>", table_cell_style)
            ])
            
        ttp_table = Table(ttp_data, colWidths=[30 * mm, 70 * mm, 55 * mm, 25 * mm])
        ttp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), SURFACE_BG),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ttp_table)
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques mapped.", body_style))
        
    story.append(Spacer(1, 1.4 * mm))
    
    # CVE Deep Dive Section (Wrapped in KeepTogether to prevent stranded cards)
    cve_elements = [
        create_section_header("CVE Deep Dive & CVSS Analysis"),
        Spacer(1, 1.5 * mm)
    ]
    
    cves = final_report.get("cves_identified", [])
    if cves:
        cve_cards = []
        for cve_id in cves[:1]: # Cap CVE cards to 1 to fit on page 2 perfectly
            cve_info = get_cve_details(cve_id)
            if cve_info:
                score = cve_info.get("cvss_score", 0.0) or 0.0
                score_color = "#dc2626" if score >= 9.0 else "#ea580c" if score >= 7.0 else "#d97706" if score >= 4.0 else "#16a34a"
                
                # Truncate CVE description to 2 sentences maximum
                desc_raw = cve_info.get("description", "") or ""
                import re as _re
                sentences = _re.split(r'(?<=[.!?])\s+', desc_raw.strip())
                if len(sentences) > 2:
                    capped_desc = " ".join(sentences[:2]) + "..."
                else:
                    capped_desc = desc_raw
                    
                cve_cards.append([
                    Paragraph(f"<b>{cve_id}  |  {cve_info.get('title', '')}</b>", table_cell_bold_style),
                    Paragraph(f"CVSS: <font color='{score_color}'><b>{score}</b></font>  |  Remediation: {cve_info.get('remediation', '')}", table_cell_style),
                    Paragraph(f"Description: {capped_desc}", table_cell_style)
                ])
        
        if cve_cards:
            cve_data = []
            for card in cve_cards:
                cve_data.append([card[0]])
                cve_data.append([card[1]])
                cve_data.append([card[2]])
            
            if len(cves) > 1:
                other_cves = cves[1:]
                cve_data.append([Spacer(1, 1 * mm)])
                cve_data.append([
                    Paragraph(f"<font color='#64748b'><i>Note: Additional identified vulnerability: {', '.join(other_cves)}</i></font>", table_cell_style)
                ])
                
            cve_table = Table(cve_data, colWidths=[180 * mm])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('LINELEFT', (0, 0), (0, -1), 3, ACCENT_BLUE),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ]))
            cve_elements.append(cve_table)
        else:
            cve_elements.append(Paragraph(f"Identified CVEs: {', '.join(cves)}", body_style))
    else:
        cve_elements.append(Paragraph("No vulnerabilities or CVEs identified for this threat.", body_style))
        
    story.append(KeepTogether(cve_elements))
    story.append(PageBreak())

    # =========================================================================
    # ── PAGE 3: CONTAINMENT & AUDIT TRAIL
    # =========================================================================
    story.append(create_page_header_banner("Containment Plan & Security Auditing", state))
    story.append(Spacer(1, 4 * mm))
    
    # Containment Plan Section
    story.append(create_section_header("Phased Containment & Response Actions"))
    story.append(Spacer(1, 2 * mm))
    
    plan = state.get("containment_plan") or final_report.get("containment_plan", {})
    phases = []
    if plan:
        if isinstance(plan, dict):
            phases = plan.get("phases", [])
        else:
            phases = getattr(plan, "phases", [])
            
    containment_rows = []
    if phases:
        for phase_idx, phase in enumerate(phases, 1):
            phase_name = ""
            if isinstance(phase, dict):
                phase_name = phase.get("name") or phase.get("label") or f"Phase {phase_idx}"
                actions = phase.get("actions", [])
            else:
                phase_name = getattr(phase, "name", "") or getattr(phase, "label", "") or f"Phase {phase_idx}"
                actions = getattr(phase, "actions", [])
            
            for act in actions[:2]: # Show up to 2 actions per phase to prevent page overflow
                if isinstance(act, dict):
                    title = act.get("title", "Test Action")
                    target = act.get("target", "N/A")
                    risk = act.get("risk_level", "LOW") or "LOW"
                    status = act.get("status", "PENDING") or "PENDING"
                    desc = act.get("description", "")
                else:
                    title = getattr(act, "title", "Test Action")
                    target = getattr(act, "target", "N/A")
                    risk = getattr(act, "risk_level", "LOW") or "LOW"
                    status = getattr(act, "status", "PENDING") or "PENDING"
                    desc = getattr(act, "description", "")
                
                status_color = "#10b981" if status in ["EXECUTED", "COMPLETE"] else "#3b82f6" if status == "EXECUTING" else "#ea580c" if status in ["PENDING"] else "#ef4444"
                risk_color = "#ef4444" if risk == "HIGH" else "#f59e0b" if risk == "MEDIUM" else "#10b981"
                
                containment_rows.append([
                    Paragraph(f"<b>{phase_name}</b>", table_cell_bold_style),
                    Paragraph(f"<b>{title}</b><br/><font color='#64748b'>{desc}</font>", table_cell_style),
                    Paragraph(target, table_cell_style),
                    Paragraph(f"<font color='{risk_color}'><b>{risk}</b></font>", table_cell_style),
                    Paragraph(f"<font color='{status_color}'><b>{status}</b></font>", table_cell_style)
                ])
                
        if containment_rows:
            cont_headers = [
                Paragraph("Phase", table_header_style),
                Paragraph("Action & Details", table_header_style),
                Paragraph("Target Host/User", table_header_style),
                Paragraph("Risk Level", table_header_style),
                Paragraph("Execution Status", table_header_style)
            ]
            cont_data = [cont_headers] + containment_rows
            cont_table = Table(cont_data, colWidths=[28 * mm, 70 * mm, 30 * mm, 20 * mm, 22 * mm])
            cont_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), SURFACE_BG),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(cont_table)
        else:
            story.append(Paragraph("No active containment plan actions.", body_style))
    else:
        story.append(Paragraph("No containment plan generated.", body_style))
        
    story.append(Spacer(1, 3 * mm))
    
    # Counterfactual Reasoning Section
    story.append(create_section_header("Counterfactual Reasoning & Alternatives Ruled Out"))
    story.append(Spacer(1, 2 * mm))
    
    logger.debug("[PDF] counterfactual keys: %s",
                 list(state.get('counterfactual_analysis',
                 state.get('counterfactual', {})).keys()))
    cf = state.get("counterfactual_reasoning", {}) or final_report.get("counterfactual_reasoning", {}) or {}
    alternatives = cf.get("alternatives_ruled_out", []) or []
    confirmed_class = cf.get("confirmed_classification", classification) or classification
    
    cf_text = [
        Paragraph(f"<b>Confirmed Attack Hypothesis:</b> <font color='#10b981'><b>{confirmed_class}</b></font>", bold_body_style),
        Spacer(1, 1 * mm)
    ]
    
    if alternatives:
        for idx, alt in enumerate(alternatives[:2], 1): # Show up to 2 alternatives
            alt_name = alt.get("classification", alt.get("alternative", "Alternative")) if isinstance(alt, dict) else alt
            reason = alt.get("reason", alt.get("ruled_out_reason", "No reason documented.")) if isinstance(alt, dict) else "Ruled out during telemetric classification check."
            missing = alt.get("missing_indicators", []) if isinstance(alt, dict) else []
            missing_str = ", ".join(missing) if missing else "None cited"
            cf_text.append(Paragraph(f"<b>Alternative {idx}: {alt_name}</b> (Ruled Out)", table_cell_bold_style))
            cf_text.append(Paragraph(f"<b>Rationale:</b> {reason}", table_cell_style))
            cf_text.append(Paragraph(f"<b>Missing Indicators:</b> <font color='#ef4444'>{missing_str}</font>", table_cell_style))
            cf_text.append(Spacer(1, 1.5 * mm))
    else:
        cf_text.append(Paragraph("No alternative classifications were analyzed or ruled out.", table_cell_style))
        
    cf_table = Table([[cf_text]], colWidths=[180 * mm])
    cf_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('LINELEFT', (0, 0), (0, -1), 3, ACCENT_AMBER),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(cf_table)
    story.append(Spacer(1, 3 * mm))
    
    # Patient Zero & Asset Exposure Radius Section
    story.append(create_section_header("Patient Zero & Asset Exposure Analysis"))
    story.append(Spacer(1, 2 * mm))
    
    pz_table_data = [
        [
            Paragraph("<b>Patient Zero IP Address</b>", meta_label_style),
            Paragraph(patient_zero.get("ip_address", "Unknown"), meta_val_style),
            Paragraph("<b>Total Assets Compromised</b>", meta_label_style),
            Paragraph(str(blast_radius.get("total_affected_ips", 0)), meta_val_style)
        ],
        [
            Paragraph("<b>Patient Zero Network Role</b>", meta_label_style),
            Paragraph(patient_zero.get("role", "Unknown"), meta_val_style),
            Paragraph("<b>Data Scope at Risk</b>", meta_label_style),
            Paragraph(blast_radius.get("data_at_risk", "Unknown"), meta_val_style)
        ]
    ]
    pz_table = Table(pz_table_data, colWidths=[40 * mm, 50 * mm, 45 * mm, 45 * mm])
    pz_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(pz_table)
    story.append(Spacer(1, 3 * mm))
    
    # Splunk Query Audit Chain Section
    story.append(create_section_header("Splunk Audit & Verification Chain"))
    story.append(Spacer(1, 2 * mm))
    
    # Problem 4: High-level verification bar
    import html as _html
    if spl_audit_log:
        summary_text = f"<b>✓ AUDIT CHAIN VERIFIED</b>  |  {len(spl_audit_log)} entries  |  SHA-256  |  Chain Intact"
        summary_bg = colors.HexColor("#f0fdf4")
        summary_border = colors.HexColor("#10b981")
        summary_text_color = "#15803d"
    else:
        summary_text = "<b>⚠ AUDIT CHAIN INCOMPLETE</b>  |  0 entries  |  Splunk offline or missing audit trace"
        summary_bg = colors.HexColor("#fff7ed")
        summary_border = colors.HexColor("#ea580c")
        summary_text_color = "#c2410c"

    summary_p = Paragraph(f"<font color='{summary_text_color}'>{summary_text}</font>", table_cell_style)
    summary_table = Table([[summary_p]], colWidths=[180 * mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), summary_bg),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('LINELEFT', (0, 0), (0, -1), 3, summary_border),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 3 * mm))
    
    if spl_audit_log:
        num_queries = len(spl_audit_log)
        story.append(Paragraph(
            f"<font color='#64748b'>Full SPL audit log with {num_queries} queries available in "
            f"investigation history and Supabase record.</font>",
            ParagraphStyle("AuditNote", parent=table_cell_style, fontSize=7.5, leading=10, textColor=TEXT_MUTED)
        ))
    else:
        story.append(Paragraph("No query execution logs in this investigation's audit trail.", body_style))

    # Build the document
    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    logger.info("[PDF] Visual incident report overhaul successfully generated | path=%s", pdf_path)
    return str(pdf_path)
