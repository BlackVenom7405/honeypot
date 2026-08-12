import io
from datetime import datetime, timezone, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render total page count 'Page X of Y'
    along with running header and footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            self.drawString(40, letter[1] - 30, "CYBERGUARD SENTINEL-X // INCIDENT AUDIT REPORT")
            self.setFont("Helvetica", 8)
            self.drawRightString(letter[0] - 40, letter[1] - 30, "TLP:AMBER | STRICTLY CONFIDENTIAL")
            
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.75)
            self.line(40, letter[1] - 35, letter[0] - 40, letter[1] - 35)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.75)
        self.line(40, 42, letter[0] - 40, 42)
        
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0F172A"))
        self.drawString(40, 30, "GSI CYBERGUARD SENTINEL")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(185, 30, "• Automated Threat Intelligence & Forensic Honeynet")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 40, 30, page_text)
        
        self.restoreState()


def generate_pdf_report(attack_logs, malware_list, stats_summary=None) -> bytes:
    """
    Generates a professional Cyber Threat Intelligence & Forensic Audit PDF report.
    Returns the generated PDF as raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12
    )

    badge_banner_style = ParagraphStyle(
        'BadgeBanner',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#DC2626'),
        alignment=2 # Right
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    body_text = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    cell_text = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1E293B')
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0F172A')
    )

    code_payload = ParagraphStyle(
        'CodePayload',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#991B1B')
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#FFFFFF')
    )

    story = []

    # Time calculations (IST and UTC)
    now_utc = datetime.now(timezone.utc)
    ist_offset = timezone(timedelta(hours=5, minutes=30))
    now_ist = now_utc.astimezone(ist_offset)
    report_id = f"CTI-{now_utc.strftime('%Y%m%d')}-{now_utc.strftime('%H%M%S')}"

    # 1. Header Banner & Classification
    header_data = [
        [
            Paragraph("<b>CYBERGUARD // SENTINEL-X HONEYNET</b>", subtitle_style),
            Paragraph("<b>CLASSIFICATION: TLP:AMBER / RESTRICTED</b>", badge_banner_style)
        ]
    ]
    header_tbl = Table(header_data, colWidths=[320, 212])
    header_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(header_tbl)

    story.append(Spacer(1, 4))
    story.append(Paragraph("Threat Intelligence & Forensic Incident Report", title_style))
    story.append(Paragraph(
        f"<b>Report ID:</b> {report_id} &nbsp;|&nbsp; "
        f"<b>Generated:</b> {now_ist.strftime('%d-%b-%Y %I:%M:%S %p')} IST ({now_utc.strftime('%H:%M:%S')} UTC) &nbsp;|&nbsp; "
        f"<b>Target System:</b> Honeypot Perimeter Deception Grid",
        subtitle_style
    ))
    
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=12))

    # Calculate summary metrics
    total_intrusions = len(attack_logs)
    unique_ips = len(set(log.ip_address for log in attack_logs if log.ip_address))
    total_quarantine = len(malware_list)
    
    # Severity distribution
    high_count = sum(1 for log in attack_logs if str(log.severity).lower() == 'high')
    med_count = sum(1 for log in attack_logs if str(log.severity).lower() == 'medium')
    low_count = sum(1 for log in attack_logs if str(log.severity).lower() == 'low')
    
    peak_severity = "CRITICAL / HIGH" if high_count > 0 else ("ELEVATED / MEDIUM" if med_count > 0 else "LOW")
    threat_color = "#DC2626" if high_count > 0 else ("#D97706" if med_count > 0 else "#059669")

    # 2. Executive Metrics KPI Grid
    story.append(Paragraph("1. Executive Summary & Threat Posture", section_heading))
    story.append(Paragraph(
        "This security audit report provides real-time forensic analysis of malicious attempts, suspicious payloads, "
        "and weaponized binary uploads trapped by the CyberGuard Sentinel honeynet architecture. "
        "All trapped adversary communications have been quarantined and parsed for indicators of compromise (IoCs).",
        body_text
    ))
    story.append(Spacer(1, 8))

    kpi_data = [
        [
            Paragraph("CAPTURED INTRUSIONS", ParagraphStyle('KpiL', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#64748B'))),
            Paragraph("UNIQUE ADVERSARIES", ParagraphStyle('KpiL', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#64748B'))),
            Paragraph("MALWARE ISOLATED", ParagraphStyle('KpiL', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#64748B'))),
            Paragraph("DEFCON STATUS", ParagraphStyle('KpiL', fontName='Helvetica-Bold', fontSize=7.5, textColor=colors.HexColor('#64748B'))),
        ],
        [
            Paragraph(f"<font size=16 color='#0F172A'><b>{total_intrusions}</b></font>", ParagraphStyle('KpiV', fontName='Helvetica-Bold')),
            Paragraph(f"<font size=16 color='#0F172A'><b>{unique_ips}</b></font>", ParagraphStyle('KpiV', fontName='Helvetica-Bold')),
            Paragraph(f"<font size=16 color='#0F172A'><b>{total_quarantine}</b></font>", ParagraphStyle('KpiV', fontName='Helvetica-Bold')),
            Paragraph(f"<font size=14 color='{threat_color}'><b>{peak_severity}</b></font>", ParagraphStyle('KpiV', fontName='Helvetica-Bold')),
        ]
    ]
    
    kpi_tbl = Table(kpi_data, colWidths=[133, 133, 133, 133])
    kpi_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(kpi_tbl)
    story.append(Spacer(1, 10))

    # 3. Threat Vector Breakdown Table
    story.append(Paragraph("2. Threat Vector Distribution", section_heading))
    
    def normalize_attack_name(atype: str) -> str:
        tl = (atype or '').lower()
        if "sql" in tl:
            return "SQL Injection"
        elif "shell" in tl or "upload" in tl:
            return "Web Shell Detection"
        elif "xss" in tl:
            return "XSS"
        elif "traversal" in tl or "command" in tl or "api" in tl:
            return "Path Traversal"
        return "Brute Force"

    # Aggregate attacks by the 5 standardized vectors
    vector_counts = {}
    for log in attack_logs:
        norm_type = normalize_attack_name(log.attack_type)
        vector_counts[norm_type] = vector_counts.get(norm_type, 0) + 1

    vector_rows = [
        [
            Paragraph("ATTACK VECTOR / CLASSIFICATION", table_header),
            Paragraph("INCIDENTS", table_header),
            Paragraph("SHARE (%)", table_header),
            Paragraph("PRIMARY RISK LEVEL", table_header)
        ]
    ]

    if vector_counts:
        for vtype, count in sorted(vector_counts.items(), key=lambda x: x[1], reverse=True):
            share = (count / total_intrusions * 100) if total_intrusions > 0 else 0
            
            # Determine vector risk
            v_lower = vtype.lower()
            if "sql" in v_lower or "shell" in v_lower:
                risk_badge = "<font color='#DC2626'><b>HIGH (CRITICAL)</b></font>"
            elif "xss" in v_lower or "traversal" in v_lower:
                risk_badge = "<font color='#D97706'><b>MEDIUM (ELEVATED)</b></font>"
            else:
                risk_badge = "<font color='#059669'><b>LOW (MONITORED)</b></font>"

            vector_rows.append([
                Paragraph(f"<b>{vtype}</b>", cell_bold),
                Paragraph(str(count), cell_text),
                Paragraph(f"{share:.1f}%", cell_text),
                Paragraph(risk_badge, cell_text)
            ])
    else:
        vector_rows.append([
            Paragraph("<i>No attack vectors recorded in active window.</i>", cell_text),
            Paragraph("0", cell_text),
            Paragraph("0.0%", cell_text),
            Paragraph("<font color='#059669'><b>CLEAN</b></font>", cell_text)
        ])

    vector_tbl = Table(vector_rows, colWidths=[200, 80, 92, 160])
    vector_tbl_styles = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]
    # Alternating row colors
    for i in range(1, len(vector_rows)):
        bg = colors.HexColor('#FFFFFF') if i % 2 == 1 else colors.HexColor('#F8FAFC')
        vector_tbl_styles.append(('BACKGROUND', (0, i), (-1, i), bg))
    
    vector_tbl.setStyle(TableStyle(vector_tbl_styles))
    story.append(vector_tbl)
    story.append(Spacer(1, 10))

    # 4. Quarantined Malware / Binary Artifacts (if any)
    if malware_list:
        story.append(Paragraph("3. Quarantined Weaponized Binaries & Malware Samples", section_heading))
        malware_rows = [
            [
                Paragraph("FILENAME", table_header),
                Paragraph("SHA-256 HASH IDENTIFIER", table_header),
                Paragraph("SIZE", table_header),
                Paragraph("MIME TYPE", table_header),
                Paragraph("SOURCE IP", table_header)
            ]
        ]
        for m in malware_list:
            malware_rows.append([
                Paragraph(f"<b>{m.filename}</b>", cell_bold),
                Paragraph(f"<font size=6.5 face='Courier'>{m.file_hash[:28]}...</font>", cell_text),
                Paragraph(f"{(m.file_size or 0)/1024:.1f} KB", cell_text),
                Paragraph(str(m.mime_type or "unknown"), cell_text),
                Paragraph(str(m.source_ip or "N/A"), cell_text)
            ])
        
        malware_tbl = Table(malware_rows, colWidths=[120, 152, 60, 110, 90])
        m_styles = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#7F1D1D')), # Dark Crimson
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ]
        for i in range(1, len(malware_rows)):
            bg = colors.HexColor('#FFFFFF') if i % 2 == 1 else colors.HexColor('#FEF2F2')
            m_styles.append(('BACKGROUND', (0, i), (-1, i), bg))
        malware_tbl.setStyle(TableStyle(m_styles))
        story.append(malware_tbl)
        story.append(Spacer(1, 10))

    # 5. Detailed Forensic Incident Logs
    story.append(Paragraph("4. Granular Forensic Incident Logs", section_heading))
    story.append(Paragraph(
        "Comprehensive log of captured intrusion attempts, intercepted payload strings, request targets, and risk scores.",
        body_text
    ))
    story.append(Spacer(1, 6))

    log_rows = [
        [
            Paragraph("TIMESTAMP", table_header),
            Paragraph("SOURCE IP", table_header),
            Paragraph("ENDPOINT", table_header),
            Paragraph("CLASSIFICATION", table_header),
            Paragraph("RISK", table_header),
            Paragraph("PAYLOAD / EVIDENCE", table_header)
        ]
    ]

    if attack_logs:
        for log in attack_logs:
            # Format time
            log_time_str = ""
            if log.timestamp:
                try:
                    if isinstance(log.timestamp, datetime):
                        # Convert to IST
                        dt_ist = log.timestamp.replace(tzinfo=timezone.utc).astimezone(ist_offset)
                        log_time_str = dt_ist.strftime("%d-%b %H:%M:%S")
                    else:
                        log_time_str = str(log.timestamp)[:19]
                except Exception:
                    log_time_str = str(log.timestamp)[:19]

            # Severity badge styling
            sev = str(log.severity or "Low").capitalize()
            if sev == "High":
                sev_html = "<font color='#DC2626'><b>HIGH</b></font>"
            elif sev == "Medium":
                sev_html = "<font color='#D97706'><b>MED</b></font>"
            else:
                sev_html = "<font color='#059669'><b>LOW</b></font>"

            # Format payload string (escape HTML chars safely)
            raw_payload = str(log.payload or "")
            clean_payload = (
                raw_payload.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
            )
            if len(clean_payload) > 130:
                clean_payload = clean_payload[:130] + "..."
            if not clean_payload.strip():
                clean_payload = "<i>[Empty / Header scan]</i>"

            norm_classification = normalize_attack_name(log.attack_type)
            log_rows.append([
                Paragraph(log_time_str, cell_text),
                Paragraph(f"<b>{log.ip_address or 'Unknown'}</b>", cell_text),
                Paragraph(str(log.endpoint or "/"), cell_text),
                Paragraph(norm_classification, cell_bold),
                Paragraph(sev_html, cell_text),
                Paragraph(clean_payload, code_payload)
            ])
    else:
        log_rows.append([
            Paragraph("<i>No logs</i>", cell_text),
            Paragraph("-", cell_text),
            Paragraph("-", cell_text),
            Paragraph("-", cell_text),
            Paragraph("-", cell_text),
            Paragraph("<i>No intrusion activities recorded.</i>", cell_text)
        ])

    # Col Widths: Total printable width = 532 (letter width 612 - 80 margins)
    # [80, 85, 75, 95, 45, 152] = 532
    log_tbl = Table(log_rows, colWidths=[80, 85, 75, 95, 45, 152], repeatRows=1)
    l_styles = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]
    for i in range(1, len(log_rows)):
        bg = colors.HexColor('#FFFFFF') if i % 2 == 1 else colors.HexColor('#F8FAFC')
        l_styles.append(('BACKGROUND', (0, i), (-1, i), bg))
    log_tbl.setStyle(TableStyle(l_styles))
    story.append(log_tbl)
    story.append(Spacer(1, 14))

    # 6. Strategic Mitigation & Security Hardening Recommendations
    rec_block = []
    rec_block.append(Paragraph("5. Recommended Countermeasures & Mitigation Plan", section_heading))
    
    mitigations = [
        ("WAF Rule Enforcement", "Deploy updated web application firewall (WAF) signatures targeting identified SQL injection substrings and script execution payloads observed on public endpoints."),
        ("Strict Input Sanitization & Parameterization", "Ensure all database queries utilize parameterized prepared statements, and implement context-aware output encoding to eliminate cross-site scripting (XSS) opportunities."),
        ("Multi-Layer Rate Limiting & Geo-Fencing", "Enforce dynamic IP-based request throttling on authentication routes (/login, /forgot-password) to counteract automated credential stuffing and brute-force tools."),
        ("Secure File Ingestion & Sandboxing", "Isolate all file ingest pipelines within locked-down, non-executable directories with MIME-type verification and anti-malware hashing.")
    ]

    for title, desc in mitigations:
        rec_block.append(Paragraph(f"• <b>{title}:</b> {desc}", body_text))
        rec_block.append(Spacer(1, 3))

    story.append(KeepTogether(rec_block))

    # Build the PDF using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
