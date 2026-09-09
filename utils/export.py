import pandas as pd
from datetime import datetime
import json

def export_to_csv(devices, path):
    flattened_devices = []
    for dev in devices:
        hardware = dev.get("hardware", {})
        device_info = dev.get("device", {})
        
        flat_dev = {
            "IP": dev.get("ip", ""),
            "Status": dev.get("status", ""),
            "MAC": hardware.get("mac_address", dev.get("mac", "")),
            "Vendor": hardware.get("vendor", dev.get("vendor", "")),
            "Device Type": dev.get("device_type", ""),
            "OS Guess": device_info.get("os_guess", dev.get("os", "")),
            "Risk Level": dev.get("risk_level", ""),
            "Risk Score": dev.get("risk_score", 0),
            "Open Ports": json.dumps(device_info.get("open_ports", dev.get("open_ports", []))),
            "Banners": json.dumps(device_info.get("banners", dev.get("banners", []))),
            "Risk Reasons": json.dumps(dev.get("risk_reasons", [])),
            "Web Intel": json.dumps(dev.get("web_intel", {})),
            "Domain": dev.get("domain", ""),
            "Is IoT": dev.get("is_iot", False)
        }
        flattened_devices.append(flat_dev)
        
    df = pd.DataFrame(flattened_devices)
    df.to_csv(path, index=False)

def export_to_pdf(devices, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    doc = SimpleDocTemplate(path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle('CyberTitle', parent=styles['Heading1'], fontSize=28, textColor=colors.HexColor("#2c3e50"), alignment=TA_CENTER, spaceAfter=30)
    subtitle_style = ParagraphStyle('CyberSubTitle', parent=styles['Normal'], fontSize=14, textColor=colors.HexColor("#7f8c8d"), alignment=TA_CENTER, spaceAfter=50)
    heading_style = ParagraphStyle('CyberHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor("#2980b9"), spaceBefore=20, spaceAfter=10)
    normal_style = ParagraphStyle('CyberNormal', parent=styles['Normal'], fontSize=10, textColor=colors.black, spaceAfter=6)
    critical_style = ParagraphStyle('CyberCritical', parent=styles['Normal'], fontSize=10, textColor=colors.red, spaceAfter=6)
    
    # --- COVER PAGE ---
    elements.append(Spacer(1, 100))
    elements.append(Paragraph("NETSCAN", title_style))
    elements.append(Paragraph("Cybersecurity Intelligence Report", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    
    # Executive Summary Stats
    active = sum(1 for d in devices if d.get('status') == 'Active')
    high_risk = sum(1 for d in devices if d.get('risk_level') == 'High')
    medium_risk = sum(1 for d in devices if d.get('risk_level') == 'Medium')
    iot_count = sum(1 for d in devices if d.get('is_iot'))
    
    elements.append(Spacer(1, 50))
    elements.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ["Total Assets Scanned", str(len(devices))],
        ["Active Hosts Discovered", str(active)],
        ["High Risk Assets", str(high_risk)],
        ["Medium Risk Assets", str(medium_risk)],
        ["IoT/Embedded Devices", str(iot_count)]
    ]
    
    sum_table = Table(summary_data, colWidths=[200, 100])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ecf0f1")),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.black),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#bdc3c7")),
    ]))
    elements.append(sum_table)
    elements.append(PageBreak())
    
    # --- HOST DETAILS ---
    elements.append(Paragraph("Detailed Host Analysis", heading_style))
    
    for dev in [d for d in devices if d.get('status') == 'Active']:
        hardware = dev.get("hardware", {})
        device_info = dev.get("device", {})
        
        ip = dev.get("ip", "Unknown")
        mac = hardware.get("mac_address", dev.get("mac", "Unknown"))
        vendor = hardware.get("vendor", dev.get("vendor", "Unknown"))
        os_guess = device_info.get("os_guess", dev.get("os", "Unknown OS"))
        risk = dev.get("risk_level", "Low")
        
        host_color = colors.red if risk == "High" else (colors.orange if risk == "Medium" else colors.green)
        
        host_header = [
            [Paragraph(f"<b>Host: {ip}</b>", styles['Normal']), Paragraph(f"<b>Risk: <font color='{host_color.hexval()}'>{risk}</font></b>", styles['Normal'])]
        ]
        h_table = Table(host_header, colWidths=[350, 150])
        h_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ecf0f1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(h_table)
        elements.append(Spacer(1, 5))
        
        info_text = f"<b>MAC:</b> {mac} | <b>Vendor:</b> {vendor} | <b>OS:</b> {os_guess}"
        if dev.get("domain"):
            info_text += f" | <b>Domain:</b> {dev.get('domain')}"
        elements.append(Paragraph(info_text, normal_style))
        
        ports = device_info.get("open_ports", dev.get("open_ports", []))
        banners = device_info.get("banners", dev.get("banners", []))
        if ports:
            elements.append(Paragraph("<b>Open Ports & Services:</b>", normal_style))
            for p, b in zip(ports, banners):
                clean_b = str(b).strip()[:100] if b else "No Banner"
                clean_b = clean_b.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                elements.append(Paragraph(f"- Port {p}: <i>{clean_b}</i>", normal_style))
        else:
            elements.append(Paragraph("<b>Open Ports:</b> None detected.", normal_style))
            
        web_intel = dev.get("web_intel", {})
        if web_intel:
            elements.append(Paragraph("<b>Web Intelligence:</b>", normal_style))
            for port, data in web_intel.items():
                if "http" in data:
                    srv = data["http"].get("server", "Unknown")
                    elements.append(Paragraph(f"- Port {port} HTTP Server: {srv}", normal_style))
                if "tls" in data:
                    tls_sub = data["tls"].get("subject", "Unknown")
                    elements.append(Paragraph(f"- Port {port} TLS Subject: {tls_sub}", normal_style))

        reasons = dev.get("risk_reasons", [])
        if reasons:
            elements.append(Paragraph("<b>Vulnerability Triggers:</b>", normal_style))
            for r in reasons:
                r = r.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                elements.append(Paragraph(f"- {r}", critical_style))
        
        elements.append(Spacer(1, 20))
        
    doc.build(elements)

def export_to_json(devices, path):
    with open(path, 'w') as f:
        json.dump(devices, f, indent=4)
