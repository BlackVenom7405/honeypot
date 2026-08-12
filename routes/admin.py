from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
from models import AttackLog, MalwareMetadata
from report_generator import generate_pdf_report
from datetime import datetime
from auth import get_current_user
import json
import re

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

# Server launch timestamp for real-time uptime calculation
SERVER_START_TIME = datetime.utcnow()

def mask_ip_address(ip: str) -> str:
    """Mask IP address for guest users (e.g., 192.168.1.100 -> 192.168.***.***)."""
    if not ip or ip == "unknown":
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    if ":" in ip:  # IPv6
        return ip.split(":")[0] + ":****:****:****"
    return "***.***.***.***"

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login?next=/admin&auth_required=1", status_code=303)
    
    return templates.TemplateResponse(request=request, name="admin.html", context={
        "user_role": user["role"],
        "username": user["username"],
        "display_name": user["display_name"]
    })

@router.get("/api/stats")
async def get_stats(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    
    is_guest = (user["role"] == "guest")

    # 1. Total Attacks
    total_attacks = db.query(AttackLog).count()
    
    # 2. Unique IPs
    unique_ips = db.query(AttackLog.ip_address).distinct().count()
    
    # 3. Total Malware
    total_malware = db.query(MalwareMetadata).count()
    
    # 4. Attack Type Distribution (Standardized to 5 Core Vectors)
    distribution_raw = db.query(AttackLog.attack_type, func.count(AttackLog.attack_type)).group_by(AttackLog.attack_type).all()
    distribution = {
        "SQL Injection": 0,
        "XSS": 0,
        "Path Traversal": 0,
        "Brute Force": 0,
        "Web Shell Detection": 0
    }
    for raw_type, count in distribution_raw:
        tl = (raw_type or '').lower()
        if "sql" in tl:
            distribution["SQL Injection"] += count
        elif "xss" in tl:
            distribution["XSS"] += count
        elif "traversal" in tl or "command" in tl or "api" in tl:
            distribution["Path Traversal"] += count
        elif "shell" in tl or "upload" in tl:
            distribution["Web Shell Detection"] += count
        else:
            distribution["Brute Force"] += count

    # 5. Recent Attacks (Rich telemetry for Traffic Analysis and Operational Deck)
    recent_attacks = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(100).all()
    recent_logs = []
    for log in recent_attacks:
        tl = (log.attack_type or '').lower()
        if "sql" in tl:
            clean_type = "SQL Injection"
        elif "xss" in tl:
            clean_type = "XSS"
        elif "traversal" in tl or "command" in tl or "api" in tl:
            clean_type = "Path Traversal"
        elif "shell" in tl or "upload" in tl:
            clean_type = "Web Shell Detection"
        else:
            clean_type = "Brute Force"

        # Apply redaction for guest users
        if is_guest:
            ip_display = mask_ip_address(log.ip_address)
            payload_display = "[REDACTED - GUEST CLEARANCE]" if log.payload else ""
            ua_display = "Standard Browser Client (Sanitized)" if log.user_agent else "unknown"
        else:
            ip_display = log.ip_address
            payload_display = log.payload or ""
            ua_display = log.user_agent or "unknown"

        recent_logs.append({
            "timestamp": log.timestamp.isoformat() if log.timestamp else datetime.now().isoformat(),
            "ip_address": ip_display,
            "endpoint": log.endpoint,
            "method": log.method or "POST",
            "attack_type": clean_type,
            "severity": log.severity,
            "payload": payload_display,
            "user_agent": ua_display
        })

    # 6. Malware Samples (Vault Telemetry)
    malware_list = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).limit(50).all()
    malware_data = []
    for m in malware_list:
        if is_guest:
            source_ip_display = mask_ip_address(m.source_ip)
            quarantine_path_display = "[RESTRICTED VAULT ACCESS]"
            hash_display = (m.file_hash[:12] + "..." + m.file_hash[-6:]) if m.file_hash else ""
        else:
            source_ip_display = m.source_ip
            quarantine_path_display = m.quarantine_path or "uploads/quarantine/"
            hash_display = m.file_hash

        malware_data.append({
            "filename": m.filename,
            "file_hash": hash_display,
            "file_size": m.file_size or 0,
            "mime_type": m.mime_type or "application/octet-stream",
            "source_ip": source_ip_display,
            "quarantine_path": quarantine_path_display,
            "timestamp": m.timestamp.isoformat() if m.timestamp else datetime.now().isoformat()
        })

    # 7. Dynamic Status and Real-time Uptime Calculation
    now_utc = datetime.utcnow()
    uptime_delta = now_utc - SERVER_START_TIME
    total_seconds = int(uptime_delta.total_seconds())
    
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        uptime_formatted = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        uptime_formatted = f"{minutes}m {seconds}s"
    else:
        uptime_formatted = f"{seconds}s"

    # Seconds since most recent attack
    sec_since_attack = 999999
    last_severity = "Low"
    if recent_attacks:
        last_log = recent_attacks[0]
        if last_log.timestamp:
            sec_since_attack = max(0, int((now_utc - last_log.timestamp).total_seconds()))
            last_severity = last_log.severity or "Low"

    # Dynamic status & simulated load impact based on active attacks
    if sec_since_attack <= 15:
        if str(last_severity).lower() == "high":
            system_status = "UNDER ATTACK"
            status_color = "danger"
            uptime_percentage = "97.80%"
        else:
            system_status = "INTERCEPTING"
            status_color = "warning"
            uptime_percentage = "98.95%"
    elif sec_since_attack <= 45:
        system_status = "MITIGATING"
        status_color = "accent"
        uptime_percentage = "99.45%"
    else:
        system_status = "NOMINAL"
        status_color = "success"
        uptime_percentage = "99.99%"

    return {
        "user_role": user["role"],
        "username": user["username"],
        "display_name": user["display_name"],
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "total_malware": total_malware,
        "distribution": distribution,
        "recent_attacks": recent_logs,
        "malware": malware_data,
        "system_status": system_status,
        "status_color": status_color,
        "uptime_percentage": uptime_percentage,
        "uptime_formatted": uptime_formatted,
        "uptime_seconds": total_seconds,
        "sec_since_attack": sec_since_attack
    }

@router.get("/api/logs/download")
@router.get("/api/logs/download/txt")
async def download_logs(request: Request, format: str = "txt", db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return PlainTextResponse("Authentication required to download logs.", status_code=401)
    if user["role"] != "admin":
        return PlainTextResponse("Access Denied: Only administrators have clearance to download raw threat logs and forensic reports.", status_code=403)

    logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).all()
    malware = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).all()
    
    if format.lower() == "pdf":
        pdf_bytes = generate_pdf_report(logs, malware)
        filename = f"sentinel_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    # Default: Plain text format
    content = "================================================================================\n"
    content += "                   GSI CYBERGUARD SENTINEL - THREAT LOGS\n"
    content += "================================================================================\n"
    content += f"Export Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    content += f"Authorized User: {user['username']} ({user['display_name']})\n"
    content += f"Total Incidents Logged: {len(logs)}\n"
    content += f"Quarantined Malware Samples: {len(malware)}\n"
    content += "================================================================================\n\n"
    
    content += "--- RECENT ADVERSARIAL EVENTS ---\n\n"
    for log in logs:
        ts = log.timestamp.isoformat() if log.timestamp else "N/A"
        content += f"[{ts}Z] IP: {log.ip_address} | Endpoint: {log.endpoint} | Type: {log.attack_type} | Severity: {log.severity}\n"
        content += f"User-Agent: {log.user_agent}\n"
        content += f"Payload: {log.payload}\n"
        content += "-" * 80 + "\n"
        
    if malware:
        content += "\n--- QUARANTINED MALWARE SAMPLES ---\n\n"
        for m in malware:
            ts = m.timestamp.isoformat() if m.timestamp else "N/A"
            content += f"[{ts}Z] File: {m.filename} | Size: {m.file_size} bytes | MIME: {m.mime_type} | Source IP: {m.source_ip}\n"
            content += f"SHA-256 Hash: {m.file_hash}\n"
            content += "-" * 80 + "\n"
        
    filename = f"sentinel_threat_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return PlainTextResponse(content=content, headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })

@router.get("/api/logs/download/pdf")
async def download_pdf_logs(request: Request, db: Session = Depends(get_db)):
    return await download_logs(request=request, format="pdf", db=db)
