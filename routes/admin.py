from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db
from models import AttackLog, MalwareMetadata
import json

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="admin.html")

@router.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)):
    # 1. Total Attacks
    total_attacks = db.query(AttackLog).count()
    
    # 2. Unique IPs
    unique_ips = db.query(AttackLog.ip_address).distinct().count()
    
    # 3. Total Malware
    total_malware = db.query(MalwareMetadata).count()
    
    # 4. Attack Type Distribution
    distribution_raw = db.query(AttackLog.attack_type, func.count(AttackLog.attack_type)).group_by(AttackLog.attack_type).all()
    distribution = {t: c for t, c in distribution_raw}
    
    # 5. Recent Attacks
    recent_attacks = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(10).all()
    recent_logs = []
    for log in recent_attacks:
        recent_logs.append({
            "timestamp": log.timestamp.isoformat(),
            "ip_address": log.ip_address,
            "endpoint": log.endpoint,
            "attack_type": log.attack_type,
            "severity": log.severity
        })
        
    # 6. Malware Samples
    malware_list = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).limit(10).all()
    malware_data = []
    for m in malware_list:
        malware_data.append({
            "filename": m.filename,
            "file_hash": m.file_hash,
            "file_size": m.file_size,
            "mime_type": m.mime_type,
            "source_ip": m.source_ip
        })

    return {
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "total_malware": total_malware,
        "distribution": distribution,
        "recent_attacks": recent_logs,
        "malware": malware_data
    }

@router.get("/api/logs/download", response_class=PlainTextResponse)
async def download_logs(db: Session = Depends(get_db)):
    logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).all()
    
    content = "GSI SENTINEL - THREAT INTELLIGENCE LOGS\n"
    content += "="*50 + "\n\n"
    
    for log in logs:
        content += f"[{log.timestamp.isoformat() + 'Z'}] IP: {log.ip_address} | Endpoint: {log.endpoint} | Type: {log.attack_type} | Severity: {log.severity}\n"
        content += f"Payload: {log.payload}\n"
        content += "-"*50 + "\n"
        
    return PlainTextResponse(content=content, headers={
        "Content-Disposition": "attachment; filename=gsi_threat_logs.txt"
    })
