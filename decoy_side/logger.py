import json
import logging
import os
from datetime import datetime
from models import AttackLog
from database import SessionLocal

# Ensure log directories exist
os.makedirs("logs", exist_ok=True)

# Configure file logging
logging.basicConfig(
    filename='logs/honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_attack(
    ip_address: str,
    user_agent: str,
    endpoint: str,
    method: str,
    headers: dict,
    payload: str,
    attack_type: str,
    severity: str = "Low",
    peer_ip: str = None,
    attribution_method: str = "direct_peer",
    attribution_status: str = "verified_peer",
    is_synthetic: bool = False
):
    """
    Logs an attack to SQLite, file logs, and optional remote admin webhook with provenance tracking.
    """
    effective_peer = peer_ip or ip_address
    # 1. Log to SQLite
    try:
        db = SessionLocal()
        new_log = AttackLog(
            ip_address=ip_address,
            peer_ip=effective_peer,
            attribution_method=attribution_method,
            attribution_status=attribution_status,
            is_synthetic=is_synthetic,
            user_agent=user_agent,
            endpoint=endpoint,
            method=method,
            headers=headers,
            payload=payload,
            attack_type=attack_type,
            severity=severity
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log)

        # Update persistent IP Threat Registry
        try:
            from threat_intel import record_threat_event
            record_threat_event(
                db, ip_address, attack_type, headers,
                peer_ip=effective_peer,
                attribution_method=attribution_method,
                attribution_status=attribution_status,
                is_synthetic=is_synthetic
            )
        except Exception as te:
            print(f"[-] Threat Registry Update Warning: {te}")

        db.close()
    except Exception as e:
        print(f"[-] SQLite Logging Error: {e}")

    # 2. Log to JSON
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "peer_ip": effective_peer,
        "attribution_method": attribution_method,
        "attribution_status": attribution_status,
        "is_synthetic": is_synthetic,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "method": method,
        "headers": headers,
        "payload": payload,
        "attack_type": attack_type,
        "severity": severity
    }
    
    try:
        with open("logs/attacks.json", "a") as f:
            f.write(json.dumps(log_data) + "\n")
    except Exception:
        pass
    
    # 3. Optional Remote Webhook Logging (Vercel -> Central Admin System)
    admin_url = os.getenv("ADMIN_SYSTEM_URL")
    if admin_url:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{admin_url.rstrip('/')}/api/remote-log",
                data=json.dumps(log_data).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            print(f"[-] Remote Admin Webhook Notice: {e}")

    logging.info(f"Attack Detected: {attack_type} from {ip_address} on {endpoint}")

