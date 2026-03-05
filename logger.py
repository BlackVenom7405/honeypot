import json
import logging
from datetime import datetime
from models import AttackLog
from database import SessionLocal

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
    severity: str = "Low"
):
    """
    Logs an attack to both SQLite and a JSON file.
    """
    # 1. Log to SQLite
    db = SessionLocal()
    new_log = AttackLog(
        ip_address=ip_address,
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
    db.close()

    # 2. Log to JSON
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "method": method,
        "headers": headers,
        "payload": payload,
        "attack_type": attack_type,
        "severity": severity
    }
    
    with open("logs/attacks.json", "a") as f:
        f.write(json.dumps(log_data) + "\n")
    
    # 3. Log to standard logger for ML dataset preparation
    with open("ml_dataset/raw_logs.csv", "a") as f:
        # Simple CSV row for ML
        f.write(f"{datetime.now().isoformat()},{ip_address},{attack_type},{payload[:100].replace(',', ' ')}\n")

    logging.info(f"Attack Detected: {attack_type} from {ip_address} on {endpoint}")
