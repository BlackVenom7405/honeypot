# Sentinel.X - Standalone Decoy Node Deployment Guide

This directory (`decoy_side/`) contains the complete, self-contained **myTunes Decoy Honeypot Website**. You can copy this entire folder to any remote machine, VM, or container to capture attack vectors over network HTTPS and view the logged threats on your central Sentinel.X Admin System.

---

## 🚀 Quick Start (Running Locally or Remotely)

### 1. Requirements
Ensure Python 3.8+ is installed on the host/target machine.

Install required dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launch the Decoy Site
Run the standalone decoy launcher:
```bash
python start_decoy.py
```
*(Or run `python app_decoy.py` directly)*

- The decoy site automatically starts on **Port 443 (HTTPS)**.
- If Port 443 is blocked or requires elevated permissions on Linux/Windows, it automatically falls back to **Port 8443 (HTTPS)**.

---

## 🛡️ Firewall Configuration

To allow external machines or attackers on your LAN/network to reach the decoy site, run the following PowerShell command as Administrator on the decoy host:

```powershell
New-NetFirewallRule -DisplayName "Honeypot Decoy Ports" -Direction Inbound -LocalPort 443,8443 -Protocol TCP -Action Allow
```

*(Refer to `firewall_rules.txt` for options to enable, disable, or remove firewall rules)*.

---

## 📊 Viewing Captured Attacks

All attacks targeted at this decoy node (SQL Injection, XSS, Path Traversal, Brute Force attempts after 4 failures, and Web Shell uploads) are automatically intercepted, logged, and quarantined:

1. **Local Database**: Saved in `database/honeypot.db` under `AttackLog` and `MalwareMetadata`.
2. **Central Admin Dashboard**:
   - Access the dashboard at `http://<ADMIN_IP>:8080/admin`.
   - Logged threats will automatically render live statistics, IP attack maps, threat category charts, and quarantined file logs.

---

## 📁 Directory Structure

- `app_decoy.py`: Standalone Decoy FastAPI / Uvicorn HTTPS server.
- `start_decoy.py`: Auto-checking launcher script.
- `detection.py`: Pattern detection rules (SQLi, XSS, Path Traversal, Web Shells, Brute Force WAF).
- `models.py` & `database.py`: SQLAlchemy database models.
- `auth.py`: User registration & session authentication engine.
- `logger.py`: Threat logging helper.
- `static/`: Complete myTunes CSS styles, JS assets, images, and audio tracks.
- `templates/`: HTML templates (`decoy_home.html`, `decoy_login.html`, `decoy_signup.html`).
- `database/`: SQLite database storage (`honeypot.db`).
- `uploads/`: Quarantined malware uploads folder.
- `cert.pem` & `key.pem`: Self-signed SSL certificate pair.
