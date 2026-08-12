# ⌬ Sentinel.X — Autonomous Cyber Deception Grid & Threat Intelligence Center

<p align="center">
  <img src="static/favicon.svg" alt="Sentinel.X Logo" width="96" height="96">
</p>

<p align="center">
  <strong>Next-Generation Honeynet &amp; Autonomous Threat Intelligence Platform</strong><br>
  Built with FastAPI, TailwindCSS, Chart.js, SQLite, and ReportLab.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-yellow?style=for-the-badge&logo=shield" alt="Version 2.0.0">
  <img src="https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/TailwindCSS-Neo--Brutalist-06B6D4?style=for-the-badge&logo=tailwindcss" alt="TailwindCSS">
  <img src="https://img.shields.io/badge/Zero--Trust-Architecture-success?style=for-the-badge" alt="Zero Trust">
</p>

---

## 📌 Overview

**Sentinel.X** is a high-interaction web honeypot and cyber deception platform designed to lure, detect, profile, and quarantine adversarial attack vectors in real time. 

By presenting convincing decoy services (authentication gateways, configuration file uploaders, credential recovery workflows, and fake REST APIs), **Sentinel.X** extracts threat telemetry, generates forensic SHA-256 hashes, classifies attack signatures, and visualizes live threat intelligence on a high-contrast Sentinel Operational Deck.

---

## ✨ Key Features

### 🛡️ 1. Multi-Vector Attack Detection & Heuristic Classifier
Real-time payload inspection categorizes inbound threats into five major vectors:
* **SQL Injection (SQLi)**: Detects boolean/union-based payloads (e.g. `' OR '1'='1`, `UNION SELECT`).
* **Cross-Site Scripting (XSS)**: Identifies script tags, event handlers, and injected HTML markup.
* **Directory Path Traversal**: Catches path escape sequences (e.g. `../../etc/passwd`, `..\windows\win.ini`).
* **Brute Force & Credential Stuffing**: Tracks repeated dictionary attacks against auth gateways.
* **Web Shell Detection**: Inspects file contents for PHP/JSP/ASP/Shell backdoors (`eval()`, `system()`, `base64_decode()`, `<?php`).

### ☣️ 2. Sandbox Malware Quarantine Vault
* **Cryptographic Hashing**: Automatically calculates SHA-256 hashes for all uploaded payloads.
* **Isolated Containment**: Quarantines uploaded files into an isolated directory (`uploads/quarantine/`) with immutable timestamped filenames—completely isolated from server kernels.
* **Forensic Metadata**: Preserves file size, MIME type, source IP, timestamp, and quarantine path in SQLite.

### 🌐 3. High-Interaction Decoy Traps
* **Landing Portal (`/`)**: High-tech brutalist landing page with live telemetry, metrics, and moving radar scanner.
* **Client Portal (`/client-portal`)**: 1-click instant access for guests and clients with automated sensitive data redaction.
* **Admin Gateway (`/login`)**: Root Administrator login challenge protected by session authentication.
* **Specification Upload (`/upload`)**: Decoy internal configuration tool that lures adversaries attempting arbitrary file uploads.
* **Auth Recovery (`/forgot-password`)**: Deceptive password reset form capturing credential enumeration attacks.
* **REST API Endpoint (`/api/v1/user`)**: Decoy user endpoint recording path traversal and parameter tampering attempts.

### 📊 4. Sentinel Operational Deck (`/admin`)
* **Live Vector Distribution Chart**: Dynamic Chart.js bar chart categorizing real-time attack frequency.
* **360° Conic Sweep Radar**: Interactive animated scanner with orbital threat blips color-coded by severity.
* **Live Incident Feed**: Chronological table displaying timestamp, origin IP, targeted endpoint, classification badge, and severity.
* **Traffic Analysis Tab**: Searchable, filterable log inspector with vector filtering and full header inspection.
* **Malware Laboratory Tab**: Vault of isolated binaries with click-to-copy SHA-256 hashes and quarantine path details.
* **Attack Vectors Taxonomy**: Interactive mitigation matrix detailing signatures, target endpoints, and mitigation protocols.

### 🔒 5. Role-Based Access Control (RBAC) & Redaction
| Feature | 🛡️ Root Admin | 👁️ Guest Analyst / Client |
| :--- | :---: | :---: |
| **Access Method** | Credentials (`admin` / `admin123`) | 1-Click (`/client-portal`) |
| **Source IP Addresses** | Full Raw IP (e.g. `192.168.1.104`) | Masked (e.g. `192.168.***.***`) |
| **Payload Details** | Full Raw Payload Inspection | `[REDACTED - GUEST CLEARANCE]` |
| **User-Agent Forensics** | Full Browser Signature | `[REDACTED]` |
| **Log Downloads** | PDF, JSON, CSV, TXT | Locked (Permission Required) |
| **Malware Sample Download** | Direct Quarantine Retrieval | Disabled |

### 🎨 6. Clean Light & Dark Mode Toggle
* Integrated theme toggle button with Sun / Moon icons across all pages.
* Zero-FOUC (Flash of Unstyled Content) initial render via immediate `<head>` script.
* Persistent theme preference saved in `localStorage`.
* Chart.js, radar canvas, data tables, and modal dialogs dynamically adapt text and grid colors.

### 📄 7. Automated Executive Forensic Reporting
* **Executive PDF Threat Report**: One-click professional multi-page PDF generated via ReportLab with executive summaries, vector breakdown charts, and mitigation strategies.
* **JSON Structured Stream**: Full structured telemetry export.
* **CSV Threat Dataset**: Standard tabular format ready for SIEM ingestion and machine learning pipelines.
* **Raw TXT Dump**: Line-by-line plaintext forensic log format.

---

## 📁 Project Structure

```plaintext
honeypot/
├── app.py                      # FastAPI application entry point & router mounting
├── auth.py                     # Role-based auth (Admin vs Guest), session tokens & hashing
├── database.py                 # SQLAlchemy database session & SQLite engine configuration
├── detection.py                # Regex & heuristic signature detection engine
├── logger.py                   # Threat logging controller for SQLite & JSON stores
├── models.py                   # ORM data models (AttackLog, MalwareMetadata)
├── report_generator.py         # Multi-format report exporter (PDF, CSV, JSON, TXT)
├── simulate_attacks.py         # Multi-vector attack generator for testing & demos
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git tracking exclusion rules
├── static/
│   └── favicon.svg             # Sentinel.X cyber aperture SVG logo
├── routes/
│   ├── public.py               # Public decoy endpoints & authentication routes
│   └── admin.py                # Admin dashboard routes, stats API & log exports
├── templates/
│   ├── home.html               # Main landing page with moving radar & telemetry
│   ├── admin.html              # Sentinel.X Threat Intelligence Center (Dashboard)
│   ├── login.html              # Administrator authentication gate
│   ├── upload.html             # Malware sandbox upload decoy
│   └── forgot_password.html    # Credential reset decoy trap
├── uploads/
│   └── quarantine/             # Sandboxed directory for trapped malware samples
└── logs/                       # Persistent JSON & raw log archives
```

---

## 🚀 Quickstart Guide

### Prerequisites
* Python 3.9+ installed on your system.
* pip package manager.

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/BlackVenom7405/honeypot.git
cd honeypot

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Server
```bash
python app.py
```
The server will start at `http://localhost:8000` with hot-reloading enabled.

---

## 🔑 Default Credentials & Access Endpoints

| Portal | URL | Credentials / Access |
| :--- | :--- | :--- |
| **Home Page** | `http://localhost:8000/` | Public |
| **Client Portal (Guest View)** | `http://localhost:8000/client-portal` | **1-Click Direct Access** (No login required) |
| **Admin Login** | `http://localhost:8000/login` | `admin` / `admin123` |
| **Threat Intelligence Deck** | `http://localhost:8000/admin` | Requires Admin or Guest Session |
| **Decoy Upload Trap** | `http://localhost:8000/upload` | Public Decoy |
| **Auth Recovery Decoy** | `http://localhost:8000/forgot-password` | Public Decoy |

---

## 💥 Simulating Multi-Vector Attacks

To generate realistic attack traffic against your honeypot and view real-time data on the dashboard:

```bash
python simulate_attacks.py
```

This script simulates 5 adversarial vectors:
1. `SQL Injection` on `/login` (`' OR '1'='1`)
2. `Cross-Site Scripting (XSS)` on `/contact` (`<script>alert(1)</script>`)
3. `Directory Path Traversal` on `/api/v1/user` (`../../etc/passwd`)
4. `Brute Force Attempt` on `/login` (Dictionary credential guessing)
5. `Web Shell Upload` on `/upload` (`r57_shell.php`)

---

## 🐳 Docker Deployment

To run Sentinel.X inside an isolated container:

```bash
# Build the Docker image
docker build -t sentinel-x -f docker/Dockerfile .

# Run the container
docker run -d -p 8000:8000 --name sentinel_honeypot sentinel-x
```

---

## ⚖️ Security Notice
This software is designed as a **cyber deception honeynet**. Any malware samples uploaded to the decoy endpoints are quarantined in an unexecuted state. Do not disable quarantine sandboxing or execute files located in `uploads/quarantine/`.

---

## 📜 License
This project is open-source under the MIT License. Built for security researchers, SOC analysts, and cybersecurity enthusiasts.
