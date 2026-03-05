# CyberGuard Honeypot System

A lightweight, FastAPI-based web honeypot designed to detect, log, and analyze malicious web activity.

## Features
- **Deceptive Frontend**: Mimics vulnerable login and file upload interfaces.
- **Attack Detection**: identifies SQLi, XSS, Path Traversal, and Command Injection.
- **Malware Quarantine**: Safely stores uploaded files with SHA256 hashing.
- **Live Admin Dashboard**: Real-time visualization of threats using Chart.js.
- **ML Ready**: Logs are stored in JSON and CSV formats for future machine learning analysis.
- **Security Isolation**: Designed to run inside Docker.

## Setup Instructions

### Local Setup
1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the Application**:
   ```bash
   python app.py
   ```
3. **Access the Honeypot**:
   - Public Interface: `http://localhost:8000/login`
   - Admin Dashboard: `http://localhost:8000/admin`

### Docker Setup
1. **Build the Image**:
   ```bash
   docker build -t honeypot -f docker/Dockerfile .
   ```
2. **Run the Container**:
   ```bash
   docker run -p 8000:8000 honeypot
   ```

## Attack Simulation
To test the system, run the included simulation script:
```bash
python simulate_attacks.py
```

## Project Structure
- `app.py`: Main entry point.
- `routes/`: Public and Admin API endpoints.
- `templates/`: HTML pages (Login, Upload, Admin).
- `logs/`: Attack logs (JSON and text).
- `uploads/quarantine/`: Safely stored malware samples.
- `ml_dataset/`: CSV logs for machine learning.
