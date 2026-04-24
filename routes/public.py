import hashlib
import os
import shutil
from fastapi import APIRouter, Request, Form, UploadFile, File, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from detection import detect_attack
from logger import log_attack
from database import get_db
from models import MalwareMetadata
from sqlalchemy.orm import Session
from datetime import datetime
from ml_analysis.attack_classifier import AttackClassifier

# Initialize ML classifier
try:
    ml_classifier = AttackClassifier(model_path="ml_analysis/model.pkl")
except Exception as e:
    print(f"Warning: ML model not loaded: {e}")
    ml_classifier = None

router = APIRouter()
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "uploads"
QUARANTINE_DIR = "uploads/quarantine"

# Ensure directories exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="home.html")

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="forgot_password.html")

@router.post("/forgot-password")
async def handle_forgot_password(request: Request, email: str = Form(...)):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    attack_type = "none"
    if ml_classifier:
        ml_result = ml_classifier.classify_log(ip=ip, endpoint="/forgot-password", payload=f"email={email}", method="POST")
        attack_type = ml_result.get('predicted_attack_type', "none")
        if attack_type == "Normal Traffic":
            attack_type = "none"
    else:
        attack_type = detect_attack(email)
    
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/forgot-password",
        method="POST",
        headers=dict(request.headers),
        payload=f"email={email}",
        attack_type=attack_type if attack_type != "none" else "forgot_password_recon",
        severity="Low"
    )
    return templates.TemplateResponse(request=request, name="forgot_password.html", context={
        "message": "If this email exists in our system, a recovery link has been sent."
    })

@router.post("/contact")
async def handle_contact(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...)
):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    payload = f"name={name}, email={email}, message={message}"
    
    attack_type = "none"
    if ml_classifier:
        ml_result = ml_classifier.classify_log(ip=ip, endpoint="/contact", payload=payload, method="POST")
        attack_type = ml_result.get('predicted_attack_type', "none")
        if attack_type == "Normal Traffic":
            attack_type = "none"
    else:
        # Check all fields for attacks
        attacks = [detect_attack(name), detect_attack(email), detect_attack(message)]
        for a in attacks:
            if a != "none":
                attack_type = a
                break

    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/contact",
        method="POST",
        headers=dict(request.headers),
        payload=payload,
        attack_type=attack_type if attack_type != "none" else "contact_inquiry",
        severity="Medium" if attack_type != "none" else "Low"
    )
    return HTMLResponse("<h2>Thank you</h2><p>Your inquiry has been received. Our team will contact you shortly.</p>")

@router.post("/login")
async def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    payload = f"username={username}, password={password}"
    
    attack_type = "none"
    if ml_classifier:
        ml_result = ml_classifier.classify_log(ip=ip, endpoint="/login", payload=payload, method="POST")
        attack_type = ml_result.get('predicted_attack_type', "none")
        if attack_type == "Normal Traffic":
            attack_type = "none"
    else:
        # Check for attacks in username/password fields
        attack_username = detect_attack(username)
        attack_password = detect_attack(password)
        
        if attack_username != "none":
            attack_type = attack_username
        elif attack_password != "none":
            attack_type = attack_password
            
    if attack_type == "none":
        # If no specific injection, classify as brute force if they keep trying
        # For simplicity, we'll just log it as a login attempt
        attack_type = "brute_force_attempt"

    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/login",
        method="POST",
        headers=dict(request.headers),
        payload=payload,
        attack_type=attack_type,
        severity="Medium" if attack_type != "brute_force_attempt" else "Low"
    )

    # Honeypot behavior: Always fail or show a fake error to keep them trying
    return templates.TemplateResponse(request=request, name="login.html", context={
        "error": "Invalid credentials. This attempt has been logged for security."
    })

@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request=request, name="upload.html")

@router.post("/upload")
async def handle_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Read file content safely
    content = await file.read()
    file_size = len(content)
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Detection: Check filename and content for suspicious patterns
    attack_type = detect_attack(file.filename)
    if attack_type == "none":
        # Sample check for web shell signatures in content
        if b"<?php" in content or b"eval(" in content or b"base64_decode" in content:
            attack_type = "web_shell_detection"
        else:
            attack_type = "suspicious_file_upload"

    # Save to quarantine
    safe_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:8]}_{file.filename}"
    quarantine_path = os.path.join(QUARANTINE_DIR, safe_filename)
    
    with open(quarantine_path, "wb") as f:
        f.write(content)
    
    # Strict permissions: read-only for owner, none for others (in a real system)
    # os.chmod(quarantine_path, 0o400)

    # Log the upload attack
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/upload",
        method="POST",
        headers=dict(request.headers),
        payload=f"filename={file.filename}, hash={file_hash}, size={file_size}",
        attack_type=attack_type,
        severity="High"
    )

    # Store metadata
    metadata = MalwareMetadata(
        filename=file.filename,
        file_hash=file_hash,
        file_size=file_size,
        mime_type=file.content_type,
        source_ip=ip,
        quarantine_path=quarantine_path
    )
    db.add(metadata)
    db.commit()

    return JSONResponse(content={"status": "success", "message": "File uploaded and queued for validation."})

@router.get("/api/v1/user")
async def fake_api(request: Request):
    # Log any access to the fake API
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Check query params for attacks
    query_params = str(request.query_params)
    attack_type = detect_attack(query_params)
    
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/api/v1/user",
        method="GET",
        headers=dict(request.headers),
        payload=query_params,
        attack_type=attack_type if attack_type != "none" else "api_reconnaissance",
        severity="Low"
    )
    
    return {
        "id": 1,
        "username": "admin",
        "email": "admin@internal.system",
        "roles": ["superuser", "master_config"]
    }
