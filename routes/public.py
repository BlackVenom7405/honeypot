import hashlib
import os
import shutil
from typing import Optional
from fastapi import APIRouter, Request, Form, UploadFile, File, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from detection import detect_attack
from logger import log_attack
from database import get_db
from models import MalwareMetadata
from sqlalchemy.orm import Session
from datetime import datetime
from auth import authenticate_user, create_session_token, get_current_user, COOKIE_NAME

router = APIRouter()
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "uploads"
QUARANTINE_DIR = "uploads/quarantine"

# Ensure directories exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def get_client_ip(request: Request) -> str:
    """Extract client IP from X-Forwarded-For, X-Real-IP, or direct connection."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="home.html")

@router.get("/client-portal")
async def client_portal_direct(request: Request):
    """
    Direct 1-click access for guests & clients.
    Automatically sets guest session and redirects straight to the guest-redacted dashboard.
    """
    user = get_current_user(request)
    if user and user["role"] == "admin":
        return RedirectResponse(url="/admin", status_code=303)
        
    token = create_session_token("guest", "guest")
    response = RedirectResponse(url="/admin", status_code=303)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400  # 24 hours
    )
    return response

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = "/admin", auth_required: Optional[str] = None):
    user = get_current_user(request)
    # If already logged in as admin, go straight to admin dashboard
    if user and user["role"] == "admin":
        return RedirectResponse(url=next or "/admin", status_code=303)
        
    notice = "Admin authentication required to access Threat Center with full unredacted clearance." if auth_required else None
    return templates.TemplateResponse(
        request=request, 
        name="login.html", 
        context={"next": next, "notice": notice}
    )

# Global tracker for failed admin login attempts by IP
admin_login_failures = {}

@router.post("/login")
async def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: Optional[str] = Form("/admin")
):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    payload = f"username={username}, password={password}"
    
    # 1. Check for valid Admin authentication
    auth_result = authenticate_user(username, password)
    if auth_result:
        # Reset counter on success
        admin_login_failures[ip] = 0
        token = create_session_token(auth_result["username"], auth_result["role"])
        target_url = next if next and next.startswith("/") else "/admin"
        response = RedirectResponse(url=target_url, status_code=303)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=86400  # 24 hours
        )
        return response

    # 2. If invalid credentials, treat as Honeypot deception & log threat
    detected_user = detect_attack(username)
    detected_pass = detect_attack(password)
    
    should_log = True
    if detected_user != "none":
        attack_type = detected_user
        severity = "High" if attack_type == "SQL Injection" else "Medium"
    elif detected_pass != "none":
        attack_type = detected_pass
        severity = "High" if attack_type == "SQL Injection" else "Medium"
    else:
        attack_type = "Brute Force"
        severity = "Medium"
        # Increment failed attempt count
        admin_login_failures[ip] = admin_login_failures.get(ip, 0) + 1
        # Only log to dashboard if attempts >= 4
        if admin_login_failures[ip] >= 4:
            admin_login_failures[ip] = 0  # Reset counter
        else:
            should_log = False

    if should_log:
        log_attack(
            ip_address=ip,
            user_agent=user_agent,
            endpoint="/login",
            method="POST",
            headers=dict(request.headers),
            payload=payload,
            attack_type=attack_type,
            severity=severity
        )

    # Return deceptive honeypot error response
    return templates.TemplateResponse(request=request, name="login.html", context={
        "error": "Invalid administrator credentials. Security incident recorded in Sentinel threat matrix.",
        "next": next
    })

@router.get("/logout")
async def handle_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key=COOKIE_NAME)
    return response

@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="forgot_password.html")

@router.post("/forgot-password")
async def handle_forgot_password(request: Request, email: str = Form(...)):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    
    detected = detect_attack(email)
    if detected != "none":
        attack_type = detected
        severity = "High" if detected == "SQL Injection" else "Medium"
    else:
        attack_type = "Brute Force"
        severity = "Low"
    
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/forgot-password",
        method="POST",
        headers=dict(request.headers),
        payload=f"email={email}",
        attack_type=attack_type,
        severity=severity
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
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    payload = f"name={name}, email={email}, message={message}"
    
    # Check all fields for attack signatures
    detected = "none"
    for field in [name, email, message]:
        d = detect_attack(field)
        if d != "none":
            detected = d
            break

    if detected != "none":
        attack_type = detected
        severity = "High" if detected == "SQL Injection" else "Medium"
    else:
        attack_type = "XSS" if ("<" in payload or ">" in payload) else "Brute Force"
        severity = "Low"

    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/contact",
        method="POST",
        headers=dict(request.headers),
        payload=payload,
        attack_type=attack_type,
        severity=severity
    )
    return HTMLResponse("<h2>Thank you</h2><p>Your inquiry has been received. Our team will contact you shortly.</p>")

@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request=request, name="upload.html")

@router.post("/upload")
async def handle_upload(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Read file content safely
    content = await file.read()
    file_size = len(content)
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Detect Web Shell signatures or Path Traversal in filename
    detected = detect_attack(file.filename)
    if detected == "Path Traversal":
        attack_type = "Path Traversal"
        severity = "High"
    elif (b"<?php" in content or b"eval(" in content or b"system(" in content or 
          b"base64_decode" in content or file.filename.lower().endswith(('.php', '.phtml', '.php5', '.jsp', '.asp', '.aspx', '.sh', '.py'))):
        attack_type = "Web Shell Detection"
        severity = "High"
    else:
        attack_type = "Web Shell Detection"
        severity = "Medium"

    # Save to quarantine
    safe_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:8]}_{file.filename}"
    quarantine_path = os.path.join(QUARANTINE_DIR, safe_filename)
    
    with open(quarantine_path, "wb") as f:
        f.write(content)

    # Log the upload attack
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/upload",
        method="POST",
        headers=dict(request.headers),
        payload=f"filename={file.filename}, hash={file_hash}, size={file_size}",
        attack_type=attack_type,
        severity=severity
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
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    query_params = str(request.query_params)
    
    detected = detect_attack(query_params)
    if detected != "none":
        attack_type = detected
        severity = "High" if detected == "SQL Injection" else "Medium"
    else:
        if "file=" in query_params or ".." in query_params:
            attack_type = "Path Traversal"
            severity = "Medium"
        else:
            attack_type = "Path Traversal"
            severity = "Low"
    
    log_attack(
        ip_address=ip,
        user_agent=user_agent,
        endpoint="/api/v1/user",
        method="GET",
        headers=dict(request.headers),
        payload=query_params,
        attack_type=attack_type,
        severity=severity
    )
    
    return {
        "id": 1,
        "username": "admin",
        "email": "admin@internal.system",
        "roles": ["superuser", "master_config"]
    }
