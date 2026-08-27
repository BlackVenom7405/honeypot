import sys
import os

# Ensure current directory is at top of sys.path for Vercel Serverless
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
import hmac
import hashlib
import shutil
import datetime
from typing import Optional, List
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import engine, Base, SessionLocal
from models import User, DecoyPlaylist, AttackLog, MalwareMetadata
from detection import detect_attack
from logger import log_attack

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="myTunes Web Player",
    description="Listen to music for everyone.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure directories exist (serverless safe)
QUARANTINE_DIR = "/tmp/uploads/quarantine" if os.getenv("VERCEL") else "uploads/quarantine"
try:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs("static/decoy", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
except Exception:
    pass

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Secret key for signing sessions
SECRET_KEY = "decoy-spotify-session-secret-key-2026"
COOKIE_NAME = "decoy_session"

# Helper function to hash passwords
def hash_password(password: str) -> str:
    salt = "decoy_spotify_salt_2026"
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Helper function to get client IP
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"

# Session tokens
def create_decoy_token(username: str) -> str:
    payload = f"{username}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_decoy_token(token: str) -> Optional[str]:
    if not token or ":" not in token:
        return None
    parts = token.split(":")
    if len(parts) != 2:
        return None
    username, sig = parts
    expected_sig = hmac.new(SECRET_KEY.encode(), username.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected_sig):
        return username
    return None

# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Get current logged-in decoy user
def get_current_decoy_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    username = verify_decoy_token(token)
    if not username:
        return None
    return db.query(User).filter(User.username == username).first()

# Intercept and log attacks helper
def check_and_log_attack(request: Request, payload: str, location: str) -> bool:
    attack_type = detect_attack(payload)
    if attack_type != "none":
        severity = "High" if attack_type in ["SQL Injection", "Path Traversal"] else "Medium"
        ip_addr = get_client_ip(request)
        ua = request.headers.get("user-agent", "Unknown")
        headers = dict(request.headers)
        log_attack(
            ip_address=ip_addr,
            user_agent=ua,
            endpoint=f"{request.url.path} ({location})",
            method=request.method,
            headers=headers,
            payload=payload,
            attack_type=attack_type,
            severity=severity
        )
        return True
    return False

# ROUTES

@app.get("/", response_class=HTMLResponse)
async def decoy_home(request: Request, db: Session = Depends(get_db)):
    user = get_current_decoy_user(request, db)
    playlists = []
    if user:
        playlists = db.query(DecoyPlaylist).filter(DecoyPlaylist.user_id == user.id).all()
    
    # Check for query messages
    message = request.query_params.get("message")
    error = request.query_params.get("error")
    
    return templates.TemplateResponse(
        "decoy_home.html", 
        {
            "request": request, 
            "user": user, 
            "user_playlists": playlists,
            "message": message,
            "error": error
        }
    )

@app.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request):
    return templates.TemplateResponse("decoy_signup.html", {"request": request})

@app.post("/signup")
async def signup_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check inputs for attacks
    if check_and_log_attack(request, username, "Signup username"):
        return templates.TemplateResponse("decoy_signup.html", {"request": request, "error": "Database error code: X09A. Registration halted."})
    if check_and_log_attack(request, email, "Signup email"):
        return templates.TemplateResponse("decoy_signup.html", {"request": request, "error": "Invalid email formatting validation error."})
    if check_and_log_attack(request, password, "Signup password"):
        return templates.TemplateResponse("decoy_signup.html", {"request": request, "error": "Password fails custom security criteria."})

    # Check if user already exists
    existing_user = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse("decoy_signup.html", {"request": request, "error": "Email or username is already registered."})

    # Create new user
    new_user = User(
        username=username,
        email=email,
        password_hash=hash_password(password)
    )
    db.add(new_user)
    db.commit()

    # Automatically set cookie session
    token = create_decoy_token(username)
    response = RedirectResponse(url="/?message=Registration successful! Welcome to myTunes.", status_code=303)
    response.set_cookie(key=COOKIE_NAME, value=token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse("decoy_login.html", {"request": request, "error": error})

# Global tracker for failed decoy login attempts by IP
decoy_login_failures = {}

@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    ip_addr = get_client_ip(request)
    
    # Check for SQL injection signature in username or password
    is_attack = False
    if check_and_log_attack(request, username, "Login username"):
        is_attack = True
    if check_and_log_attack(request, password, "Login password"):
        is_attack = True

    if is_attack:
        # Deceptive return for attackers
        return templates.TemplateResponse("decoy_login.html", {"request": request, "error": "Invalid username or password."})

    # Authenticate user
    user = db.query(User).filter(User.username == username).first()
    if not user or user.password_hash != hash_password(password):
        # Increment failed attempt count
        decoy_login_failures[ip_addr] = decoy_login_failures.get(ip_addr, 0) + 1
        
        # Log this failed attempt to the dashboard as a Brute Force threat only on/after the 4th attempt
        if decoy_login_failures[ip_addr] >= 4:
            decoy_login_failures[ip_addr] = 0  # Reset counter
            ua = request.headers.get("user-agent", "Unknown")
            log_attack(
                ip_address=ip_addr,
                user_agent=ua,
                endpoint="/login (Credential verification)",
                method="POST",
                headers=dict(request.headers),
                payload=f"username={username}",
                attack_type="Brute Force",
                severity="Medium"
            )
        return templates.TemplateResponse("decoy_login.html", {"request": request, "error": "Incorrect username or password."})

    # Successful Login: reset failures
    decoy_login_failures[ip_addr] = 0
    token = create_decoy_token(username)
    response = RedirectResponse(url="/?message=Logged in successfully.", status_code=303)
    response.set_cookie(key=COOKIE_NAME, value=token, httponly=True)
    return response

@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/?message=Logged out successfully.", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.get("/search")
async def decoy_search(request: Request, q: str = "", db: Session = Depends(get_db)):
    user = get_current_decoy_user(request, db)
    
    # Intercept attack signatures
    if check_and_log_attack(request, q, "Search query"):
        # Deceptive clean output: show no results found so the attacker is not notified
        playlists = []
        if user:
            playlists = db.query(DecoyPlaylist).filter(DecoyPlaylist.user_id == user.id).all()
        return templates.TemplateResponse("decoy_home.html", {"request": request, "user": user, "user_playlists": playlists, "q": q, "error": f"No results found for '{q}'."})

    playlists = []
    if user:
        playlists = db.query(DecoyPlaylist).filter(DecoyPlaylist.user_id == user.id).all()
    
    # Simulated search response
    return templates.TemplateResponse("decoy_home.html", {"request": request, "user": user, "user_playlists": playlists, "q": q, "message": f"Showing results for '{q}'."})

@app.post("/create-playlist")
async def decoy_create_playlist(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_decoy_user(request, db)
    if not user:
        return RedirectResponse(url="/login?error=Please log in to create a playlist.", status_code=303)

    # Check for XSS or other attacks in the playlist name
    if check_and_log_attack(request, name, "Playlist Name"):
        # Deceptively "succeed" by creating a sanitized decoy playlist to avoid alert
        sanitized_name = "New Playlist"
        new_pl = DecoyPlaylist(name=sanitized_name, user_id=user.id)
        db.add(new_pl)
        db.commit()
        return RedirectResponse(url="/?message=Playlist created successfully!", status_code=303)

    new_pl = DecoyPlaylist(name=name, user_id=user.id)
    db.add(new_pl)
    db.commit()
    return RedirectResponse(url="/?message=Playlist created successfully!", status_code=303)

@app.post("/upload-avatar")
async def decoy_upload_avatar(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    user = get_current_decoy_user(request, db)
    if not user:
        return RedirectResponse(url="/login?error=Please log in to change your avatar.", status_code=303)

    filename = file.filename
    content = await file.read()
    
    # Check for malicious Web Shell signatures
    is_malicious = False
    reasons = []
    
    # 1. File extension checking
    ext = os.path.splitext(filename)[1].lower()
    if ext in [".php", ".phtml", ".php5", ".asp", ".aspx", ".jsp", ".jspx", ".pl", ".py", ".sh"]:
        is_malicious = True
        reasons.append(f"Executable extension: {ext}")
        
    # 2. File content checking (signatures)
    content_str = ""
    try:
        content_str = content.decode("utf-8", errors="ignore").lower()
    except Exception:
        pass
        
    shell_signatures = [
        "<?php", "eval(", "system(", "exec(", "shell_exec(", "passthru(", "base64_decode(",
        "cmd.exe", "/bin/sh", "/bin/bash", "request.getparameter", "multipart/form-data"
    ]
    for sig in shell_signatures:
        if sig in content_str:
            is_malicious = True
            reasons.append(f"Web Shell signature: {sig}")

    if is_malicious:
        # Calculate SHA256 of payload
        sha256 = hashlib.sha256(content).hexdigest()
        file_size = len(content)
        mime_type = file.content_type or "application/octet-stream"
        ip_addr = get_client_ip(request)
        ua = request.headers.get("user-agent", "Unknown")

        # Isolated sandboxed save
        quarantine_filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
        with open(quarantine_path, "wb") as f:
            f.write(content)

        # Log malware
        new_malware = MalwareMetadata(
            filename=filename,
            file_hash=sha256,
            file_size=file_size,
            mime_type=mime_type,
            source_ip=ip_addr,
            quarantine_path=quarantine_path
        )
        db.add(new_malware)
        
        # Log attack vector
        log_attack(
            ip_address=ip_addr,
            user_agent=ua,
            endpoint=f"/upload-avatar (File Upload)",
            method="POST",
            headers=dict(request.headers),
            payload=f"filename={filename}, reasons={', '.join(reasons)}",
            attack_type="Web Shell Detection",
            severity="High"
        )
        db.commit()

        # Deceptive return response to keep the attacker blind
        return RedirectResponse(url="/?message=Profile picture updated successfully!", status_code=303)

    # Safe file path (mock upload success)
    return RedirectResponse(url="/?message=Profile picture updated successfully!", status_code=303)

# LEGACY DEC_OY ROUTES (For backwards compatibility with simulate_attacks.py)

@app.post("/upload")
async def legacy_upload(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Legacy Web Shell decoy endpoint targeted by the original simulation."""
    filename = file.filename
    content = await file.read()
    
    sha256 = hashlib.sha256(content).hexdigest()
    file_size = len(content)
    mime_type = file.content_type or "application/octet-stream"
    ip_addr = get_client_ip(request)
    ua = request.headers.get("user-agent", "Unknown")
    
    quarantine_filename = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
    with open(quarantine_path, "wb") as f:
        f.write(content)

    new_malware = MalwareMetadata(
        filename=filename,
        file_hash=sha256,
        file_size=file_size,
        mime_type=mime_type,
        source_ip=ip_addr,
        quarantine_path=quarantine_path
    )
    db.add(new_malware)
    
    log_attack(
        ip_address=ip_addr,
        user_agent=ua,
        endpoint="/upload (Legacy Decoy)",
        method="POST",
        headers=dict(request.headers),
        payload=f"filename={filename}",
        attack_type="Web Shell Detection",
        severity="High"
    )
    db.commit()
    
    return JSONResponse(status_code=200, content={"message": "File uploaded and queued for validation."})

@app.post("/contact")
async def legacy_contact(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...)
):
    """Legacy XSS contact decoy endpoint targeted by the original simulation."""
    check_and_log_attack(request, name, "Contact Name")
    check_and_log_attack(request, email, "Contact Email")
    check_and_log_attack(request, message, "Contact Message")
    return JSONResponse(status_code=200, content={"message": "Your message has been sent successfully."})

@app.get("/api/v1/user")
async def legacy_user_api(request: Request):
    """Legacy Path Traversal decoy endpoint targeted by the original simulation."""
    file_param = request.query_params.get("file", "")
    check_and_log_attack(request, file_param, "User API File Parameter")
    return JSONResponse(status_code=200, content={"id": 1, "username": "guest_analyst", "email": "guest@gsi-integrity.com"})

if __name__ == "__main__":
    import uvicorn
    import socket

    def is_port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    port = 443
    if is_port_in_use(443):
        print("Port 443 is already in use. Falling back to port 8443...")
        port = 8443

    try:
        uvicorn.run("app_decoy:app", host="0.0.0.0", port=port, ssl_keyfile="key.pem", ssl_certfile="cert.pem", reload=False)
    except BaseException as e:
        if port == 443:
            print(f"Port 443 binding failed ({e}). Attempting fallback to port 8443...")
            uvicorn.run("app_decoy:app", host="0.0.0.0", port=8443, ssl_keyfile="key.pem", ssl_certfile="cert.pem", reload=False)
        else:
            raise
