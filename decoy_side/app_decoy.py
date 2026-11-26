import sys
import os

# Ensure current directory is at top of sys.path for Vercel Serverless
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
import hmac
import hashlib
import shutil
import datetime
import secrets
import logging
from typing import Optional, List
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

from database import engine, Base, SessionLocal
from models import User, DecoyPlaylist, AttackLog, MalwareMetadata
from detection import detect_attack
from logger import log_attack
from source_attribution import extract_source_attribution, SourceAttribution

logger = logging.getLogger("baitscope.decoy")

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="myTunes Web Player",
    description="Listen to music for everyone.",
    version="5.0.0"
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

# Secret key for signing decoy sessions
_decoy_secret = os.getenv("BAITSCOPE_DECOY_SECRET_KEY") or os.getenv("SENTINEL_DECOY_SECRET_KEY")
if not _decoy_secret:
    logger.warning(
        "[!] SECURITY WARNING: BAITSCOPE_DECOY_SECRET_KEY is not configured (checked SENTINEL_DECOY_SECRET_KEY fallback). "
        "Generating an ephemeral runtime secret for decoy sessions."
    )
    SECRET_KEY = secrets.token_hex(32)
else:
    SECRET_KEY = _decoy_secret

COOKIE_NAME = "decoy_session"
DECOY_SALT = os.getenv("BAITSCOPE_DECOY_SALT") or os.getenv("SENTINEL_DECOY_SALT", "decoy_spotify_salt_2026")
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 5 * 1024 * 1024))

# Helper function to hash passwords
def hash_password(password: str) -> str:
    return hashlib.sha256((password + DECOY_SALT).encode("utf-8")).hexdigest()

# Helper function to get client IP using trustworthy proxy extraction
def get_client_ip(request: Request) -> str:
    try:
        return extract_source_attribution(request).client_ip
    except Exception:
        return request.client.host if (request and request.client) else "127.0.0.1"

def check_and_enforce_rate_limit(request: Request, db: Session, bucket: str, limit: int, window_sec: int = 60) -> Optional[Response]:
    """
    Applies SQLite-backed rate limiting per IP and bucket.
    If exceeded, logs attack and returns HTTP 429 response with provenance fields.
    """
    try:
        from threat_intel import check_rate_limit
        attr = extract_source_attribution(request)
        client_ip = attr.client_ip
        allowed, count, retry_after = check_rate_limit(db, client_ip, bucket, limit, window_sec)
        if not allowed:
            log_attack(
                ip_address=client_ip,
                user_agent=request.headers.get("user-agent", "Unknown"),
                endpoint=f"{request.url.path} (Rate Limit Exceeded)",
                method=request.method,
                headers=dict(request.headers),
                payload=f"Bucket: {bucket}, Hit limit: {count}/{limit} req in {window_sec}s",
                attack_type="Rate Limit Exceeded",
                severity="Medium",
                peer_ip=attr.peer_ip,
                attribution_method=attr.attribution_method,
                attribution_status=attr.attribution_status,
                is_synthetic=attr.is_synthetic
            )
            return JSONResponse(
                status_code=429,
                content={"error": "Too Many Requests. Rate limit exceeded.", "retry_after": retry_after},
                headers={"Retry-After": str(retry_after)}
            )
    except Exception:
        pass
    return None

# Session tokens
def create_decoy_token(username: str) -> str:
    payload = f"{username}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_decoy_token(token: str) -> Optional[str]:
    if not token or ":" not in token:
        return None
    parts = token.split(":")
    if len(parts) != 2:
        return None
    username, sig = parts
    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), username.encode("utf-8"), hashlib.sha256).hexdigest()
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
        attr = extract_source_attribution(request)
        ua = request.headers.get("user-agent", "Unknown")
        headers = dict(request.headers)
        log_attack(
            ip_address=attr.client_ip,
            user_agent=ua,
            endpoint=f"{request.url.path} ({location})",
            method=request.method,
            headers=headers,
            payload=payload,
            attack_type=attack_type,
            severity=severity,
            peer_ip=attr.peer_ip,
            attribution_method=attr.attribution_method,
            attribution_status=attr.attribution_status,
            is_synthetic=attr.is_synthetic
        )
        return True
    return False

# --- TASK 2: Secure Upload Helpers ---
def sanitize_upload_filename(filename: str) -> str:
    """Sanitize user-provided filename to prevent directory traversal and remove unsafe chars."""
    if not filename:
        return "unnamed_upload.bin"
    # Strip any directory path components (both UNIX / and Windows \)
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes and non-printable control characters
    clean = re.sub(r'[\x00-\x1f\x7f]', '', base)
    # Strip leading/trailing dots and spaces
    clean = clean.strip(". ")
    # Replace dangerous characters with underscores
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', clean)
    if not clean:
        clean = "sanitized_upload.bin"
    return clean

async def read_bounded_upload(file: UploadFile, max_size: int = MAX_UPLOAD_SIZE) -> tuple[bytes, bool]:
    """Read file content in bounded chunks (64 KB) to prevent Out-Of-Memory (OOM) DoS."""
    chunks = []
    total = 0
    chunk_size = 64 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_size:
            return b"", True
        chunks.append(chunk)
    return b"".join(chunks), False

def save_quarantined_file(original_filename: str, content: bytes) -> str:
    """
    Saves suspicious payload into quarantine directory with cryptographic randomness.
    Strictly verifies destination path remains contained inside QUARANTINE_DIR
    using canonical resolved filesystem paths (realpath & commonpath).
    """
    sanitized = sanitize_upload_filename(original_filename)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    rand_token = secrets.token_hex(4)
    safe_filename = f"{timestamp}_{rand_token}_{sanitized}"
    
    quarantine_real = os.path.realpath(QUARANTINE_DIR)
    os.makedirs(quarantine_real, exist_ok=True)
    target_real = os.path.realpath(os.path.join(quarantine_real, safe_filename))
    
    # Resolved filesystem containment verification (defense-in-depth against symlinks / reparse points)
    try:
        is_contained = (
            os.path.commonpath([quarantine_real, target_real]) == quarantine_real
            and target_real != quarantine_real
        )
    except ValueError:
        is_contained = False
        
    if not is_contained or not target_real.startswith(quarantine_real + os.sep):
        raise ValueError(f"Path traversal detected: {target_real} outside {quarantine_real}")
        
    with open(target_real, "wb") as f:
        f.write(content)
        
    # Return normalized relative path for database storage
    return os.path.relpath(target_real, os.getcwd())

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
        request=request,
        name="decoy_home.html", 
        context={
            "user": user, 
            "user_playlists": playlists,
            "message": message,
            "error": error
        }
    )

@app.get("/signup", response_class=HTMLResponse)
async def signup_get(request: Request):
    return templates.TemplateResponse(request=request, name="decoy_signup.html", context={})

@app.post("/signup")
async def signup_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    rate_err = check_and_enforce_rate_limit(request, db, "signup", limit=20, window_sec=60)
    if rate_err:
        return rate_err

    # Check inputs for attacks
    if check_and_log_attack(request, username, "Signup username"):
        return templates.TemplateResponse(request=request, name="decoy_signup.html", context={"error": "Database error code: X09A. Registration halted."})
    if check_and_log_attack(request, email, "Signup email"):
        return templates.TemplateResponse(request=request, name="decoy_signup.html", context={"error": "Invalid email formatting validation error."})
    if check_and_log_attack(request, password, "Signup password"):
        return templates.TemplateResponse(request=request, name="decoy_signup.html", context={"error": "Password fails custom security criteria."})

    # Check if user already exists
    existing_user = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="decoy_signup.html", context={"error": "Email or username is already registered."})

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
    is_https = (request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https")
    response.set_cookie(key=COOKIE_NAME, value=token, httponly=True, samesite="lax", secure=is_https)
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    error = request.query_params.get("error")
    return templates.TemplateResponse(request=request, name="decoy_login.html", context={"error": error})

# Global tracker for failed decoy login attempts by IP
decoy_login_failures = {}

@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    rate_err = check_and_enforce_rate_limit(request, db, "login", limit=20, window_sec=60)
    if rate_err:
        return rate_err

    attr = extract_source_attribution(request)
    ip_addr = attr.client_ip
    
    # Check for SQL injection signature in username or password
    is_attack = False
    if check_and_log_attack(request, username, "Login username"):
        is_attack = True
    if check_and_log_attack(request, password, "Login password"):
        is_attack = True

    if is_attack:
        # Deceptive return for attackers
        return templates.TemplateResponse(request=request, name="decoy_login.html", context={"error": "Invalid username or password."})

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
                severity="Medium",
                peer_ip=attr.peer_ip,
                attribution_method=attr.attribution_method,
                attribution_status=attr.attribution_status,
                is_synthetic=attr.is_synthetic
            )
        return templates.TemplateResponse(request=request, name="decoy_login.html", context={"error": "Incorrect username or password."})

    # Successful Login: reset failures
    decoy_login_failures[ip_addr] = 0
    token = create_decoy_token(username)
    response = RedirectResponse(url="/?message=Logged in successfully.", status_code=303)
    is_https = (request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https")
    response.set_cookie(key=COOKIE_NAME, value=token, httponly=True, samesite="lax", secure=is_https)
    return response

@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/?message=Logged out successfully.", status_code=303)
    response.delete_cookie(COOKIE_NAME, httponly=True, samesite="lax")
    return response

@app.get("/search")
async def decoy_search(request: Request, q: str = "", db: Session = Depends(get_db)):
    rate_err = check_and_enforce_rate_limit(request, db, "search", limit=60, window_sec=60)
    if rate_err:
        return rate_err

    user = get_current_decoy_user(request, db)
    
    # Intercept attack signatures
    if check_and_log_attack(request, q, "Search query"):
        # Deceptive clean output: show no results found so the attacker is not notified
        playlists = []
        if user:
            playlists = db.query(DecoyPlaylist).filter(DecoyPlaylist.user_id == user.id).all()
        return templates.TemplateResponse(
            request=request,
            name="decoy_home.html",
            context={"user": user, "user_playlists": playlists, "q": q, "error": f"No results found for '{q}'."}
        )

    playlists = []
    if user:
        playlists = db.query(DecoyPlaylist).filter(DecoyPlaylist.user_id == user.id).all()
    
    # Simulated search response
    return templates.TemplateResponse(
        request=request,
        name="decoy_home.html",
        context={"user": user, "user_playlists": playlists, "q": q, "message": f"Showing results for '{q}'."}
    )

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

    original_filename = file.filename or "avatar.bin"
    
    # Bounded chunk read with max size check (prevents OOM DoS)
    content, is_exceeded = await read_bounded_upload(file)
    if is_exceeded:
        return RedirectResponse(url="/?error=File size exceeds maximum allowable limit (5MB).", status_code=303)

    # Check for malicious Web Shell signatures
    is_malicious = False
    reasons = []
    
    # 1. File extension checking
    ext = os.path.splitext(original_filename)[1].lower()
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
        attr = extract_source_attribution(request)
        ip_addr = attr.client_ip
        ua = request.headers.get("user-agent", "Unknown")

        # Isolated sandboxed save with strict path containment
        quarantine_path = save_quarantined_file(original_filename, content)

        # Log malware metadata
        sanitized_display_name = sanitize_upload_filename(original_filename)
        new_malware = MalwareMetadata(
            filename=sanitized_display_name,
            file_hash=sha256,
            file_size=file_size,
            mime_type=mime_type,
            source_ip=ip_addr,
            peer_ip=attr.peer_ip,
            attribution_method=attr.attribution_method,
            attribution_status=attr.attribution_status,
            is_synthetic=attr.is_synthetic,
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
            payload=f"filename={sanitized_display_name}, reasons={', '.join(reasons)}",
            attack_type="Web Shell Detection",
            severity="High",
            peer_ip=attr.peer_ip,
            attribution_method=attr.attribution_method,
            attribution_status=attr.attribution_status,
            is_synthetic=attr.is_synthetic
        )
        db.commit()

        # Deceptive return response to keep the attacker blind
        return RedirectResponse(url="/?message=Profile picture updated successfully!", status_code=303)

    # Safe file path (mock upload success)
    return RedirectResponse(url="/?message=Profile picture updated successfully!", status_code=303)

# LEGACY DECOY ROUTES (For backwards compatibility with penetration testing & simulation)

@app.post("/upload")
async def legacy_upload(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Legacy Web Shell decoy endpoint targeted by automated simulations."""
    original_filename = file.filename or "upload.bin"
    
    # Bounded read
    content, is_exceeded = await read_bounded_upload(file)
    if is_exceeded:
        return JSONResponse(status_code=413, content={"error": "File exceeds maximum permitted size of 5MB."})

    sha256 = hashlib.sha256(content).hexdigest()
    file_size = len(content)
    mime_type = file.content_type or "application/octet-stream"
    attr = extract_source_attribution(request)
    ip_addr = attr.client_ip
    ua = request.headers.get("user-agent", "Unknown")
    
    # Safe quarantine save with containment check
    quarantine_path = save_quarantined_file(original_filename, content)
    sanitized_display_name = sanitize_upload_filename(original_filename)

    new_malware = MalwareMetadata(
        filename=sanitized_display_name,
        file_hash=sha256,
        file_size=file_size,
        mime_type=mime_type,
        source_ip=ip_addr,
        peer_ip=attr.peer_ip,
        attribution_method=attr.attribution_method,
        attribution_status=attr.attribution_status,
        is_synthetic=attr.is_synthetic,
        quarantine_path=quarantine_path
    )
    db.add(new_malware)
    
    log_attack(
        ip_address=ip_addr,
        user_agent=ua,
        endpoint="/upload (Legacy Decoy)",
        method="POST",
        headers=dict(request.headers),
        payload=f"filename={sanitized_display_name}",
        attack_type="Web Shell Detection",
        severity="High",
        peer_ip=attr.peer_ip,
        attribution_method=attr.attribution_method,
        attribution_status=attr.attribution_status,
        is_synthetic=attr.is_synthetic
    )
    db.commit()
    
    return JSONResponse(status_code=200, content={"message": "File uploaded and queued for validation."})

@app.post("/contact")
async def legacy_contact(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(get_db)
):
    """Legacy XSS contact decoy endpoint targeted by the original simulation."""
    rate_err = check_and_enforce_rate_limit(request, db, "contact", limit=30, window_sec=60)
    if rate_err:
        return rate_err

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

    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("[!] SSL certificates missing. Generating self-signed TLS certificate and key...")
        from generate_ssl import generate_self_signed_cert
        generate_self_signed_cert()

    def is_port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) == 0

    default_port = int(os.getenv("BAITSCOPE_DECOY_PORT") or os.getenv("SENTINEL_DECOY_PORT", "443"))
    fallback_port = int(os.getenv("BAITSCOPE_DECOY_FALLBACK_PORT") or os.getenv("SENTINEL_DECOY_FALLBACK_PORT", "8443"))

    port = default_port
    if is_port_in_use(port):
        print(f"Port {port} is already in use. Falling back to port {fallback_port}...")
        port = fallback_port

    try:
        uvicorn.run("app_decoy:app", host="0.0.0.0", port=port, ssl_keyfile="key.pem", ssl_certfile="cert.pem", reload=False)
    except BaseException as e:
        if port == default_port:
            print(f"Port {port} binding failed ({e}). Attempting fallback to port {fallback_port}...")
            uvicorn.run("app_decoy:app", host="0.0.0.0", port=fallback_port, ssl_keyfile="key.pem", ssl_certfile="cert.pem", reload=False)
        else:
            raise
