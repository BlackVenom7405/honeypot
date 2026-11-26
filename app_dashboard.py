import os
import hmac
import hashlib
import datetime
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

from database import engine, Base, SessionLocal
from models import AttackLog, MalwareMetadata
from auth import verify_session_token, authenticate_user, create_session_token, COOKIE_NAME
from source_attribution import normalize_ip_address
from routes import admin

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    try:
        yield
    finally:
        await admin.shutdown_realtime_stream()


app = FastAPI(
    title="BAITSCOPE Admin Console",
    description="BAITSCOPE Threat Operations Center & Forensic Management Console (Deceive. Detect. Investigate.).",
    version="5.0.0",
    lifespan=lifespan,
)

# Secure CORS: Default to localhost/same-origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8080", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Ensure folders exist
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# DB Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper function to get current admin user
def get_current_admin(request: Request) -> Optional[dict]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    user = verify_session_token(token)
    if not user or user.get("role") != "admin":
        return None
    return user

# ROUTES

@app.post("/api/remote-log")
async def receive_remote_log(request: Request, db: Session = Depends(get_db)):
    """
    Webhook for remote decoy nodes to forward threat telemetry.
    Strictly requires either a valid Bearer token matching SENTINEL_REMOTE_LOG_KEY
    or an authenticated admin session.
    """
    remote_log_key = os.getenv("BAITSCOPE_REMOTE_LOG_KEY") or os.getenv("SENTINEL_REMOTE_LOG_KEY")
    auth_header = request.headers.get("Authorization", "").strip()
    admin_user = get_current_admin(request)
    
    authorized = False
    if remote_log_key and auth_header.startswith("Bearer "):
        token_candidate = auth_header.split(" ", 1)[1].strip()
        if hmac.compare_digest(token_candidate, remote_log_key.strip()):
            authorized = True
    elif admin_user:
        authorized = True
        
    if not authorized:
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized remote logger: Valid Bearer token or Admin session required"}
        )
            
    try:
        data = await request.json()
        
        # 1. Reporting node actual TCP connection peer (never allow remote node to spoof this)
        reporting_peer_raw = request.client.host if (request.client and request.client.host) else "127.0.0.1"
        try:
            norm_reporting_peer, _ = normalize_ip_address(reporting_peer_raw)
        except Exception:
            norm_reporting_peer = reporting_peer_raw

        # 2. Reported attacker IP address (validate syntactically)
        raw_attacker_ip = str(data.get("ip_address", "Unknown")).strip()
        try:
            norm_attacker_ip, _ = normalize_ip_address(raw_attacker_ip)
        except Exception:
            norm_attacker_ip = raw_attacker_ip if raw_attacker_ip else "0.0.0.0"

        is_synthetic = bool(data.get("is_synthetic", False))

        new_log = AttackLog(
            ip_address=norm_attacker_ip,
            peer_ip=norm_reporting_peer,
            attribution_method="remote_node",
            attribution_status="remote_node_forwarded",
            is_synthetic=is_synthetic,
            user_agent=data.get("user_agent", "Unknown"),
            endpoint=data.get("endpoint", "/"),
            method=data.get("method", "GET"),
            headers=data.get("headers", {}),
            payload=data.get("payload", ""),
            attack_type=data.get("attack_type", "Suspicious Activity"),
            severity=data.get("severity", "Low")
        )
        db.add(new_log)
        db.commit()

        # Update persistent IP Threat Registry
        try:
            from threat_intel import record_threat_event
            record_threat_event(
                db, 
                norm_attacker_ip, 
                new_log.attack_type, 
                new_log.headers,
                peer_ip=norm_reporting_peer,
                attribution_method="remote_node",
                attribution_status="remote_node_forwarded",
                is_synthetic=is_synthetic
            )
        except Exception as te:
            pass

        return {"status": "success", "message": "Remote log received"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"status": "error", "message": str(e)})

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # If logged in as admin, go to dashboard, otherwise login
    admin_user = get_current_admin(request)
    if admin_user:
        return RedirectResponse(url="/admin", status_code=303)
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = "/admin", auth_required: Optional[str] = None):
    admin_user = get_current_admin(request)
    if admin_user:
        return RedirectResponse(url=next or "/admin", status_code=303)
        
    notice = "Secure admin authentication required to access BAITSCOPE Threat Center." if auth_required else None
    return templates.TemplateResponse(
        request=request, 
        name="login.html", 
        context={"next": next, "notice": notice, "is_dashboard": True}
    )

@app.post("/login")
async def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: Optional[str] = Form("/admin")
):
    # Authenticate against single configured admin identity with PBKDF2
    auth_result = authenticate_user(username, password)
    if auth_result and auth_result["role"] == "admin":
        token = create_session_token(auth_result["username"], auth_result["role"])
        target_url = next if next and next.startswith("/") else "/admin"
        response = RedirectResponse(url=target_url, status_code=303)
        
        # Check if running behind HTTPS or TLS termination
        is_https = (request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https")
        
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            secure=is_https,
            max_age=86400  # 24 hours
        )
        return response

    # If auth fails, return standard alert (do not log failed attempts on our monitoring port, only log attacks on decoy port)
    return templates.TemplateResponse(request=request, name="login.html", context={
        "error": "Invalid administrator credentials. Access Denied.",
        "next": next,
        "is_dashboard": True
    })

@app.get("/logout")
async def handle_logout(request: Request):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key=COOKIE_NAME, httponly=True, samesite="lax")
    return response

# Mount admin dashboard router
# We override dependency in route handlers to ensure only admin has access
@app.middleware("http")
async def require_admin_middleware(request: Request, call_next):
    # Exclude login, logout, static files, and remote webhook from standard session checks
    path = request.url.path
    if path in ["/login", "/logout", "/api/remote-log"] or path.startswith("/static") or path == "/":
        return await call_next(request)
        
    # All other paths require authenticated admin
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        if path.startswith("/admin/api/"):
            return JSONResponse(status_code=401, content={"error": "Unauthorized"})
        return RedirectResponse(url="/login?auth_required=1", status_code=303)
        
    user = verify_session_token(token)
    if not user or user.get("role") != "admin":
        if path.startswith("/admin/api/"):
            return JSONResponse(status_code=403, content={"error": "Forbidden - Admin clearance required"})
        return RedirectResponse(url="/login?error=Access+Denied+-+Admin+clearance+required", status_code=303)
        
    return await call_next(request)

app.include_router(admin.router)

if __name__ == "__main__":
    import uvicorn
    # Default to 127.0.0.1 to isolate management interface from public / LAN interfaces
    host = os.getenv("BAITSCOPE_DASHBOARD_HOST") or os.getenv("SENTINEL_DASHBOARD_HOST", "127.0.0.1")
    port = int(os.getenv("BAITSCOPE_DASHBOARD_PORT") or os.getenv("SENTINEL_DASHBOARD_PORT", "8080"))
    uvicorn.run("app_dashboard:app", host=host, port=port, reload=True)
