import os
import datetime
from typing import Optional
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import engine, Base, SessionLocal
from models import AttackLog, MalwareMetadata
from auth import verify_session_token, authenticate_user, create_session_token, COOKIE_NAME
from routes import admin

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Sentinel.X Admin Console",
    description="Threat Intelligence & Cyber Deception Center Dashboard.",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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
    try:
        data = await request.json()
        new_log = AttackLog(
            ip_address=data.get("ip_address", "Unknown"),
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
        return {"status": "success", "message": "Remote log received"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
        
    notice = "Secure admin authentication required to access Sentinel.X Threat Center." if auth_required else None
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
    # Only authenticate if they are actual root admin credentials
    auth_result = authenticate_user(username, password)
    if auth_result and auth_result["role"] == "admin":
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

    # If auth fails, return standard alert (do not log failed attempts on our monitoring port, only log attacks on decoy port)
    return templates.TemplateResponse(request=request, name="login.html", context={
        "error": "Invalid administrator credentials. Access Denied.",
        "next": next,
        "is_dashboard": True
    })

@app.get("/logout")
async def handle_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key=COOKIE_NAME)
    return response

# Mount admin dashboard router
# We override dependency in route handlers to ensure only admin has access
@app.middleware("http")
async def require_admin_middleware(request: Request, call_next):
    # Exclude login and static files from auth checks
    path = request.url.path
    if path in ["/login", "/logout"] or path.startswith("/static") or path == "/":
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
    uvicorn.run("app_dashboard:app", host="0.0.0.0", port=8080, reload=True)
