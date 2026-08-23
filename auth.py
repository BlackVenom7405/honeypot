import hmac
import hashlib
from typing import Optional, Dict
from fastapi import Request

SECRET_KEY = "gsi-sentinel-threat-intelligence-honeypot-key-2026"
COOKIE_NAME = "gsi_session"

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate against pre-configured Admin and Guest accounts.
    Returns user dict if valid, or None if invalid (honeypot will catch invalid attempts).
    """
    u = (username or "").strip().lower()
    p = (password or "").strip()
    
    # Administrator credentials
    if u in ["admin", "root", "sentinel"] and p in ["admin", "admin123", "password", "root", "sentinel123"]:
        return {
            "username": "admin",
            "role": "admin",
            "display_name": "Root Administrator"
        }
    
    # Guest credentials removed to ensure strict admin-only access
    return None

def create_session_token(username: str, role: str) -> str:
    """Create a signed HMAC session token."""
    payload = f"{username}:{role}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_session_token(token: str) -> Optional[Dict]:
    """Verify signed session token integrity."""
    if not token or ":" not in token:
        return None
    parts = token.split(":")
    if len(parts) != 3:
        return None
    username, role, sig = parts
    expected_sig = hmac.new(SECRET_KEY.encode(), f"{username}:{role}".encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected_sig):
        if role != "admin":
            return None
        return {
            "username": username,
            "role": "admin",
            "display_name": "Root Administrator"
        }
    return None

def get_current_user(request: Request) -> Optional[Dict]:
    """Extract and verify user from cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return verify_session_token(token)
