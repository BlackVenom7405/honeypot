import os
import time
import hmac
import hashlib
import logging
import secrets
from typing import Optional, Dict
from fastapi import Request
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()

# Configure logger
logger = logging.getLogger("baitscope.auth")

# Strict production enforcement flag (supports BAITSCOPE_STRICT_SECRETS with legacy SENTINEL_STRICT_SECRETS fallback)
STRICT_SECRETS = (os.getenv("BAITSCOPE_STRICT_SECRETS") or os.getenv("SENTINEL_STRICT_SECRETS", "0")).lower() in ("1", "true", "yes", "production")

# Admin HMAC session signing key
_env_secret = os.getenv("BAITSCOPE_ADMIN_SECRET_KEY") or os.getenv("SENTINEL_ADMIN_SECRET_KEY")
if not _env_secret:
    if STRICT_SECRETS:
        raise RuntimeError("CRITICAL STARTUP FAILURE: BAITSCOPE_ADMIN_SECRET_KEY (or legacy SENTINEL_ADMIN_SECRET_KEY) is required in strict/production mode.")
    logger.warning(
        "[!] SECURITY WARNING: BAITSCOPE_ADMIN_SECRET_KEY is not configured in environment (checked SENTINEL_ADMIN_SECRET_KEY fallback). "
        "Generating an ephemeral runtime secret. Active sessions will be invalidated on server restart."
    )
    SECRET_KEY = secrets.token_hex(32)
else:
    SECRET_KEY = _env_secret

COOKIE_NAME = "gsi_session"
SESSION_MAX_AGE_SECONDS = int(os.getenv("BAITSCOPE_SESSION_MAX_AGE") or os.getenv("SENTINEL_SESSION_MAX_AGE", "86400"))  # 24 hours default
PBKDF2_ITERATIONS = int(os.getenv("BAITSCOPE_PBKDF2_ITERATIONS") or os.getenv("SENTINEL_PBKDF2_ITERATIONS", "100000"))

# Single explicitly configured administrator identity
CONFIGURED_ADMIN_USER = (os.getenv("BAITSCOPE_ADMIN_USERNAME") or os.getenv("SENTINEL_ADMIN_USERNAME", "admin")).strip().lower()
CONFIGURED_ADMIN_SALT = (os.getenv("BAITSCOPE_ADMIN_SALT") or os.getenv("SENTINEL_ADMIN_SALT", "baitscope_admin_salt_2026")).strip()

def derive_password_hash(password: str, salt: str = CONFIGURED_ADMIN_SALT, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Derive secure PBKDF2-HMAC-SHA256 key with configurable iterations (default: 100,000; OWASP recommended: 600,000)."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations
    ).hex()

# Precompute expected password hash for the configured admin
_raw_pass_hash = os.getenv("BAITSCOPE_ADMIN_PASSWORD_HASH") or os.getenv("SENTINEL_ADMIN_PASSWORD_HASH")
_raw_password = os.getenv("BAITSCOPE_ADMIN_PASSWORD") or os.getenv("SENTINEL_ADMIN_PASSWORD")

if not _raw_password and not _raw_pass_hash:
    if STRICT_SECRETS:
        raise RuntimeError("CRITICAL STARTUP FAILURE: BAITSCOPE_ADMIN_PASSWORD/HASH (or legacy SENTINEL_ADMIN_PASSWORD/HASH) must be configured in strict/production mode.")
    _raw_password = "admin123"

if _raw_pass_hash:
    EXPECTED_ADMIN_HASH = _raw_pass_hash.strip().lower()
else:
    EXPECTED_ADMIN_HASH = derive_password_hash(_raw_password, CONFIGURED_ADMIN_SALT, PBKDF2_ITERATIONS)

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate against the single explicitly configured Administrator account.
    Uses PBKDF2-HMAC-SHA256 and constant-time comparison to prevent timing attacks.
    Returns user dict if valid, or None if invalid.
    """
    u = (username or "").strip().lower()
    p = (password or "").strip()
    
    # 1. Enforce strict single administrator username
    if not hmac.compare_digest(u, CONFIGURED_ADMIN_USER):
        return None
        
    # 2. Derive hash of supplied password and perform constant-time check
    supplied_hash = derive_password_hash(p, CONFIGURED_ADMIN_SALT, PBKDF2_ITERATIONS)
    if not hmac.compare_digest(supplied_hash, EXPECTED_ADMIN_HASH):
        return None
        
    return {
        "username": CONFIGURED_ADMIN_USER,
        "role": "admin",
        "display_name": "Root Administrator"
    }

def create_session_token(username: str, role: str) -> str:
    """Create a signed, timestamped HMAC-SHA256 session token."""
    ts = int(time.time())
    payload = f"{username}:{role}:{ts}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def verify_session_token(token: str) -> Optional[Dict]:
    """Verify signed session token integrity and freshness in constant time."""
    if not token or ":" not in token:
        return None
    parts = token.split(":")
    
    if len(parts) == 4:
        # Timestamped token: username:role:timestamp:sig
        username, role, ts_str, sig = parts
        try:
            ts = int(ts_str)
            if time.time() > ts + SESSION_MAX_AGE_SECONDS:
                return None  # Session expired
        except ValueError:
            return None
        payload = f"{username}:{role}:{ts_str}"
    elif len(parts) == 3:
        # Legacy non-timestamped token: username:role:sig
        username, role, sig = parts
        payload = f"{username}:{role}"
    else:
        return None
    
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    if hmac.compare_digest(sig, expected_sig):
        # Enforce single admin identity and admin role
        if role != "admin" or username != CONFIGURED_ADMIN_USER:
            return None
        return {
            "username": username,
            "role": "admin",
            "display_name": "Root Administrator"
        }
    return None

def get_current_user(request: Request) -> Optional[Dict]:
    """Extract and verify administrator user from session cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return verify_session_token(token)
