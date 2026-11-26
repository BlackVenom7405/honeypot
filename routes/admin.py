import asyncio
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
import database
from database import get_db
from models import AttackLog, MalwareMetadata, IPThreatRegistry, RateLimitRecord
from report_generator import generate_pdf_report
from auth import get_current_user

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="templates")

# Server launch timestamp for real-time uptime calculation
SERVER_START_TIME = datetime.utcnow()

ACTIVE_VECTOR_NAMES = (
    "SQL Injection",
    "XSS",
    "Path Traversal",
    "Brute Force",
    "Web Shell Detection",
)
SSE_PAYLOAD_PREVIEW_LIMIT = 256
FORBIDDEN_QUERY_SECRET_PARAMS = frozenset(
    {"token", "auth", "secret", "password", "passwd", "api_key", "apikey", "key", "session", "cookie"}
)


def mask_ip_address(ip: str) -> str:
    """Mask IP address for guest users (e.g., 192.168.1.100 -> 192.168.***.***)."""
    if not ip or ip == "unknown":
        return "unknown"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    if ":" in ip:  # IPv6
        return ip.split(":")[0] + ":****:****:****"
    return "***.***.***.***"


def normalize_attack_vector(raw_type: Optional[str]) -> str:
    """Map raw database attack_type values to active canonical vectors or Legacy (Retired)."""
    tl = (raw_type or "").lower()
    if "command" in tl:
        return "Legacy (Retired)"
    if "sql" in tl:
        return "SQL Injection"
    if "xss" in tl:
        return "XSS"
    if "traversal" in tl or "api" in tl:
        return "Path Traversal"
    if "shell" in tl or "upload" in tl:
        return "Web Shell Detection"
    return "Brute Force"


def serialize_attack_log(
    log: AttackLog,
    is_guest: bool = False,
    max_payload_len: Optional[int] = None,
    watchlisted_set: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Serialize an AttackLog ORM row cleanly with optional payload truncation and guest redaction."""
    raw_payload = log.payload or ""
    if is_guest:
        ip_display = mask_ip_address(log.ip_address)
        peer_display = mask_ip_address(log.peer_ip or log.ip_address)
        payload_display = "[REDACTED - GUEST CLEARANCE]" if raw_payload else ""
        payload_truncated = False
        ua_display = "Standard Browser Client (Sanitized)" if log.user_agent else "unknown"
    else:
        ip_display = log.ip_address
        peer_display = log.peer_ip or log.ip_address
        if max_payload_len is not None and len(raw_payload) > max_payload_len:
            payload_display = raw_payload[:max_payload_len]
            payload_truncated = True
        else:
            payload_display = raw_payload
            payload_truncated = False
        ua_display = log.user_agent or "unknown"

    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat() if log.timestamp else datetime.utcnow().isoformat(),
        "ip_address": ip_display,
        "peer_ip": peer_display,
        "attribution_method": log.attribution_method or "direct_peer",
        "attribution_status": log.attribution_status or "verified_peer",
        "is_synthetic": bool(log.is_synthetic),
        "endpoint": log.endpoint,
        "method": log.method or "POST",
        "attack_type": normalize_attack_vector(log.attack_type),
        "severity": log.severity,
        "payload": payload_display,
        "payload_truncated": payload_truncated,
        "user_agent": ua_display,
        "is_watchlisted": bool(watchlisted_set and log.ip_address in watchlisted_set),
    }


def serialize_malware_item(m: MalwareMetadata, is_guest: bool = False) -> Dict[str, Any]:
    """Serialize a MalwareMetadata ORM row cleanly with guest redaction when required."""
    if is_guest:
        source_ip_display = mask_ip_address(m.source_ip)
        peer_display = mask_ip_address(m.peer_ip or m.source_ip)
        quarantine_path_display = "[RESTRICTED VAULT ACCESS]"
        hash_display = (m.file_hash[:12] + "..." + m.file_hash[-6:]) if m.file_hash else ""
    else:
        source_ip_display = m.source_ip
        peer_display = m.peer_ip or m.source_ip
        quarantine_path_display = m.quarantine_path or "uploads/quarantine/"
        hash_display = m.file_hash

    return {
        "filename": m.filename,
        "file_hash": hash_display,
        "file_size": m.file_size or 0,
        "mime_type": m.mime_type or "application/octet-stream",
        "source_ip": source_ip_display,
        "peer_ip": peer_display,
        "attribution_method": m.attribution_method or "direct_peer",
        "attribution_status": m.attribution_status or "verified_peer",
        "is_synthetic": bool(m.is_synthetic),
        "quarantine_path": quarantine_path_display,
        "timestamp": m.timestamp.isoformat() if m.timestamp else datetime.utcnow().isoformat(),
    }


def compute_uptime_metrics(now_utc: Optional[datetime] = None) -> Tuple[str, int]:
    """Compute formatted dashboard uptime string and integer seconds."""
    current = now_utc or datetime.utcnow()
    total_seconds = max(0, int((current - SERVER_START_TIME).total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        formatted = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        formatted = f"{minutes}m {seconds}s"
    else:
        formatted = f"{seconds}s"
    return formatted, total_seconds


def compute_status_from_last_attack(
    last_timestamp: Optional[datetime],
    last_severity: Optional[str],
    now_utc: Optional[datetime] = None,
) -> Tuple[str, str, str, int]:
    """Compute live threat level state, color token, uptime pct, and elapsed seconds."""
    current = now_utc or datetime.utcnow()
    sec_since_attack = 999999
    if last_timestamp:
        sec_since_attack = max(0, int((current - last_timestamp).total_seconds()))

    if sec_since_attack <= 15:
        if str(last_severity or "").lower() == "high":
            return "UNDER ATTACK", "danger", "97.80%", sec_since_attack
        return "INTERCEPTING", "warning", "98.95%", sec_since_attack
    if sec_since_attack <= 45:
        return "MITIGATING", "accent", "99.45%", sec_since_attack
    return "NOMINAL", "success", "99.99%", sec_since_attack


def build_active_distribution(db: Session) -> Dict[str, int]:
    """Compute grouped 5-vector distribution counts while excluding retired Command Injection rows."""
    distribution: Dict[str, int] = {name: 0 for name in ACTIVE_VECTOR_NAMES}
    rows = db.query(AttackLog.attack_type, func.count(AttackLog.attack_type)).group_by(AttackLog.attack_type).all()
    for raw_type, count in rows:
        vec = normalize_attack_vector(raw_type)
        if vec in distribution:
            distribution[vec] += count
    return distribution


def get_watchlisted_ip_set(db: Session) -> Set[str]:
    """Return the exact set of attributed IP addresses currently flagged on the watchlist."""
    rows = db.query(IPThreatRegistry.ip_address).filter(IPThreatRegistry.is_watchlisted == True).all()
    return {r[0] for r in rows if r and r[0]}


def compute_dashboard_metrics(
    db: Session,
    latest_row: Optional[AttackLog] = None,
    watchlisted_set: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Compute shared dashboard KPIs, 5-vector distribution, status, and threat intel counts."""
    total_attacks = db.query(func.count(AttackLog.id)).scalar() or 0
    unique_ips = db.query(AttackLog.ip_address).distinct().count()
    total_malware = db.query(func.count(MalwareMetadata.id)).scalar() or 0
    distribution = build_active_distribution(db)

    now_utc = datetime.utcnow()
    uptime_formatted, uptime_seconds = compute_uptime_metrics(now_utc)
    if latest_row is None and total_attacks > 0:
        latest_row = db.query(AttackLog).order_by(AttackLog.timestamp.desc(), AttackLog.id.desc()).first()

    last_ts = latest_row.timestamp if latest_row else None
    last_sev = latest_row.severity if latest_row else "Low"
    system_status, status_color, uptime_percentage, sec_since_attack = compute_status_from_last_attack(
        last_ts, last_sev, now_utc
    )

    wl_set = watchlisted_set if watchlisted_set is not None else get_watchlisted_ip_set(db)
    total_tracked_ips = db.query(func.count(IPThreatRegistry.id)).scalar() or 0
    repeat_offenders = db.query(func.count(IPThreatRegistry.id)).filter(IPThreatRegistry.total_events > 1).scalar() or 0
    watchlisted_ips = len(wl_set)
    classifications = {
        "Critical": db.query(func.count(IPThreatRegistry.id)).filter(IPThreatRegistry.threat_classification == "Critical").scalar() or 0,
        "High": db.query(func.count(IPThreatRegistry.id)).filter(IPThreatRegistry.threat_classification == "High").scalar() or 0,
        "Medium": db.query(func.count(IPThreatRegistry.id)).filter(IPThreatRegistry.threat_classification == "Medium").scalar() or 0,
        "Low": db.query(func.count(IPThreatRegistry.id)).filter(IPThreatRegistry.threat_classification == "Low").scalar() or 0,
    }

    return {
        "total_attacks": total_attacks,
        "unique_ips": unique_ips,
        "total_malware": total_malware,
        "distribution": distribution,
        "system_status": system_status,
        "status_color": status_color,
        "uptime_percentage": uptime_percentage,
        "uptime_formatted": uptime_formatted,
        "uptime_seconds": uptime_seconds,
        "sec_since_attack": sec_since_attack,
        "threat_intel": {
            "total_tracked_ips": total_tracked_ips,
            "repeat_offenders": repeat_offenders,
            "watchlisted_ips": watchlisted_ips,
            "classification_counts": classifications,
        },
    }


def _apply_guest_redaction_to_event(event: Dict[str, Any], is_guest: bool) -> Dict[str, Any]:
    """Return subscriber-safe event copy without mutating shared event payload."""
    if not is_guest:
        return event
    data = dict(event.get("data", {}))
    if "attacks" in data:
        redacted_attacks = []
        for item in data["attacks"]:
            copy_item = dict(item)
            copy_item["ip_address"] = mask_ip_address(copy_item.get("ip_address", ""))
            copy_item["peer_ip"] = mask_ip_address(copy_item.get("peer_ip", ""))
            if copy_item.get("payload"):
                copy_item["payload"] = "[REDACTED - GUEST CLEARANCE]"
            copy_item["payload_truncated"] = False
            copy_item["user_agent"] = "Standard Browser Client (Sanitized)"
            redacted_attacks.append(copy_item)
        data["attacks"] = redacted_attacks
    if "malware" in data and data["malware"] is not None:
        redacted_mal = []
        for m in data["malware"]:
            copy_m = dict(m)
            copy_m["source_ip"] = mask_ip_address(copy_m.get("source_ip", ""))
            copy_m["peer_ip"] = mask_ip_address(copy_m.get("peer_ip", ""))
            copy_m["quarantine_path"] = "[RESTRICTED VAULT ACCESS]"
            fh = copy_m.get("file_hash") or ""
            copy_m["file_hash"] = (fh[:12] + "..." + fh[-6:]) if fh else ""
            redacted_mal.append(copy_m)
        data["malware"] = redacted_mal
    return {"event": event["event"], "id": event["id"], "data": data}


class RealtimeStreamBroker:
    """
    Shared single-producer SQLite delta observer and multi-client SSE fan-out broker.
    Runs a single background DB polling loop only while >=1 subscriber is connected,
    executing synchronous SQLAlchemy checks on a worker thread.
    """

    def __init__(self, poll_interval: float = 0.25, heartbeat_interval: float = 15.0):
        self._poll_interval = poll_interval
        self._heartbeat_interval = heartbeat_interval
        self._subscribers: Dict[int, Tuple[asyncio.Queue, bool]] = {}
        self._next_sub_id = 1
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._watcher_task: Optional[asyncio.Task] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._last_attack_id: int = 0
        self._last_attack_count: int = 0
        self._last_malware_id: int = 0
        self._last_malware_count: int = 0
        self._last_attack_ts: Optional[datetime] = None
        self._last_attack_severity: str = "Low"
        self._last_emitted_status: str = "NOMINAL"
        self._last_watchlisted_ips: Set[str] = set()
        self._baseline_ready = False

    def _ensure_loop_state(self) -> asyncio.AbstractEventLoop:
        running = asyncio.get_running_loop()
        if self._loop is not running:
            # Handle TestClient / multi-loop lifecycles cleanly without cross-loop Future errors
            self._subscribers.clear()
            self._watcher_task = None
            self._shutdown_event = asyncio.Event()
            self._loop = running
            self._baseline_ready = False
        elif self._shutdown_event is None:
            self._shutdown_event = asyncio.Event()
        elif self._shutdown_event.is_set() and not self._subscribers:
            self._shutdown_event = asyncio.Event()
        return running

    def _query_initial_state(self, last_event_id: Optional[int], is_guest: bool) -> Dict[str, Any]:
        db = database.SessionLocal()
        try:
            max_id, total_attacks = db.query(
                func.coalesce(func.max(AttackLog.id), 0),
                func.count(AttackLog.id),
            ).one()
            max_mal_id, total_malware = db.query(
                func.coalesce(func.max(MalwareMetadata.id), 0),
                func.count(MalwareMetadata.id),
            ).one()
            latest_row = db.query(AttackLog).order_by(AttackLog.timestamp.desc(), AttackLog.id.desc()).first()
            watchlisted_set = get_watchlisted_ip_set(db)
            metrics = compute_dashboard_metrics(db, latest_row=latest_row, watchlisted_set=watchlisted_set)

            self._last_attack_id = int(max_id or 0)
            self._last_attack_count = int(total_attacks or 0)
            self._last_malware_id = int(max_mal_id or 0)
            self._last_malware_count = int(total_malware or 0)
            self._last_attack_ts = latest_row.timestamp if latest_row else None
            self._last_attack_severity = (latest_row.severity or "Low") if latest_row else "Low"
            self._last_emitted_status = metrics["system_status"]
            self._last_watchlisted_ips = set(watchlisted_set)
            self._baseline_ready = True

            if last_event_id is None:
                return {
                    "event": "connected",
                    "id": self._last_attack_id,
                    "data": {
                        "status": "connected",
                        "last_id": self._last_attack_id,
                        "metrics": metrics,
                        "server_time": datetime.utcnow().isoformat(),
                    },
                }

            if self._last_attack_count == 0 and last_event_id > 0:
                return {
                    "event": "reset",
                    "id": 0,
                    "data": {
                        "last_id": 0,
                        "attacks": [],
                        "malware": [],
                        "metrics": metrics,
                    },
                }

            if self._last_attack_id < last_event_id:
                return {
                    "event": "reset",
                    "id": self._last_attack_id,
                    "data": {
                        "last_id": self._last_attack_id,
                        "attacks": [],
                        "malware": [],
                        "metrics": metrics,
                    },
                }

            if self._last_attack_id > last_event_id:
                missed = (
                    db.query(AttackLog)
                    .filter(AttackLog.id > last_event_id)
                    .order_by(AttackLog.id.asc())
                    .limit(100)
                    .all()
                )
                serialized = [
                    serialize_attack_log(
                        r,
                        is_guest=is_guest,
                        max_payload_len=SSE_PAYLOAD_PREVIEW_LIMIT,
                        watchlisted_set=watchlisted_set,
                    )
                    for r in missed
                ]
                mal_rows = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).limit(50).all()
                return {
                    "event": "attack",
                    "id": serialized[-1]["id"] if serialized else self._last_attack_id,
                    "data": {
                        "last_id": serialized[-1]["id"] if serialized else self._last_attack_id,
                        "attacks": serialized,
                        "malware": [serialize_malware_item(m, is_guest=is_guest) for m in mal_rows],
                        "metrics": metrics,
                    },
                }

            return {
                "event": "connected",
                "id": self._last_attack_id,
                "data": {
                    "status": "connected",
                    "last_id": self._last_attack_id,
                    "metrics": metrics,
                    "server_time": datetime.utcnow().isoformat(),
                },
            }
        finally:
            db.close()

    def _poll_db_changes(self) -> Optional[Dict[str, Any]]:
        db = database.SessionLocal()
        try:
            max_id, total_attacks = db.query(
                func.coalesce(func.max(AttackLog.id), 0),
                func.count(AttackLog.id),
            ).one()
            max_mal_id, total_malware = db.query(
                func.coalesce(func.max(MalwareMetadata.id), 0),
                func.count(MalwareMetadata.id),
            ).one()

            max_id = int(max_id or 0)
            total_attacks = int(total_attacks or 0)
            max_mal_id = int(max_mal_id or 0)
            total_malware = int(total_malware or 0)

            attack_changed = (max_id != self._last_attack_id) or (total_attacks != self._last_attack_count)
            malware_changed = (max_mal_id != self._last_malware_id) or (total_malware != self._last_malware_count)
            watchlisted_set = get_watchlisted_ip_set(db)
            watchlist_changed = (watchlisted_set != self._last_watchlisted_ips)

            if not attack_changed and not malware_changed and not watchlist_changed:
                # Check in-memory Threat Level decay transitions (UNDER ATTACK -> MITIGATING -> NOMINAL) without full scans
                if self._last_emitted_status != "NOMINAL":
                    now_utc = datetime.utcnow()
                    cur_status, cur_color, cur_pct, cur_sec = compute_status_from_last_attack(
                        self._last_attack_ts, self._last_attack_severity, now_utc
                    )
                    if cur_status != self._last_emitted_status:
                        self._last_emitted_status = cur_status
                        uptime_fmt, uptime_sec = compute_uptime_metrics(now_utc)
                        return {
                            "event": "metrics",
                            "id": self._last_attack_id,
                            "data": {
                                "last_id": self._last_attack_id,
                                "metrics": {
                                    "system_status": cur_status,
                                    "status_color": cur_color,
                                    "uptime_percentage": cur_pct,
                                    "uptime_formatted": uptime_fmt,
                                    "uptime_seconds": uptime_sec,
                                    "sec_since_attack": cur_sec,
                                },
                            },
                        }
                return None

            # Detect history clear / DB reset across processes
            if (total_attacks == 0 and self._last_attack_count > 0) or max_id < self._last_attack_id:
                metrics = compute_dashboard_metrics(db, latest_row=None, watchlisted_set=watchlisted_set)
                self._last_attack_id = max_id
                self._last_attack_count = total_attacks
                self._last_malware_id = max_mal_id
                self._last_malware_count = total_malware
                self._last_attack_ts = None
                self._last_attack_severity = "Low"
                self._last_emitted_status = metrics["system_status"]
                self._last_watchlisted_ips = set(watchlisted_set)
                return {
                    "event": "reset",
                    "id": max_id,
                    "data": {
                        "last_id": max_id,
                        "attacks": [],
                        "malware": [],
                        "metrics": metrics,
                    },
                }

            new_rows: List[AttackLog] = []
            if max_id > self._last_attack_id:
                new_rows = (
                    db.query(AttackLog)
                    .filter(AttackLog.id > self._last_attack_id)
                    .order_by(AttackLog.id.asc())
                    .limit(100)
                    .all()
                )

            latest_row = new_rows[-1] if new_rows else db.query(AttackLog).order_by(AttackLog.timestamp.desc(), AttackLog.id.desc()).first()
            metrics = compute_dashboard_metrics(db, latest_row=latest_row, watchlisted_set=watchlisted_set)
            serialized_attacks = [
                serialize_attack_log(
                    r,
                    is_guest=False,
                    max_payload_len=SSE_PAYLOAD_PREVIEW_LIMIT,
                    watchlisted_set=watchlisted_set,
                )
                for r in new_rows
            ]

            malware_payload = None
            if malware_changed:
                mal_rows = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).limit(50).all()
                malware_payload = [serialize_malware_item(m, is_guest=False) for m in mal_rows]

            self._last_attack_id = serialized_attacks[-1]["id"] if serialized_attacks else max_id
            self._last_attack_count = total_attacks
            self._last_malware_id = max_mal_id
            self._last_malware_count = total_malware
            self._last_watchlisted_ips = set(watchlisted_set)
            if latest_row:
                self._last_attack_ts = latest_row.timestamp
                self._last_attack_severity = latest_row.severity or "Low"
            self._last_emitted_status = metrics["system_status"]

            return {
                "event": "attack" if serialized_attacks else "metrics",
                "id": self._last_attack_id,
                "data": {
                    "last_id": self._last_attack_id,
                    "attacks": serialized_attacks,
                    "malware": malware_payload,
                    "metrics": metrics,
                },
            }
        finally:
            db.close()

    def _enqueue_to_all(self, event: Dict[str, Any]) -> None:
        for _, (q, is_guest) in list(self._subscribers.items()):
            payload = _apply_guest_redaction_to_event(event, is_guest)
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def _watcher_loop(self) -> None:
        try:
            while self._subscribers and self._shutdown_event and not self._shutdown_event.is_set():
                try:
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=self._poll_interval)
                    break
                except asyncio.TimeoutError:
                    pass
                if not self._subscribers:
                    break
                try:
                    event = await asyncio.to_thread(self._poll_db_changes)
                except Exception:
                    event = None
                if event is not None and self._subscribers:
                    self._enqueue_to_all(event)
        except asyncio.CancelledError:
            pass

    async def subscribe(
        self, last_event_id: Optional[int], is_guest: bool
    ) -> Tuple[asyncio.Queue, int, Dict[str, Any]]:
        loop = self._ensure_loop_state()
        sub_id = self._next_sub_id
        self._next_sub_id += 1
        queue: asyncio.Queue = asyncio.Queue(maxsize=128)
        initial_event = await asyncio.to_thread(self._query_initial_state, last_event_id, is_guest)
        self._subscribers[sub_id] = (queue, is_guest)
        if self._watcher_task is None or self._watcher_task.done():
            self._watcher_task = loop.create_task(self._watcher_loop())
        return queue, sub_id, initial_event

    async def unsubscribe(self, sub_id: int) -> None:
        self._subscribers.pop(sub_id, None)
        if not self._subscribers and self._watcher_task and not self._watcher_task.done():
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except BaseException:
                pass
            self._watcher_task = None

    async def shutdown(self) -> None:
        if self._shutdown_event is not None:
            self._shutdown_event.set()
        if self._watcher_task and not self._watcher_task.done():
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except BaseException:
                pass
            self._watcher_task = None
        self._subscribers.clear()


realtime_broker = RealtimeStreamBroker()


async def shutdown_realtime_stream() -> None:
    """Cleanly stop active SSE watcher and close subscriber streams on app shutdown."""
    await realtime_broker.shutdown()


def _format_sse_frame(event_name: str, data: Dict[str, Any], event_id: Optional[int] = None) -> str:
    lines: List[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event_name}")
    lines.append(f"data: {json.dumps(data)}")
    lines.append("")
    return "\n".join(lines) + "\n"


def _parse_cursor_id(raw_value: Optional[str]) -> Optional[int]:
    if raw_value is None:
        return None
    cleaned = str(raw_value).strip()
    if not cleaned:
        return None
    try:
        parsed = int(cleaned)
        return parsed if parsed >= 0 else None
    except ValueError:
        return None


@router.get("/api/events/stream")
async def stream_attack_events(request: Request, since_id: Optional[str] = None):
    """
    Server-Sent Events endpoint pushing newly persisted attack telemetry in real time.
    Requires authenticated session cookie; query-string secrets are explicitly rejected.
    """
    for param_key in request.query_params.keys():
        if param_key.lower() in FORBIDDEN_QUERY_SECRET_PARAMS:
            return JSONResponse(status_code=400, content={"error": "Authentication secrets are not permitted in query parameters"})

    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    if user.get("role") not in ("admin",):
        return JSONResponse(status_code=403, content={"error": "Forbidden - Admin clearance required"})

    is_guest = (user["role"] == "guest")
    header_cursor = _parse_cursor_id(request.headers.get("last-event-id"))
    query_cursor = _parse_cursor_id(since_id)
    cursor_id = header_cursor if header_cursor is not None else query_cursor

    queue, sub_id, initial_event = await realtime_broker.subscribe(cursor_id, is_guest)

    async def event_generator():
        try:
            yield _format_sse_frame(
                initial_event["event"],
                initial_event["data"],
                event_id=initial_event.get("id"),
            )
            loop = asyncio.get_running_loop()
            last_emit_ts = loop.time()

            while True:
                if realtime_broker._shutdown_event and realtime_broker._shutdown_event.is_set():
                    break
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=0.5)
                    yield _format_sse_frame(ev["event"], ev["data"], event_id=ev.get("id"))
                    last_emit_ts = loop.time()
                except asyncio.TimeoutError:
                    now_ts = loop.time()
                    if (now_ts - last_emit_ts) >= realtime_broker._heartbeat_interval:
                        uptime_fmt, uptime_sec = compute_uptime_metrics()
                        yield _format_sse_frame(
                            "heartbeat",
                            {
                                "ts": datetime.utcnow().isoformat(),
                                "uptime_formatted": uptime_fmt,
                                "uptime_seconds": uptime_sec,
                            },
                        )
                        last_emit_ts = now_ts
        except asyncio.CancelledError:
            pass
        finally:
            await realtime_broker.unsubscribe(sub_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/health")
async def admin_health_check(request: Request):
    """
    Lightweight authenticated connectivity probe for the dashboard watchdog.
    Verifies backend reachability and session validity without database queries.
    """
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    if user.get("role") not in ("admin", "guest"):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})

    return JSONResponse(
        status_code=200,
        content={"status": "ok", "service": "baitscope-dashboard"},
        headers={"Cache-Control": "no-store, no-cache"},
    )


@router.get("/api/attacks/{attack_id}")
async def get_attack_detail(attack_id: int, request: Request, db: Session = Depends(get_db)):
    """Fetch complete single attack telemetry row for on-demand payload inspection."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    if user.get("role") not in ("admin", "guest"):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})

    row = db.query(AttackLog).filter(AttackLog.id == attack_id).first()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Attack record not found"})

    return serialize_attack_log(row, is_guest=(user["role"] == "guest"), max_payload_len=None)


@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login?next=/admin&auth_required=1", status_code=303)
    
    return templates.TemplateResponse(request=request, name="admin.html", context={
        "user_role": user["role"],
        "username": user["username"],
        "display_name": user["display_name"]
    })

@router.get("/api/stats")
async def get_stats(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    
    is_guest = (user["role"] == "guest")

    watchlisted_set = get_watchlisted_ip_set(db)
    recent_attacks = (
        db.query(AttackLog)
        .order_by(AttackLog.timestamp.desc(), AttackLog.id.desc())
        .limit(100)
        .all()
    )
    recent_logs = [serialize_attack_log(log, is_guest=is_guest, max_payload_len=None, watchlisted_set=watchlisted_set) for log in recent_attacks]

    malware_list = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).limit(50).all()
    malware_data = [serialize_malware_item(m, is_guest=is_guest) for m in malware_list]

    latest_row = recent_attacks[0] if recent_attacks else None
    metrics = compute_dashboard_metrics(db, latest_row=latest_row, watchlisted_set=watchlisted_set)

    # Top Threats summary for Threat Intel overview strip
    top_threat_records = db.query(IPThreatRegistry).order_by(IPThreatRegistry.threat_score.desc()).limit(5).all()
    top_threats = []
    for tr in top_threat_records:
        ip_str = mask_ip_address(tr.ip_address) if is_guest else tr.ip_address
        top_threats.append({
            "ip": ip_str,
            "version": tr.ip_version,
            "score": tr.threat_score,
            "classification": tr.threat_classification,
            "total_events": tr.total_events,
            "is_watchlisted": tr.is_watchlisted,
            "last_observed": tr.last_observed.isoformat() if tr.last_observed else None,
            "explanation": tr.score_explanation
        })
    metrics["threat_intel"]["top_threats"] = top_threats

    return {
        "user_role": user["role"],
        "username": user["username"],
        "display_name": user["display_name"],
        **metrics,
        "recent_attacks": recent_logs,
        "malware": malware_data,
    }

@router.get("/api/logs/download")
@router.get("/api/logs/download/txt")
async def download_logs(request: Request, format: str = "txt", db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return PlainTextResponse("Authentication required to download logs.", status_code=401)
    if user["role"] != "admin":
        return PlainTextResponse("Access Denied: Only administrators have clearance to download raw threat logs and forensic reports.", status_code=403)

    logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).all()
    malware = db.query(MalwareMetadata).order_by(MalwareMetadata.timestamp.desc()).all()
    
    if format.lower() == "pdf":
        pdf_bytes = generate_pdf_report(logs, malware)
        filename = f"baitscope_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    # Default: Plain text format
    content = "================================================================================\n"
    content += "                   GSI CYBERGUARD BAITSCOPE - THREAT LOGS\n"
    content += "================================================================================\n"
    content += f"Export Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    content += f"Authorized User: {user['username']} ({user['display_name']})\n"
    content += f"Total Incidents Logged: {len(logs)}\n"
    content += f"Quarantined Malware Samples: {len(malware)}\n"
    content += "================================================================================\n\n"
    
    content += "--- RECENT ADVERSARIAL EVENTS ---\n\n"
    for log in logs:
        ts = log.timestamp.isoformat() if log.timestamp else "N/A"
        peer_info = f" (Peer: {log.peer_ip or log.ip_address}, Status: {log.attribution_status or 'verified_peer'})" if log.peer_ip else ""
        content += f"[{ts}Z] IP: {log.ip_address}{peer_info} | Endpoint: {log.endpoint} | Type: {log.attack_type} | Severity: {log.severity}\n"
        content += f"User-Agent: {log.user_agent}\n"
        content += f"Payload: {log.payload}\n"
        content += "-" * 80 + "\n"
        
    if malware:
        content += "\n--- QUARANTINED MALWARE SAMPLES ---\n\n"
        for m in malware:
            ts = m.timestamp.isoformat() if m.timestamp else "N/A"
            content += f"[{ts}Z] File: {m.filename} | Size: {m.file_size} bytes | MIME: {m.mime_type} | Source IP: {m.source_ip}\n"
            content += f"SHA-256 Hash: {m.file_hash}\n"
            content += "-" * 80 + "\n"
        
    filename = f"baitscope_threat_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return PlainTextResponse(content=content, headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })

@router.get("/api/logs/download/pdf")
async def download_pdf_logs(request: Request, db: Session = Depends(get_db)):
    return await download_logs(request=request, format="pdf", db=db)

@router.get("/api/threats")
async def list_threats(
    request: Request,
    classification: Optional[str] = None,
    watchlisted: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List tracked IP threats with optional classification/watchlist filtering and pagination."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})

    query = db.query(IPThreatRegistry)
    if classification:
        query = query.filter(IPThreatRegistry.threat_classification == classification)
    if watchlisted is not None:
        query = query.filter(IPThreatRegistry.is_watchlisted == watchlisted)
    if search:
        query = query.filter(
            (IPThreatRegistry.ip_address.like(f"%{search}%")) |
            (IPThreatRegistry.notes.like(f"%{search}%"))
        )

    total = query.count()
    records = query.order_by(IPThreatRegistry.threat_score.desc()).offset(offset).limit(limit).all()

    is_guest = (user["role"] == "guest")
    items = []
    for r in records:
        items.append({
            "id": r.id,
            "ip_address": mask_ip_address(r.ip_address) if is_guest else r.ip_address,
            "ip_version": r.ip_version,
            "peer_ip": mask_ip_address(r.peer_ip or r.ip_address) if is_guest else (r.peer_ip or r.ip_address),
            "attribution_method": r.attribution_method or "direct_peer",
            "attribution_status": r.attribution_status or "verified_peer",
            "is_synthetic": bool(r.is_synthetic),
            "first_observed": r.first_observed.isoformat() if r.first_observed else None,
            "last_observed": r.last_observed.isoformat() if r.last_observed else None,
            "total_events": r.total_events,
            "attack_counts": r.attack_counts or {},
            "threat_score": r.threat_score,
            "threat_classification": r.threat_classification,
            "is_watchlisted": r.is_watchlisted,
            "score_explanation": r.score_explanation,
            "notes": r.notes
        })

    return {"total": total, "limit": limit, "offset": offset, "threats": items}


@router.get("/api/threats/export")
async def export_threats(request: Request, format: str = "json", db: Session = Depends(get_db)):
    """Export persistent threat intelligence records in JSON or CSV format."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})

    records = db.query(IPThreatRegistry).order_by(IPThreatRegistry.threat_score.desc()).all()
    is_guest = (user["role"] == "guest")

    if format.lower() == "csv":
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP Address", "IP Version", "Peer IP", "Attribution Method", "Attribution Status", "Is Synthetic", "First Observed", "Last Observed", "Total Events", "Threat Score", "Classification", "Watchlisted", "Attack Categories", "Explanation", "Notes"])
        for r in records:
            ip_str = mask_ip_address(r.ip_address) if is_guest else r.ip_address
            peer_str = mask_ip_address(r.peer_ip or r.ip_address) if is_guest else (r.peer_ip or r.ip_address)
            cats = json.dumps(r.attack_counts or {})
            writer.writerow([
                ip_str,
                r.ip_version,
                peer_str,
                r.attribution_method or "direct_peer",
                r.attribution_status or "verified_peer",
                bool(r.is_synthetic),
                r.first_observed.isoformat() if r.first_observed else "",
                r.last_observed.isoformat() if r.last_observed else "",
                r.total_events,
                r.threat_score,
                r.threat_classification,
                r.is_watchlisted,
                cats,
                r.score_explanation,
                r.notes
            ])
        filename = f"baitscope_threat_intelligence_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        return PlainTextResponse(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    else:
        items = []
        for r in records:
            items.append({
                "ip_address": mask_ip_address(r.ip_address) if is_guest else r.ip_address,
                "ip_version": r.ip_version,
                "peer_ip": mask_ip_address(r.peer_ip or r.ip_address) if is_guest else (r.peer_ip or r.ip_address),
                "attribution_method": r.attribution_method or "direct_peer",
                "attribution_status": r.attribution_status or "verified_peer",
                "is_synthetic": bool(r.is_synthetic),
                "first_observed": r.first_observed.isoformat() if r.first_observed else None,
                "last_observed": r.last_observed.isoformat() if r.last_observed else None,
                "total_events": r.total_events,
                "threat_score": r.threat_score,
                "threat_classification": r.threat_classification,
                "is_watchlisted": r.is_watchlisted,
                "attack_counts": r.attack_counts or {},
                "score_explanation": r.score_explanation,
                "notes": r.notes
            })
        filename = f"baitscope_threat_intelligence_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return JSONResponse(
            content={"export_timestamp": datetime.utcnow().isoformat(), "total_records": len(items), "threats": items},
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )


@router.get("/api/threats/{ip:path}")
async def get_threat_detail(ip: str, request: Request, db: Session = Depends(get_db)):
    """Inspect detailed threat intelligence profile and forensic attack history for a single IP."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})

    record = db.query(IPThreatRegistry).filter(IPThreatRegistry.ip_address == ip).first()
    if not record:
        return JSONResponse(status_code=404, content={"error": f"Threat record for IP '{ip}' not found"})

    is_guest = (user["role"] == "guest")
    raw_logs = db.query(AttackLog).filter(AttackLog.ip_address == ip).order_by(AttackLog.timestamp.desc()).limit(50).all()
    logs_data = []
    for l in raw_logs:
        logs_data.append({
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "peer_ip": mask_ip_address(l.peer_ip or l.ip_address) if is_guest else (l.peer_ip or l.ip_address),
            "attribution_method": l.attribution_method or "direct_peer",
            "attribution_status": l.attribution_status or "verified_peer",
            "is_synthetic": bool(l.is_synthetic),
            "endpoint": l.endpoint,
            "method": l.method,
            "attack_type": l.attack_type,
            "severity": l.severity,
            "payload": "[REDACTED - GUEST]" if is_guest else (l.payload or "")
        })

    return {
        "ip_address": mask_ip_address(record.ip_address) if is_guest else record.ip_address,
        "ip_version": record.ip_version,
        "peer_ip": mask_ip_address(record.peer_ip or record.ip_address) if is_guest else (record.peer_ip or record.ip_address),
        "attribution_method": record.attribution_method or "direct_peer",
        "attribution_status": record.attribution_status or "verified_peer",
        "is_synthetic": bool(record.is_synthetic),
        "first_observed": record.first_observed.isoformat() if record.first_observed else None,
        "last_observed": record.last_observed.isoformat() if record.last_observed else None,
        "total_events": record.total_events,
        "attack_counts": record.attack_counts or {},
        "threat_score": record.threat_score,
        "threat_classification": record.threat_classification,
        "is_watchlisted": record.is_watchlisted,
        "score_explanation": record.score_explanation,
        "notes": record.notes,
        "recent_logs": logs_data
    }


@router.post("/api/threats/{ip:path}/watchlist")
async def toggle_watchlist(ip: str, request: Request, db: Session = Depends(get_db)):
    """Add or remove an IP address from the threat watchlist with optional notes."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    if user["role"] != "admin":
        return JSONResponse(status_code=403, content={"error": "Only administrators can manage the watchlist"})

    record = db.query(IPThreatRegistry).filter(IPThreatRegistry.ip_address == ip).first()
    if not record:
        from threat_intel import record_threat_event
        record = record_threat_event(db, ip, "Manual Watchlist", {"user-agent": "Admin Console"})

    try:
        body = await request.json()
    except Exception:
        body = {}

    action = body.get("action", "toggle")
    notes = body.get("notes")

    if action == "add":
        record.is_watchlisted = True
    elif action == "remove":
        record.is_watchlisted = False
    else:
        record.is_watchlisted = not record.is_watchlisted

    if notes is not None:
        record.notes = notes

    db.commit()
    db.refresh(record)

    return {
        "status": "success",
        "ip_address": record.ip_address,
        "is_watchlisted": record.is_watchlisted,
        "notes": record.notes,
        "threat_classification": record.threat_classification,
        "threat_score": record.threat_score
    }


@router.post("/api/clear-logs")
@router.delete("/api/clear-logs")
async def clear_logs(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    if user.get("role") != "admin":
        return JSONResponse(status_code=403, content={"error": "Only administrators can clear attack logs."})

    try:
        # Delete records from database
        db.query(AttackLog).delete()
        db.query(MalwareMetadata).delete()
        db.commit()

        # Truncate JSON log file if present
        try:
            with open("logs/attacks.json", "w") as f:
                f.write("")
        except Exception:
            pass

        return {"status": "success", "message": "All captured attack history cleared successfully."}
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": f"Failed to clear attack history: {str(e)}"})
