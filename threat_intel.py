"""
BAITSCOPE Advanced Threat Intelligence & Persistent Rate Limiting Core (v2.0.0)
Cyber Deception and Threat Intelligence Platform
Deceive. Detect. Investigate.

Capabilities:
1. Trustworthy Source IP Extraction & Proxy Verification (RFC 7239 / CIDR parsing)
2. IPv4 & IPv6 Normalization & Validation
3. Persistent IP Threat Registry (Upsert, Deduplication, Forensic History)
4. Configurable Heuristic Threat Scoring Model with Recency Decay & Human Explanations
5. Atomic SQLite-Backed Rate Limiting with Exponential Backoff Retries
"""

import os
import time
import datetime
import ipaddress
import json
from typing import Optional, Tuple, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError, IntegrityError
from fastapi import Request

from models import IPThreatRegistry, RateLimitRecord
from source_attribution import (
    normalize_ip_address,
    get_configured_trusted_proxies,
    is_trusted_proxy,
    extract_source_attribution,
    SourceAttribution
)

# =============================================================================
# 1. TRUSTED PROXIES & SOURCE IP EXTRACTION (DELEGATED TO SOURCE_ATTRIBUTION)
# =============================================================================

def extract_client_ip(request: Request) -> Tuple[str, str, bool, Optional[str]]:
    """
    Trustworthy source IP extraction without blind trust in client-controllable headers.
    Returns:
        (effective_ip, ip_version, is_forwarded, raw_forwarded_for)
    """
    attr = extract_source_attribution(request)
    return (attr.client_ip, attr.ip_version, attr.is_forwarded, attr.raw_forwarded_for or attr.raw_real_ip)


# =============================================================================
# 2. CONFIGURABLE THREAT SCORING MODEL
# =============================================================================

# Category Severity Base Weights
SEVERITY_WEIGHTS: Dict[str, int] = {
    "Web Shell Detection": 25,
    "SQL Injection": 20,
    "Path Traversal": 15,
    "XSS": 10,
    "Brute Force": 8,
    "Rate Limit Exceeded": 6,
    "Suspicious Activity": 5
}

def calculate_threat_score(
    total_events: int,
    attack_counts: Dict[str, int],
    first_observed: datetime.datetime,
    last_observed: datetime.datetime
) -> Tuple[int, str, str]:
    """
    Calculates a deterministic, transparent threat score (0 to 100) and classification.
    
    Scoring Components:
    1. Base Severity Score (S_sev): Weighted sum of attack categories observed.
    2. Velocity Bonus (S_vel): Rapid successive attacks in short windows.
    3. Vector Diversity Bonus (S_div): Multiple distinct attack types indicates targeted assault.
    4. Volume Scaling (S_vol): Proportional bonus for high event frequency.
    5. Inactivity Decay (D): Decays score if attacker has been dormant.
    
    Returns:
        (threat_score, threat_classification, score_explanation)
    """
    # 1. Base Severity Points (Capped at 50 to prevent single-vector distortion)
    raw_sev = 0
    for cat, count in (attack_counts or {}).items():
        if str(cat).strip().lower() == "command injection":
            continue
        weight = SEVERITY_WEIGHTS.get(cat, 5)
        raw_sev += count * weight
    s_sev = min(50, raw_sev)

    # 2. Vector Diversity Bonus
    distinct_vectors = len([
        c for c, count in (attack_counts or {}).items()
        if count > 0 and str(c).strip().lower() != "command injection"
    ])
    if distinct_vectors >= 3:
        s_div = 20
    elif distinct_vectors == 2:
        s_div = 10
    else:
        s_div = 0

    # 3. Velocity Bonus
    # Calculate duration between first and last observed event
    duration_sec = max(1.0, (last_observed - first_observed).total_seconds())
    if total_events >= 3 and duration_sec <= 600:  # 3+ attacks in 10 minutes
        s_vel = 15
    elif total_events >= 10 and duration_sec <= 3600:  # 10+ attacks in 1 hour
        s_vel = 25
    else:
        s_vel = 0

    # 4. Volume Scaling (up to 15 points)
    s_vol = min(15, total_events * 2)

    # 5. Inactivity Decay Factor
    now = datetime.datetime.utcnow()
    idle_sec = max(0.0, (now - last_observed).total_seconds())
    if idle_sec < 7200:          # < 2 hours
        decay = 1.0
    elif idle_sec < 86400:       # 2 to 24 hours
        decay = 0.90
    elif idle_sec < 604800:      # 1 to 7 days
        decay = 0.75
    else:                        # > 7 days
        decay = 0.50

    raw_total = s_sev + s_div + s_vel + s_vol
    final_score = max(0, min(100, int(round(raw_total * decay))))

    # Threat Classification
    if final_score >= 75:
        classification = "Critical"
    elif final_score >= 50:
        classification = "High"
    elif final_score >= 25:
        classification = "Medium"
    else:
        classification = "Low"

    vectors_summary = ", ".join([f"{k}:{v}" for k, v in (attack_counts or {}).items()]) or "None"
    explanation = (
        f"Score {final_score}/100 ({classification}) | {total_events} event(s) across {distinct_vectors} vector(s) "
        f"[{vectors_summary}] | Severity: +{s_sev}, Diversity: +{s_div}, Velocity: +{s_vel}, "
        f"Volume: +{s_vol}, Recency Decay: {decay}x"
    )

    return (final_score, classification, explanation)


# =============================================================================
# 3. PERSISTENT THREAT REGISTRY MANAGEMENT
# =============================================================================

def record_threat_event(
    db: Session,
    ip_address: str,
    attack_type: str,
    raw_headers: Optional[Dict[str, Any]] = None,
    peer_ip: Optional[str] = None,
    attribution_method: str = "direct_peer",
    attribution_status: str = "verified_peer",
    is_synthetic: bool = False
) -> IPThreatRegistry:
    """
    Atomically updates or registers an attacker IP in the IPThreatRegistry.
    Handles duplicate prevention, attack count aggregation, score updates, and provenance tracking.
    """
    try:
        norm_ip, ip_version = normalize_ip_address(ip_address)
    except ValueError:
        norm_ip, ip_version = ip_address, "IPv4"

    now = datetime.datetime.utcnow()
    headers_sample = {k: v for k, v in (raw_headers or {}).items() if k.lower() in ["user-agent", "x-forwarded-for", "host"]}

    # Check if record exists
    record = db.query(IPThreatRegistry).filter(IPThreatRegistry.ip_address == norm_ip).first()

    if not record:
        initial_counts = {attack_type: 1} if attack_type else {}
        score, classification, explanation = calculate_threat_score(
            total_events=1,
            attack_counts=initial_counts,
            first_observed=now,
            last_observed=now
        )
        record = IPThreatRegistry(
            ip_address=norm_ip,
            ip_version=ip_version,
            peer_ip=peer_ip or norm_ip,
            attribution_method=attribution_method,
            attribution_status=attribution_status,
            is_synthetic=is_synthetic,
            first_observed=now,
            last_observed=now,
            total_events=1,
            attack_counts=initial_counts,
            threat_score=score,
            threat_classification=classification,
            is_watchlisted=False,
            score_explanation=explanation,
            notes="",
            raw_headers_sample=headers_sample
        )
        db.add(record)
    else:
        record.total_events += 1
        record.last_observed = now
        counts = dict(record.attack_counts or {})
        counts[attack_type] = counts.get(attack_type, 0) + 1
        record.attack_counts = counts
        record.raw_headers_sample = headers_sample
        if peer_ip:
            record.peer_ip = peer_ip
        if attribution_method:
            record.attribution_method = attribution_method
        if record.attribution_status == "unverified_historical" and attribution_status != "unverified_historical":
            record.attribution_status = attribution_status
            record.is_synthetic = is_synthetic

        score, classification, explanation = calculate_threat_score(
            total_events=record.total_events,
            attack_counts=counts,
            first_observed=record.first_observed,
            last_observed=now
        )
        record.threat_score = score
        record.threat_classification = classification
        record.score_explanation = explanation

    db.commit()
    db.refresh(record)
    return record


# =============================================================================
# 4. PERSISTENT SQLITE-BACKED RATE LIMITING
# =============================================================================

def check_rate_limit(
    db: Session,
    ip_address: str,
    bucket: str,
    max_requests: int,
    window_seconds: int = 60,
    max_retries: int = 5
) -> Tuple[bool, int, int]:
    """
    SQLite-backed atomic fixed-window rate-limiting with collision resilience.
    Uses in-database atomic increments to prevent lost updates under concurrency.
    
    Returns:
        (is_allowed: bool, current_count: int, retry_after_seconds: int)
    """
    now_ts = time.time()
    window_start = int(now_ts // window_seconds) * window_seconds
    rate_key = f"{ip_address}:{bucket}"
    now_utc = datetime.datetime.utcnow()

    for attempt in range(max_retries):
        try:
            # Atomic in-database increment to avoid lost updates under concurrency
            updated = db.query(RateLimitRecord).filter(
                RateLimitRecord.rate_key == rate_key,
                RateLimitRecord.window_start == window_start
            ).update(
                {
                    RateLimitRecord.request_count: RateLimitRecord.request_count + 1,
                    RateLimitRecord.last_request_time: now_utc
                },
                synchronize_session=False
            )

            if updated > 0:
                db.commit()
                rec = db.query(RateLimitRecord).filter(
                    RateLimitRecord.rate_key == rate_key,
                    RateLimitRecord.window_start == window_start
                ).first()
                cnt = rec.request_count if rec else 1
                if cnt > max_requests:
                    retry_after = max(1, int((window_start + window_seconds) - now_ts))
                    return (False, cnt, retry_after)
                return (True, cnt, 0)
            else:
                # First request in this window - insert new record
                rec = RateLimitRecord(
                    rate_key=rate_key,
                    window_start=window_start,
                    request_count=1,
                    last_request_time=now_utc
                )
                db.add(rec)
                db.commit()
                return (True, 1, 0)

        except (OperationalError, IntegrityError):
            db.rollback()
            time.sleep(0.02 * (attempt + 1))
            continue
        except Exception:
            db.rollback()
            break

    # Fail open with warning if SQLite is heavily congested
    return (True, 1, 0)
