from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean, Float, Index
from database import Base
import datetime

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)  # Attributed client IP
    peer_ip = Column(String(45), nullable=True)  # Immediate TCP connection peer
    attribution_method = Column(String(32), default="direct_peer", nullable=True)  # direct_peer | trusted_proxy_chain | remote_node
    attribution_status = Column(String(32), default="verified_peer", nullable=True)  # verified_peer | proxy_attributed | unverified_historical | remote_node_forwarded
    is_synthetic = Column(Boolean, default=False, nullable=True)
    user_agent = Column(String)
    endpoint = Column(String)
    method = Column(String)
    headers = Column(JSON)
    payload = Column(Text)
    attack_type = Column(String)  # SQLi, XSS, etc.
    severity = Column(String)     # Low, Medium, High

class MalwareMetadata(Base):
    __tablename__ = "malware_metadata"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    filename = Column(String)
    file_hash = Column(String)  # SHA256
    file_size = Column(Integer)
    mime_type = Column(String)
    source_ip = Column(String)  # Attributed client IP
    peer_ip = Column(String(45), nullable=True)  # Immediate TCP connection peer
    attribution_method = Column(String(32), default="direct_peer", nullable=True)
    attribution_status = Column(String(32), default="verified_peer", nullable=True)
    is_synthetic = Column(Boolean, default=False, nullable=True)
    quarantine_path = Column(String)

class User(Base):
    __tablename__ = "decoy_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DecoyPlaylist(Base):
    __tablename__ = "decoy_playlists"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    user_id = Column(Integer, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class IPThreatRegistry(Base):
    __tablename__ = "ip_threat_registry"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    ip_version = Column(String(8), default="IPv4", nullable=False)
    peer_ip = Column(String(45), nullable=True)  # Immediate TCP connection peer
    attribution_method = Column(String(32), default="direct_peer", nullable=True)
    attribution_status = Column(String(32), default="verified_peer", nullable=True)
    is_synthetic = Column(Boolean, default=False, nullable=True)
    first_observed = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_observed = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    total_events = Column(Integer, default=1, nullable=False)
    attack_counts = Column(JSON, default=dict, nullable=False)
    threat_score = Column(Integer, default=0, index=True, nullable=False)
    threat_classification = Column(String(16), default="Low", index=True, nullable=False)
    is_watchlisted = Column(Boolean, default=False, index=True, nullable=False)
    score_explanation = Column(Text, default="", nullable=False)
    notes = Column(Text, default="", nullable=False)
    raw_headers_sample = Column(JSON, default=dict, nullable=False)

    __table_args__ = (
        Index("idx_threat_score", "threat_score"),
        Index("idx_last_observed", "last_observed"),
        Index("idx_watchlist", "is_watchlisted"),
        Index("idx_classification", "threat_classification"),
        Index("idx_threat_synthetic", "is_synthetic"),
        Index("idx_threat_status", "attribution_status"),
    )

class RateLimitRecord(Base):
    __tablename__ = "rate_limit_records"

    id = Column(Integer, primary_key=True, index=True)
    rate_key = Column(String(128), index=True, nullable=False)  # "{ip}:{bucket}"
    window_start = Column(Integer, index=True, nullable=False)  # epoch seconds // window
    request_count = Column(Integer, default=1, nullable=False)
    last_request_time = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_rate_key_window", "rate_key", "window_start", unique=True),
    )

