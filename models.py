from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from database import Base
import datetime

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
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
    source_ip = Column(String)
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
