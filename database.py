from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Handle Custom Path, Vercel / Read-Only Serverless Environments
_db_env = os.getenv("BAITSCOPE_DATABASE_PATH") or os.getenv("SENTINEL_DATABASE_PATH")
if _db_env:
    DATABASE_PATH = _db_env
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
elif os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    db_dir = "/tmp/database"
    os.makedirs(db_dir, exist_ok=True)
    DATABASE_PATH = os.path.join(db_dir, "honeypot.db")
else:
    db_dir = "./database"
    os.makedirs(db_dir, exist_ok=True)
    DATABASE_PATH = os.path.join(db_dir, "honeypot.db")

DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 10.0}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_migrations(db_engine=None):
    """
    Idempotent database migration adding source attribution and provenance columns.
    Preserves all existing event IDs, timestamps, categories, and hashes.
    Classifies pre-existing legacy records without provenance as 'unverified_historical'.
    """
    eng = db_engine or engine
    import sqlite3
    if eng.url.drivername.startswith("sqlite"):
        db_file = eng.url.database
        if not db_file or not os.path.exists(db_file):
            return
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        migrations = [
            ("attack_logs", "peer_ip", "VARCHAR(45)"),
            ("attack_logs", "attribution_method", "VARCHAR(32) DEFAULT 'direct_peer'"),
            ("attack_logs", "attribution_status", "VARCHAR(32) DEFAULT 'verified_peer'"),
            ("attack_logs", "is_synthetic", "BOOLEAN DEFAULT 0"),
            ("ip_threat_registry", "peer_ip", "VARCHAR(45)"),
            ("ip_threat_registry", "attribution_method", "VARCHAR(32) DEFAULT 'direct_peer'"),
            ("ip_threat_registry", "attribution_status", "VARCHAR(32) DEFAULT 'verified_peer'"),
            ("ip_threat_registry", "is_synthetic", "BOOLEAN DEFAULT 0"),
            ("malware_metadata", "peer_ip", "VARCHAR(45)"),
            ("malware_metadata", "attribution_method", "VARCHAR(32) DEFAULT 'direct_peer'"),
            ("malware_metadata", "attribution_status", "VARCHAR(32) DEFAULT 'verified_peer'"),
            ("malware_metadata", "is_synthetic", "BOOLEAN DEFAULT 0"),
            ("decoy_users", "avatar_filename", "VARCHAR"),
        ]
        
        for table, col, col_type in migrations:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass
                
        cursor.execute("UPDATE attack_logs SET attribution_status = 'unverified_historical', is_synthetic = 1, attribution_method = 'direct_peer', peer_ip = ip_address WHERE peer_ip IS NULL")
        cursor.execute("UPDATE ip_threat_registry SET attribution_status = 'unverified_historical', is_synthetic = 1, attribution_method = 'direct_peer', peer_ip = ip_address WHERE peer_ip IS NULL")
        cursor.execute("UPDATE malware_metadata SET attribution_status = 'unverified_historical', is_synthetic = 1, attribution_method = 'direct_peer', peer_ip = source_ip WHERE peer_ip IS NULL")
        
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_logs_status ON attack_logs (attribution_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_status ON ip_threat_registry (attribution_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_synthetic ON ip_threat_registry (is_synthetic)")
        except sqlite3.OperationalError:
            pass

        conn.commit()
        conn.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
