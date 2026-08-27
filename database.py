from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Handle Vercel / Read-Only Serverless Environments
if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    db_dir = "/tmp/database"
    os.makedirs(db_dir, exist_ok=True)
    DATABASE_PATH = os.path.join(db_dir, "honeypot.db")
else:
    db_dir = "./database"
    os.makedirs(db_dir, exist_ok=True)
    DATABASE_PATH = os.path.join(db_dir, "honeypot.db")

DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
