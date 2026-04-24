import json
import sqlite3
import pandas as pd
from typing import List, Dict, Union

class DataLoader:
    """
    Handles loading honeypot attack logs from various data sources (JSON or SQLite).
    """

    @staticmethod
    def load_from_json(file_path: str) -> pd.DataFrame:
        """
        Load attack logs from a JSON file.
        Expects a list of dictionaries with keys like:
        ip, timestamp, method, endpoint, headers, payload, user_agent
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            df = pd.DataFrame(data)
            return df
        except Exception as e:
            print(f"Error loading JSON data: {e}")
            return pd.DataFrame()

    @staticmethod
    def load_from_sqlite(db_path: str, table_name: str = "logs") -> pd.DataFrame:
        """
        Load attack logs from an SQLite database.
        """
        try:
            conn = sqlite3.connect(db_path)
            query = f"SELECT * FROM {table_name}"
            df = pd.read_sql_query(query, conn)
            conn.close()
            return df
        except Exception as e:
            print(f"Error loading SQLite data: {e}")
            return pd.DataFrame()

    @staticmethod
    def clean_data(df: pd.DataFrame) -> pd.DataFrame:
        """
        Basic data cleaning.
        Fills missing values and ensures correct types.
        """
        if df.empty:
            return df
            
        # Fill missing payloads or headers with empty strings
        for col in ['payload', 'headers', 'user_agent', 'endpoint', 'method']:
            if col in df.columns:
                df[col] = df[col].fillna('')
                df[col] = df[col].astype(str)
        
        # Parse timestamp if it exists
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            
        return df


