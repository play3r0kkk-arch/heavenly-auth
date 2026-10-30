import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

DB_FILE = os.path.join(os.path.dirname(__file__), "heavenly.db")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        hwid TEXT DEFAULT '',
        sub_until TEXT DEFAULT '',
        role TEXT DEFAULT 'User',
        is_banned INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
    except Exception:
        pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activation_keys (
        key TEXT PRIMARY KEY,
        days INTEGER NOT NULL,
        is_used INTEGER DEFAULT 0,
        used_by TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("SELECT id FROM users WHERE LOWER(username) = 'heavenlyowner'")
    owner = cursor.fetchone()
    if not owner:
        cursor.execute("""
        INSERT OR IGNORE INTO users (id, username, password_hash, hwid, sub_until, role)
        VALUES (1, 'HeavenlyOwner', ?, '', 'LIFETIME', 'Owner')
        """, (hash_password("admin123"),))
        print("[DB] Создан аккаунт владельца с UID 1: логин 'HeavenlyOwner', пароль 'admin123'")

    sample_keys = [
        ("HV-LIFE-TIME-2026", 9999),
        ("HV-30DAY-PASS-0001", 30),
        ("HV-30DAY-PASS-0002", 30),
        ("HV-07DAY-TRIAL-001", 7)
    ]
    for key, days in sample_keys:
        cursor.execute("INSERT OR IGNORE INTO activation_keys (key, days) VALUES (?, ?)", (key, days))

    conn.commit()
    conn.close()
