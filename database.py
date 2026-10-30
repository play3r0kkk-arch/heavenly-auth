import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = bool(DATABASE_URL)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

if IS_POSTGRES:
    import psycopg2
    from psycopg2.extras import RealDictCursor

    class PostgresCursorWrapper:
        def __init__(self, cursor):
            self._cursor = cursor

        def execute(self, query, params=None):
            pg_query = query.replace("?", "%s")
            if "INSERT OR IGNORE INTO users" in pg_query:
                pg_query = pg_query.replace("INSERT OR IGNORE INTO users", "INSERT INTO users")
                if "ON CONFLICT" not in pg_query:
                    pg_query += " ON CONFLICT (username) DO NOTHING"
            elif "INSERT OR IGNORE INTO activation_keys" in pg_query:
                pg_query = pg_query.replace("INSERT OR IGNORE INTO activation_keys", "INSERT INTO activation_keys")
                if "ON CONFLICT" not in pg_query:
                    pg_query += " ON CONFLICT (key) DO NOTHING"

            if params is not None:
                self._cursor.execute(pg_query, params)
            else:
                self._cursor.execute(pg_query)
            return self

        def fetchone(self):
            row = self._cursor.fetchone()
            if row is None:
                return None
            return dict(row)

        def fetchall(self):
            rows = self._cursor.fetchall()
            return [dict(r) for r in rows]

        @property
        def rowcount(self):
            return self._cursor.rowcount

        def close(self):
            self._cursor.close()

    class PostgresConnectionWrapper:
        def __init__(self, conn):
            self._conn = conn

        def cursor(self):
            return PostgresCursorWrapper(self._conn.cursor(cursor_factory=RealDictCursor))

        def commit(self):
            self._conn.commit()

        def rollback(self):
            self._conn.rollback()

        def close(self):
            self._conn.close()

    def get_db():
        conn = psycopg2.connect(DATABASE_URL)
        return PostgresConnectionWrapper(conn)

else:
    DB_FILE = os.path.join(os.path.dirname(__file__), "heavenly.db")

    def get_db():
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    if IS_POSTGRES:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            hwid TEXT DEFAULT '',
            sub_until TEXT DEFAULT '',
            role TEXT DEFAULT 'User',
            is_banned INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS activation_keys (
            key TEXT PRIMARY KEY,
            days INTEGER NOT NULL,
            is_used INTEGER DEFAULT 0,
            used_by TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );
        """)
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = 'heavenlyowner'")
        owner = cursor.fetchone()
        if not owner:
            cursor.execute("""
            INSERT INTO users (id, username, password_hash, hwid, sub_until, role)
            VALUES (777, 'HeavenlyOwner', ?, '', 'LIFETIME', 'Owner')
            ON CONFLICT (id) DO NOTHING
            """, (hash_password("admin123"),))
            print("[DB] Создан аккаунт владельца с UID 777 (PostgreSQL)")
    else:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
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
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );
        """)

        cursor.execute("SELECT id FROM users WHERE LOWER(username) = 'heavenlyowner'")
        owner = cursor.fetchone()
        if not owner:
            cursor.execute("""
            INSERT OR IGNORE INTO users (id, username, password_hash, hwid, sub_until, role)
            VALUES (777, 'HeavenlyOwner', ?, '', 'LIFETIME', 'Owner')
            """, (hash_password("admin123"),))
            print("[DB] Создан аккаунт владельца с UID 777")

    conn.commit()
    conn.close()

def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    cursor = conn.cursor()
    if IS_POSTGRES:
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (key, value))
    else:
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?", (key, value, value))
    conn.commit()
    conn.close()
