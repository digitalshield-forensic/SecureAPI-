"""SQLite access. Every query is parameterised; no string-built SQL anywhere."""
import contextlib
import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user','admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id, created_at);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


@contextlib.contextmanager
def connect(path: str):
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: str) -> None:
    with connect(path) as db:
        db.executescript(SCHEMA)


def insert_user(path: str, username: str, password_hash: str, role: str = "user") -> str:
    uid = str(uuid.uuid4())
    with connect(path) as db:
        db.execute(
            "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (uid, username.lower(), password_hash, role, time.time()),
        )
    return uid
