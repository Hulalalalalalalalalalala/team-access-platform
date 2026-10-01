"""SQLite persistence: schema, connection pool, and atomic-commit helpers.

Durability settings
--------------------
* The database lives in a single file (default ``data/app.db``) so every
  committed change survives process restarts.
* WAL journal mode + ``synchronous=NORMAL`` give concurrency (multiple
  readers, one writer) with safe commit boundaries for our workload; every
  business operation is wrapped in one ``IMMEDIATE`` transaction, so the
  business write and its audit/idempotency rows commit atomically or not at
  all.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

from . import config

_init_lock = threading.Lock()
_initialized = False

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,            -- pbkdf2 string, never logged/returned
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('admin','member')),
    status      TEXT NOT NULL CHECK (status IN ('active','disabled')),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id, status);

CREATE TABLE IF NOT EXISTS invites (
    id              INTEGER PRIMARY KEY,
    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,   -- only the hash is stored
    invite_username TEXT NOT NULL,          -- invite is bound to this username
    role            TEXT NOT NULL CHECK (role IN ('admin','member')),
    status          TEXT NOT NULL CHECK (status IN ('available','used','revoked')),
    created_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    used_by         INTEGER REFERENCES users(id),
    revoked_at      INTEGER,
    delegation_id   INTEGER REFERENCES delegations(id)  -- set when issued by a delegate
);
CREATE INDEX IF NOT EXISTS idx_invites_user ON invites(invite_username);

-- Temporary delegation of invite management: an active admin grants one
-- active plain member the power to issue/revoke member invites for a
-- bounded time. At most one ACTIVE delegation per (org, delegate).
CREATE TABLE IF NOT EXISTS delegations (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    grantor_id  INTEGER NOT NULL REFERENCES users(id),
    delegate_id INTEGER NOT NULL REFERENCES users(id),
    status      TEXT NOT NULL CHECK (status IN ('active','expired','revoked','invalidated')),
    reason      TEXT,               -- 'expired' / 'revoked' / 'grantor_not_active_admin' / 'delegate_not_active_member'
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    ended_at    INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_delegations_one_active
    ON delegations(org_id, delegate_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_delegations_delegate ON delegations(org_id, delegate_id);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,        -- raw token only ever lives in the client
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id   INTEGER REFERENCES users(id),
    action     TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT,
    before_state TEXT,                      -- JSON snapshot, nullable
    after_state  TEXT,                      -- JSON snapshot, nullable
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, id);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    id              INTEGER PRIMARY KEY,
    operator_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT NOT NULL,          -- 'global' or 'org:<id>'
    idempotency_key TEXT NOT NULL,
    request_hash    TEXT NOT NULL,          -- sha256 of canonical request body
    response_status INTEGER NOT NULL,
    response_body   TEXT NOT NULL,          -- JSON of the first successful response
    delegation_id   INTEGER,                -- delegation that authorized the original call
    created_at      INTEGER NOT NULL,
    UNIQUE (operator_id, scope, idempotency_key)
);

-- Test-only fault-injection hook. When this table has a row whose action
-- equals the audit action about to be inserted, the audit INSERT raises,
-- which aborts the whole transaction (proving atomic rollback). The table is
-- harmless in production (it stays empty).
CREATE TABLE IF NOT EXISTS _fail_next_actions (
    action TEXT PRIMARY KEY
);
"""

# Trigger attached to audit_logs: used by rollback tests to force the audit
# write (and therefore the whole business transaction) to fail.
FAIL_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS trg_fail_next_audit
BEFORE INSERT ON audit_logs
WHEN EXISTS (SELECT 1 FROM _fail_next_actions WHERE action = NEW.action)
BEGIN
    SELECT RAISE(ABORT, 'injected audit failure');
END;
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(
        config.DB_PATH,
        timeout=30.0,            # wait behind the write lock instead of erroring
        isolation_level=None,    # explicit BEGIN/COMMIT, full control
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """Idempotent migration: add ``column`` to ``table`` when missing.

    Needed so databases created by older versions pick up the delegation
    columns on restart (CREATE TABLE IF NOT EXISTS leaves them untouched).
    """
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db() -> None:
    global _initialized
    with _init_lock:
        if _initialized:
            return
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute(FAIL_TRIGGER)
            _ensure_column(conn, "invites", "delegation_id",
                           "delegation_id INTEGER REFERENCES delegations(id)")
            _ensure_column(conn, "idempotency_keys", "delegation_id",
                           "delegation_id INTEGER")
        finally:
            conn.close()
        _initialized = True


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Open one serializable-ish write transaction.

    ``BEGIN IMMEDIATE`` acquires the SQLite write lock up front, which makes
    concurrent writers queue rather than hit ``SQLITE_BUSY`` at commit time,
    and lets us rely on row ordering for concurrency invariants
    (single-use invite, last-admin protection).
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def get_conn() -> sqlite3.Connection:
    """Per-request connection (FastAPI dependency)."""
    init_db()
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
