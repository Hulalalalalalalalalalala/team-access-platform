#!/usr/bin/env python3
"""Organization member & permission management HTTP service.

Stack: Python stdlib only (http.server + sqlite3 + bcrypt).

Design notes
------------
* Persistence: a single SQLite file (WAL mode). Every write is wrapped in an
  explicit ``BEGIN IMMEDIATE`` transaction so that business data, audit records
  and idempotency records commit atomically (no partial writes on failure).
* Concurrency: ``BEGIN IMMEDIATE`` serializes all writers; conditional UPDATEs
  (e.g. invite acceptance, last-admin protection) are evaluated inside the
  transaction, so concurrent retries/invites can never produce duplicate
  memberships or leave an org with zero enabled admins.
* Passwords: hashed with bcrypt; never stored or returned in plaintext.
* Secrets: session tokens and invite tokens are generated from 32 bytes of
  ``secrets`` randomness; only their SHA-256 hashes are stored. Access logs
  record method/path/status/user-id only -- never headers, bodies or tokens.
* Authorization: org-scoped operations require an active membership; admins
  additionally require role ``admin``. All actor-side failures (non-member,
  disabled member, insufficient role, unknown org) return the same 403 code
  ``org_access_denied`` so that organization existence is never leaked.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import bcrypt

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))
INVITE_TTL_HOURS = 24
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
IDEM_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
PASSWORD_MIN = 8
PASSWORD_MAX = 128
ORG_NAME_MAX = 64

logger = logging.getLogger("orgapi")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class ApiError(Exception):
    """An error that is rendered as a JSON response with a stable code."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


# Stable error codes -------------------------------------------------------- #
E_BAD_REQUEST = "bad_request"
E_UNAUTHORIZED = "unauthorized"
E_ORG_ACCESS_DENIED = "org_access_denied"
E_NOT_FOUND = "not_found"
E_USERNAME_EXISTS = "username_exists"
E_INVALID_CREDENTIALS = "invalid_credentials"
E_INVITE_UNAVAILABLE = "invite_unavailable"
E_INVITE_USERNAME_MISMATCH = "invite_username_mismatch"
E_ALREADY_MEMBER = "already_member"
E_LAST_ADMIN_REQUIRED = "last_admin_required"
E_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
E_INTERNAL = "internal_error"


# --------------------------------------------------------------------------- #
# Time / token helpers
# --------------------------------------------------------------------------- #

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def expires_iso(hours):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def new_token():
    """Return (token, sha256_hex) for a bearer/invite secret."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    org_id     INTEGER NOT NULL REFERENCES organizations(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    role       TEXT    NOT NULL CHECK (role IN ('admin','member')),
    status     TEXT    NOT NULL CHECK (status IN ('active','disabled')),
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id);

CREATE TABLE IF NOT EXISTS invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    org_id      INTEGER NOT NULL REFERENCES organizations(id),
    role        TEXT    NOT NULL CHECK (role IN ('admin','member')),
    invited_by  INTEGER NOT NULL REFERENCES users(id),
    username    TEXT    NOT NULL,
    status      TEXT    NOT NULL CHECK (status IN ('pending','accepted','revoked')),
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    accepted_by INTEGER REFERENCES users(id),
    accepted_at TEXT,
    revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_org ON invites(org_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES organizations(id),
    actor_id    INTEGER NOT NULL REFERENCES users(id),
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    before_json TEXT,
    after_json  TEXT,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, id);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key            TEXT    NOT NULL,
    user_id        INTEGER NOT NULL REFERENCES users(id),
    scope          TEXT    NOT NULL,
    op             TEXT    NOT NULL,
    request_hash   TEXT    NOT NULL,
    response_status INTEGER NOT NULL,
    response_body  TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    PRIMARY KEY (key, user_id, scope)
);
"""


def open_db(path):
    conn = sqlite3.connect(path, timeout=15, check_same_thread=False,
                          isolation_level=None)  # explicit transaction control
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.executescript(SCHEMA)
    return conn


class WriteTx:
    """Context manager for an explicit SERIALIZABLE write transaction."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        return False


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def parse_json_body(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    ctype = handler.headers.get("Content-Type", "")
    if "application/json" not in ctype:
        raise ApiError(400, E_BAD_REQUEST, "Content-Type must be application/json")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiError(400, E_BAD_REQUEST, "Malformed JSON body")
    if not isinstance(body, dict):
        raise ApiError(400, E_BAD_REQUEST, "JSON body must be an object")
    return body


def validate_username(value):
    if not isinstance(value, str) or not USERNAME_RE.match(value):
        raise ApiError(400, E_BAD_REQUEST,
                       "username must be 3-32 chars: letters, digits, _ or -")
    return value


def validate_password(value):
    if not isinstance(value, str) or not (PASSWORD_MIN <= len(value) <= PASSWORD_MAX):
        raise ApiError(400, E_BAD_REQUEST,
                       "password must be 8-128 characters")
    return value


def validate_role(value):
    if value not in ("admin", "member"):
        raise ApiError(400, E_BAD_REQUEST, "role must be 'admin' or 'member'")
    return value


def validate_org_name(value):
    if not isinstance(value, str) or not (1 <= len(value.strip()) <= ORG_NAME_MAX):
        raise ApiError(400, E_BAD_REQUEST,
                       "name must be 1-64 non-empty characters")
    return value.strip()


def require_idem_key(handler):
    key = handler.headers.get("Idempotency-Key")
    if key is None:
        return None
    if not IDEM_KEY_RE.match(key):
        raise ApiError(400, E_BAD_REQUEST,
                       "Idempotency-Key must be 1-128 chars: letters, digits, _ or -")
    return key


def request_hash(op, body):
    canonical = json.dumps({"op": op, "body": body}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Auth / org access
# --------------------------------------------------------------------------- #

def session_user(conn, token):
    row = conn.execute(
        "SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ?", (hash_token(token),)).fetchone()
    return row


def require_member(conn, org_id, user):
    """Active member of the org, else uniform 403 (org existence not leaked)."""
    row = conn.execute(
        "SELECT role, status FROM members WHERE org_id = ? AND user_id = ?",
        (org_id, user["id"])).fetchone()
    if row is None or row["status"] != "active":
        raise ApiError(403, E_ORG_ACCESS_DENIED,
                       "Access to this organization is denied")
    return row


def require_admin(conn, org_id, user):
    row = require_member(conn, org_id, user)
    if row["role"] != "admin":
        raise ApiError(403, E_ORG_ACCESS_DENIED,
                       "Access to this organization is denied")
    return row


def count_active_admins(conn, org_id):
    return conn.execute(
        "SELECT COUNT(*) AS c FROM members "
        "WHERE org_id = ? AND role = 'admin' AND status = 'active'",
        (org_id,)).fetchone()["c"]


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #

def idem_lookup(conn, key, user, scope, op, body):
    """Return a stored idempotency record, or None.

    Raises idempotency_conflict when the same key was reused with a different
    request. Callers re-validate permissions *before* this lookup, so retries
    after a permission change are rejected instead of replayed.
    """
    if key is None:
        return None
    row = conn.execute(
        "SELECT * FROM idempotency_keys WHERE key = ? AND user_id = ? AND scope = ?",
        (key, user["id"], scope)).fetchone()
    if row is None:
        return None
    if row["request_hash"] != request_hash(op, body):
        raise ApiError(409, E_IDEMPOTENCY_CONFLICT,
                       "Idempotency-Key was already used with a different request")
    return row


def idem_store(conn, key, user, scope, op, body, status, response_obj):
    if key is None:
        return
    conn.execute(
        "INSERT INTO idempotency_keys "
        "(key, user_id, scope, op, request_hash, response_status, response_body, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (key, user["id"], scope, op, request_hash(op, body), status,
         json.dumps(response_obj, ensure_ascii=False), now_iso()))


def idem_replay(row):
    return row["response_status"], json.loads(row["response_body"])


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def audit(conn, org_id, actor_id, action, target_type, target_id, before, after):
    conn.execute(
        "INSERT INTO audit_log "
        "(org_id, actor_id, action, target_type, target_id, before_json, after_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (org_id, actor_id, action, target_type, str(target_id),
         json.dumps(before, ensure_ascii=False) if before is not None else None,
         json.dumps(after, ensure_ascii=False) if after is not None else None,
         now_iso()))


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "OrgApi/1.0"
    protocol_version = "HTTP/1.1"

    # Per-request state set up in dispatch() -------------------------------- #
    conn = None
    user = None
    started_at = None

    # -- logging ------------------------------------------------------------- #
    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler's default logger writes the request line,
        # which is safe (no tokens). We use our own structured access log.
        pass

    def _access_log(self, status):
        logger.info(
            'uid=%s %s %s -> %s %.1fms',
            self.user["id"] if self.user else "-",
            self.command, self.path, status,
            (datetime.now(timezone.utc) - self.started_at).total_seconds() * 1000.0,
        )

    # -- response helpers ---------------------------------------------------- #
    def send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, err):
        self.send_json(err.status, {
            "error": {"code": err.code, "message": err.message},
        })

    # -- routing ------------------------------------------------------------- #
    def _route(self, method, path):
        parts = [p for p in path.split("/") if p]
        # /healthz
        if path == "/healthz" and method == "GET":
            return self.healthz, {}
        # /api/auth/...
        if len(parts) == 3 and parts[:2] == ["api", "auth"]:
            if method == "POST" and parts[2] == "register":
                return self.register, {}
            if method == "POST" and parts[2] == "login":
                return self.login, {}
            if method == "POST" and parts[2] == "logout":
                return self.logout, {}
        if path == "/api/me" and method == "GET":
            return self.me, {}
        if path == "/api/orgs" and method == "GET":
            return self.list_orgs, {}
        if path == "/api/orgs" and method == "POST":
            return self.create_org, {}
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "orgs" and method == "GET":
            return self.org_detail, {"org_id": int(parts[2])}
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "orgs" and parts[3] == "members":
            if method == "GET":
                return self.list_members, {"org_id": int(parts[2])}
        if len(parts) == 5 and parts[0] == "api" and parts[1] == "orgs" and parts[3] == "members":
            if method == "PATCH":
                return self.update_member, {"org_id": int(parts[2]), "user_id": int(parts[4])}
        if (len(parts) == 6 and parts[0] == "api" and parts[1] == "orgs"
                and parts[3] == "members" and parts[5] in ("disable", "enable")):
            return self.set_member_status, {
                "org_id": int(parts[2]), "user_id": int(parts[4]), "mode": parts[5]}
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "orgs" and parts[3] == "invites":
            if method == "GET":
                return self.list_invites, {"org_id": int(parts[2])}
            if method == "POST":
                return self.create_invite, {"org_id": int(parts[2])}
        if (len(parts) == 6 and parts[0] == "api" and parts[1] == "orgs"
                and parts[3] == "invites" and parts[5] == "revoke"):
            return self.revoke_invite, {"org_id": int(parts[2]), "invite_id": int(parts[4])}
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "orgs" and parts[3] == "audit":
            if method == "GET":
                return self.query_audit, {"org_id": int(parts[2])}
        if path == "/api/invites/accept" and method == "POST":
            return self.accept_invite, {}
        return None, {}

    def dispatch(self, method):
        self.started_at = datetime.now(timezone.utc)
        parsed = self.path.split("?", 1)[0]
        handler, kwargs = self._route(method, parsed)
        if handler is None:
            self.send_error_json(ApiError(404, E_NOT_FOUND, "Unknown route"))
            self._access_log(404)
            return
        # One connection per request: ThreadingHTTPServer dispatches each
        # request to its own thread, and a single shared sqlite3 connection
        # would interleave transaction state across threads.
        conn = open_db(self.server.db_path)
        self.conn = conn
        try:
            # Public endpoints do not require a session.
            public = (handler in (self.healthz, self.register, self.login))
            if not public:
                token = None
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    token = auth[7:].strip()
                if not token:
                    raise ApiError(401, E_UNAUTHORIZED, "Authentication required")
                self.user = session_user(conn, token)
                if self.user is None:
                    raise ApiError(401, E_UNAUTHORIZED, "Session is invalid or expired")
            status, obj = handler(**kwargs)
            self.send_json(status, obj)
            self._access_log(status)
        except ApiError as err:
            self.send_error_json(err)
            self._access_log(err.status)
        except Exception:
            logger.exception("Unhandled error on %s %s", method, parsed)
            self.send_error_json(ApiError(500, E_INTERNAL, "Internal server error"))
            self._access_log(500)
        finally:
            conn.close()
            self.user = None

    do_GET = lambda self: self.dispatch("GET")
    do_POST = lambda self: self.dispatch("POST")
    do_PATCH = lambda self: self.dispatch("PATCH")
    do_DELETE = lambda self: self.dispatch("DELETE")

    # -- health -------------------------------------------------------------- #
    def healthz(self):
        return 200, {"status": "ok"}

    # -- auth ---------------------------------------------------------------- #
    def register(self):
        body = parse_json_body(self)
        username = validate_username(body.get("username"))
        password = validate_password(body.get("password"))
        pw_hash = bcrypt.hashpw(password.encode("utf-8"),
                                bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")
        with WriteTx(self.conn):
            try:
                cur = self.conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, pw_hash, now_iso()))
            except sqlite3.IntegrityError:
                raise ApiError(409, E_USERNAME_EXISTS, "Username is already taken")
            user_id = cur.lastrowid
        return 201, {"user_id": user_id, "username": username}

    def login(self):
        body = parse_json_body(self)
        username = body.get("username")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise ApiError(400, E_BAD_REQUEST, "username and password are required")
        row = self.conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)).fetchone()
        # Always run a bcrypt check so unknown-user logins take the same time.
        stored = row["password_hash"] if row else bcrypt.hashpw(
            b"dummy", bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")
        ok = bcrypt.checkpw(password.encode("utf-8"), stored.encode("ascii"))
        if row is None or not ok:
            raise ApiError(401, E_INVALID_CREDENTIALS, "Invalid username or password")
        token, token_h = new_token()
        with WriteTx(self.conn):
            self.conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)",
                (token_h, row["id"], now_iso()))
        return 200, {"token": token, "user_id": row["id"], "username": row["username"]}

    def logout(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else None
        if token:
            with WriteTx(self.conn):
                self.conn.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
        return 200, {"logged_out": True}

    def me(self):
        return 200, {"user_id": self.user["id"], "username": self.user["username"]}

    # -- organizations ------------------------------------------------------- #
    def create_org(self):
        body = parse_json_body(self)
        name = validate_org_name(body.get("name"))
        key = require_idem_key(self)
        scope = "global"
        op = "org.create"
        with WriteTx(self.conn):
            # No org permission to re-check for global scope; replay as-is.
            stored = idem_lookup(self.conn, key, self.user, scope, op, body)
            if stored is not None:
                return idem_replay(stored)
            cur = self.conn.execute(
                "INSERT INTO organizations (name, created_by, created_at) VALUES (?, ?, ?)",
                (name, self.user["id"], now_iso()))
            org_id = cur.lastrowid
            self.conn.execute(
                "INSERT INTO members (org_id, user_id, role, status, created_at, updated_at) "
                "VALUES (?, ?, 'admin', 'active', ?, ?)",
                (org_id, self.user["id"], now_iso(), now_iso()))
            audit(self.conn, org_id, self.user["id"], "org.create", "org", org_id,
                  None, {"name": name, "org_id": org_id})
            resp = {"org": {"id": org_id, "name": name,
                            "role": "admin", "status": "active"}}
            idem_store(self.conn, key, self.user, scope, op, body, 201, resp)
        return 201, resp

    def list_orgs(self):
        rows = self.conn.execute(
            "SELECT o.id, o.name, m.role, m.status FROM organizations o "
            "JOIN members m ON m.org_id = o.id "
            "WHERE m.user_id = ? ORDER BY o.id",
            (self.user["id"],)).fetchall()
        return 200, {"items": [
            {"id": r["id"], "name": r["name"],
             "role": r["role"], "status": r["status"]} for r in rows]}

    def org_detail(self, org_id):
        membership = require_member(self.conn, org_id, self.user)
        org = self.conn.execute(
            "SELECT id, name, created_at FROM organizations WHERE id = ?",
            (org_id,)).fetchone()
        if org is None:
            raise ApiError(403, E_ORG_ACCESS_DENIED,
                           "Access to this organization is denied")
        return 200, {"org": {"id": org["id"], "name": org["name"],
                              "created_at": org["created_at"],
                              "role": membership["role"],
                              "status": membership["status"]}}

    # -- members ------------------------------------------------------------- #
    def list_members(self, org_id):
        require_member(self.conn, org_id, self.user)
        rows = self.conn.execute(
            "SELECT u.id AS user_id, u.username, m.role, m.status, m.created_at AS joined_at "
            "FROM members m JOIN users u ON u.id = m.user_id "
            "WHERE m.org_id = ? ORDER BY m.created_at, m.user_id", (org_id,)).fetchall()
        return 200, {"items": [
            {"user_id": r["user_id"], "username": r["username"],
             "role": r["role"], "status": r["status"],
             "joined_at": r["joined_at"]} for r in rows]}

    def update_member(self, org_id, user_id):
        body = parse_json_body(self)
        new_role = validate_role(body.get("role"))
        key = require_idem_key(self)
        scope = f"org:{org_id}"
        op = "member.role_change"
        with WriteTx(self.conn):
            require_admin(self.conn, org_id, self.user)
            stored = idem_lookup(self.conn, key, self.user, scope, op, body)
            if stored is not None:
                return idem_replay(stored)
            target = self.conn.execute(
                "SELECT role, status FROM members WHERE org_id = ? AND user_id = ?",
                (org_id, user_id)).fetchone()
            if target is None:
                raise ApiError(404, E_NOT_FOUND, "Member not found in this organization")
            if target["role"] == new_role:
                resp = {"member": {"user_id": user_id, "role": new_role,
                                   "status": target["status"]}, "changed": False}
                idem_store(self.conn, key, self.user, scope, op, body, 200, resp)
                return 200, resp
            # Last-enabled-admin protection (also covers self-demotion).
            if (new_role == "member" and target["role"] == "admin"
                    and target["status"] == "active"):
                if count_active_admins(self.conn, org_id) <= 1:
                    raise ApiError(409, E_LAST_ADMIN_REQUIRED,
                                   "Cannot demote the last enabled admin")
            self.conn.execute(
                "UPDATE members SET role = ?, updated_at = ? "
                "WHERE org_id = ? AND user_id = ?",
                (new_role, now_iso(), org_id, user_id))
            audit(self.conn, org_id, self.user["id"], "member.role_change",
                  "member", user_id,
                  {"role": target["role"]}, {"role": new_role})
            resp = {"member": {"user_id": user_id, "role": new_role,
                               "status": target["status"]}, "changed": True}
            idem_store(self.conn, key, self.user, scope, op, body, 200, resp)
        return 200, resp

    def set_member_status(self, org_id, user_id, mode):
        body = parse_json_body(self) if self.headers.get("Content-Length") else {}
        key = require_idem_key(self)
        scope = f"org:{org_id}"
        op = f"member.{mode}"
        new_status = "disabled" if mode == "disable" else "active"
        with WriteTx(self.conn):
            require_admin(self.conn, org_id, self.user)
            stored = idem_lookup(self.conn, key, self.user, scope, op, body)
            if stored is not None:
                return idem_replay(stored)
            target = self.conn.execute(
                "SELECT role, status FROM members WHERE org_id = ? AND user_id = ?",
                (org_id, user_id)).fetchone()
            if target is None:
                raise ApiError(404, E_NOT_FOUND, "Member not found in this organization")
            if target["status"] == new_status:
                resp = {"member": {"user_id": user_id, "role": target["role"],
                                   "status": new_status}, "changed": False}
                idem_store(self.conn, key, self.user, scope, op, body, 200, resp)
                return 200, resp
            if new_status == "disabled" and target["role"] == "admin":
                if count_active_admins(self.conn, org_id) <= 1:
                    raise ApiError(409, E_LAST_ADMIN_REQUIRED,
                                   "Cannot disable the last enabled admin")
            self.conn.execute(
                "UPDATE members SET status = ?, updated_at = ? "
                "WHERE org_id = ? AND user_id = ?",
                (new_status, now_iso(), org_id, user_id))
            audit(self.conn, org_id, self.user["id"], f"member.{mode}",
                  "member", user_id,
                  {"status": target["status"]}, {"status": new_status})
            resp = {"member": {"user_id": user_id, "role": target["role"],
                               "status": new_status}, "changed": True}
            idem_store(self.conn, key, self.user, scope, op, body, 200, resp)
        return 200, resp

    # -- invites ------------------------------------------------------------- #
    def create_invite(self, org_id):
        body = parse_json_body(self)
        username = validate_username(body.get("username"))
        role = validate_role(body.get("role"))
        key = require_idem_key(self)
        scope = f"org:{org_id}"
        op = "invite.create"
        with WriteTx(self.conn):
            require_admin(self.conn, org_id, self.user)
            stored = idem_lookup(self.conn, key, self.user, scope, op, body)
            if stored is not None:
                return idem_replay(stored)
            token, token_h = new_token()
            created = now_iso()
            expires = expires_iso(INVITE_TTL_HOURS)
            cur = self.conn.execute(
                "INSERT INTO invites "
                "(token_hash, org_id, role, invited_by, username, status, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (token_h, org_id, role, self.user["id"], username, created, expires))
            invite_id = cur.lastrowid
            audit(self.conn, org_id, self.user["id"], "invite.create",
                  "invite", invite_id, None,
                  {"username": username, "role": role, "expires_at": expires})
            resp = {"invite": {"id": invite_id, "token": token, "username": username,
                               "role": role, "status": "pending",
                               "created_at": created, "expires_at": expires}}
            idem_store(self.conn, key, self.user, scope, op, body, 201, resp)
        return 201, resp

    def list_invites(self, org_id):
        require_admin(self.conn, org_id, self.user)
        rows = self.conn.execute(
            "SELECT id, username, role, status, created_at, expires_at, "
            "accepted_at, revoked_at FROM invites WHERE org_id = ? ORDER BY id DESC",
            (org_id,)).fetchall()
        now = now_iso()
        items = []
        for r in rows:
            eff = r["status"]
            if eff == "pending" and r["expires_at"] < now:
                eff = "expired"
            items.append({"id": r["id"], "username": r["username"], "role": r["role"],
                          "status": eff, "created_at": r["created_at"],
                          "expires_at": r["expires_at"], "accepted_at": r["accepted_at"],
                          "revoked_at": r["revoked_at"]})
        return 200, {"items": items}

    def revoke_invite(self, org_id, invite_id):
        key = require_idem_key(self)
        scope = f"org:{org_id}"
        op = "invite.revoke"
        with WriteTx(self.conn):
            require_admin(self.conn, org_id, self.user)
            stored = idem_lookup(self.conn, key, self.user, scope, op, {})
            if stored is not None:
                return idem_replay(stored)
            invite = self.conn.execute(
                "SELECT id, status FROM invites WHERE id = ? AND org_id = ?",
                (invite_id, org_id)).fetchone()
            if invite is None or invite["status"] != "pending":
                raise ApiError(409, E_INVITE_UNAVAILABLE,
                               "Invite does not exist or is no longer available")
            cur = self.conn.execute(
                "UPDATE invites SET status = 'revoked', revoked_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (now_iso(), invite_id))
            if cur.rowcount != 1:
                raise ApiError(409, E_INVITE_UNAVAILABLE,
                               "Invite is no longer available")
            audit(self.conn, org_id, self.user["id"], "invite.revoke",
                  "invite", invite_id, {"status": "pending"}, {"status": "revoked"})
            resp = {"invite": {"id": invite_id, "status": "revoked"}, "changed": True}
            idem_store(self.conn, key, self.user, scope, op, {}, 200, resp)
        return 200, resp

    def accept_invite(self):
        body = parse_json_body(self)
        token = body.get("token")
        if not isinstance(token, str) or not token:
            raise ApiError(400, E_BAD_REQUEST, "token is required")
        with WriteTx(self.conn):
            invite = self.conn.execute(
                "SELECT * FROM invites WHERE token_hash = ?",
                (hash_token(token),)).fetchone()
            # 1) Invite availability: exists, pending, not expired.
            if (invite is None or invite["status"] != "pending"
                    or invite["expires_at"] < now_iso()):
                raise ApiError(409, E_INVITE_UNAVAILABLE,
                               "Invite does not exist, has expired, was revoked or already used")
            # 2) Bound username must match the logged-in user.
            if invite["username"] != self.user["username"]:
                raise ApiError(403, E_INVITE_USERNAME_MISMATCH,
                               "Invite was issued for a different username")
            # 3) Existing membership cannot be overwritten.
            existing = self.conn.execute(
                "SELECT role, status FROM members WHERE org_id = ? AND user_id = ?",
                (invite["org_id"], self.user["id"])).fetchone()
            if existing is not None:
                raise ApiError(409, E_ALREADY_MEMBER,
                               "User is already a member of this organization")
            cur = self.conn.execute(
                "UPDATE invites SET status = 'accepted', accepted_by = ?, accepted_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (self.user["id"], now_iso(), invite["id"]))
            if cur.rowcount != 1:
                raise ApiError(409, E_INVITE_UNAVAILABLE,
                               "Invite was already used")
            self.conn.execute(
                "INSERT INTO members (org_id, user_id, role, status, created_at, updated_at) "
                "VALUES (?, ?, ?, 'active', ?, ?)",
                (invite["org_id"], self.user["id"], invite["role"], now_iso(), now_iso()))
            audit(self.conn, invite["org_id"], self.user["id"], "invite.accept",
                  "invite", invite["id"], None,
                  {"username": self.user["username"], "role": invite["role"],
                   "org_id": invite["org_id"]})
            org = self.conn.execute(
                "SELECT name FROM organizations WHERE id = ?",
                (invite["org_id"],)).fetchone()
        return 200, {"org_id": invite["org_id"], "org_name": org["name"],
                     "role": invite["role"], "status": "active"}

    # -- audit --------------------------------------------------------------- #
    def query_audit(self, org_id):
        from urllib.parse import parse_qs, urlsplit
        qs = parse_qs(urlsplit(self.path).query)
        limit = DEFAULT_PAGE_LIMIT
        cursor = None
        try:
            limit = max(1, min(MAX_PAGE_LIMIT, int(qs.get("limit", [DEFAULT_PAGE_LIMIT])[0])))
        except ValueError:
            raise ApiError(400, E_BAD_REQUEST, "limit must be an integer")
        if qs.get("cursor", [""])[0]:
            try:
                cursor = int(qs["cursor"][0])
            except ValueError:
                raise ApiError(400, E_BAD_REQUEST, "cursor must be an integer")
        # Deferred read transaction: consistent snapshot, no write lock.
        self.conn.execute("BEGIN")
        try:
            require_admin(self.conn, org_id, self.user)
            if cursor is None:
                rows = self.conn.execute(
                    "SELECT a.*, u.username AS actor_username FROM audit_log a "
                    "JOIN users u ON u.id = a.actor_id "
                    "WHERE a.org_id = ? ORDER BY a.id DESC LIMIT ?",
                    (org_id, limit)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT a.*, u.username AS actor_username FROM audit_log a "
                    "JOIN users u ON u.id = a.actor_id "
                    "WHERE a.org_id = ? AND a.id < ? ORDER BY a.id DESC LIMIT ?",
                    (org_id, cursor, limit)).fetchall()
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        items = [{
            "id": r["id"], "action": r["action"],
            "actor_id": r["actor_id"], "actor_username": r["actor_username"],
            "target_type": r["target_type"], "target_id": r["target_id"],
            "before": json.loads(r["before_json"]) if r["before_json"] else None,
            "after": json.loads(r["after_json"]) if r["after_json"] else None,
            "created_at": r["created_at"],
        } for r in rows]
        next_cursor = items[-1]["id"] if len(items) == limit else None
        return 200, {"items": items, "next_cursor": next_cursor}


# --------------------------------------------------------------------------- #
# Server entrypoint
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Organization member & permission API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default="data.db", help="SQLite database file path")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    # Initialize the schema once; per-request connections re-run the idempotent
    # CREATE TABLE IF NOT EXISTS statements on open.
    init_conn = open_db(args.db)
    init_conn.close()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.db_path = args.db
    logger.info("Listening on http://%s:%s (db=%s)", args.host, args.port, args.db)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
