"""FastAPI application: organizations, memberships, invitations, audit.

Endpoints
---------
Auth
  POST /auth/register   register with unique username + password
  POST /auth/login      start a session (returns opaque token once)
  POST /auth/logout     invalidate the current session immediately

Organizations
  POST /orgs                 create an org (creator becomes admin) [idempotent]
  GET  /orgs                 list the caller's organizations
  GET  /orgs/{org_id}/members                 active members: roster
  GET  /orgs/{org_id}/members/me              own membership state
  PATCH /orgs/{org_id}/members/{user_id}      role/status change   [idempotent]

Invitations
  POST /orgs/{org_id}/invites         admin issues single-use invite [idempotent]
  POST /orgs/{org_id}/invites/revoke  admin revokes an invite
  POST /invites/accept                accept an invite (join the org)

Audit
  GET /orgs/{org_id}/audit?page=&page_size=   admins only, paged read-only
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI, Header, Query, Request

from . import config, idempotency
from .audit import add_audit
from .auth import CurrentUser, current_user, require_membership
from .db import get_conn, init_db, transaction
from .errors import (
    ApiError,
    conflict,
    install_exception_handlers,
    not_found,
)
from .schemas import (
    AcceptInviteRequest,
    CreateInviteRequest,
    CreateOrgRequest,
    LoginRequest,
    RegisterRequest,
    RevokeInviteRequest,
    UpdateMemberRequest,
)
from .security import (
    generate_invite_token,
    generate_session_token,
    hash_password,
    hash_token,
    now_ts,
    verify_password,
)

# ------------------------------------------------------------- log hygiene

# Session tokens are 64 hex chars; invite tokens are 40. Any log line that
# contains such a run is scrubbed, so a token can never reach a log file
# even if a dependency accidentally emits one.
_TOKEN_RE = re.compile(r"\b[0-9a-f]{40,128}\b")


class _TokenRedactor(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        if _TOKEN_RE.search(rendered):
            record.msg = _TOKEN_RE.sub("<redacted-token>", rendered)
            record.args = ()
        return True


_redactor = _TokenRedactor()
for _name in ("root", "uvicorn", "uvicorn.error", "uvicorn.access"):
    logging.getLogger(_name).addFilter(_redactor)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Team Access Platform", version="1.0.0", lifespan=lifespan)
install_exception_handlers(app)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ------------------------------------------------------------- serializers

def user_public(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "username": row["username"], "created_at": row["created_at"]}


def membership_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "org_id": row["org_id"],
        "user_id": row["user_id"],
        "username": row["username"],
        "role": row["role"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


async def raw_body(request: Request) -> bytes:
    return await request.body()


# ===================================================================== auth

@app.post("/auth/register", status_code=201)
def register(body: RegisterRequest, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    ts = now_ts()
    try:
        with transaction(conn):
            exists = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (body.username,)
            ).fetchone()
            if exists is not None:
                # Unique-username violation gets a stable 409 code.
                raise conflict("username_taken", "username is already taken")
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (body.username, hash_password(body.password), ts),
            )
            row = conn.execute(
                "SELECT id, username, created_at FROM users WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError:
        # Concurrent registration of the same username.
        raise conflict("username_taken", "username is already taken")
    return {"user": user_public(row)}


@app.post("/auth/login")
def login(body: LoginRequest, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    ts = now_ts()
    user_row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (body.username,)
    ).fetchone()
    # Same error whether the username is unknown or the password is wrong.
    if user_row is None or not verify_password(body.password, user_row["password_hash"]):
        raise ApiError(401, "invalid_credentials", "invalid username or password")
    raw_token = generate_session_token()
    with transaction(conn):
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, revoked_at)"
            " VALUES (?, ?, ?, ?, NULL)",
            (hash_token(raw_token), user_row["id"], ts, ts + config.SESSION_TTL_SECONDS),
        )
    return {"token": raw_token, "user": user_public(user_row)}


@app.post("/auth/logout")
def logout(
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, bool]:
    with transaction(conn):
        # Immediate invalidation of THIS session.
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (now_ts(), user.session_id),
        )
    return {"logged_out": True}


# ============================================================== organizations

def _run_idempotent(
    conn: sqlite3.Connection,
    user: CurrentUser,
    scope: str,
    key: Optional[str],
    body: bytes,
    check_perm: Callable[[sqlite3.Connection], None],
    perform: Callable[[sqlite3.Connection, int], tuple[int, dict[str, Any]]],
) -> tuple[int, dict[str, Any]]:
    """Execute ``perform`` with Idempotency-Key semantics inside one txn.

    * same operator + scope + key + same body -> stored first success
    * same key, different body                -> 409 idempotency_conflict
    * permission is re-checked on every attempt, including stored replays
    * business change, audit row and idempotency row commit atomically
    """
    if not key:
        with transaction(conn):
            check_perm(conn)
            return perform(conn, now_ts())

    request_hash = idempotency.fingerprint(body)

    def _replay(row: sqlite3.Row) -> tuple[int, dict[str, Any]]:
        if row["request_hash"] != request_hash:
            raise conflict(
                "idempotency_conflict",
                "Idempotency-Key was already used with a different request",
            )
        return row["response_status"], idempotency.replay_body(row)

    class _KeyRace(Exception):
        pass

    try:
        with transaction(conn):
            check_perm(conn)
            existing = idempotency.find(conn, user.id, scope, key)
            if existing is not None:
                return _replay(existing)
            status, resp = perform(conn, now_ts())
            try:
                idempotency.store_encrypted(
                    conn,
                    operator_id=user.id,
                    scope=scope,
                    key=key,
                    request_hash=request_hash,
                    status_code=status,
                    response_body=resp,
                    ts=now_ts(),
                )
            except sqlite3.IntegrityError:
                # Concurrent retry won the unique index; abort our changes
                # and replay the winner's committed result.
                raise _KeyRace()
        return status, resp
    except _KeyRace:
        with transaction(conn):
            check_perm(conn)
            existing = idempotency.find(conn, user.id, scope, key)
            if existing is None:  # pragma: no cover - winner must have committed
                raise conflict("idempotency_conflict", "concurrent idempotency conflict")
            return _replay(existing)


@app.post("/orgs", status_code=201)
def create_org(
    body: CreateOrgRequest,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        if c.execute("SELECT 1 FROM organizations WHERE name = ?", (body.name,)).fetchone():
            raise conflict("org_name_taken", "organization name is already taken")
        try:
            org_cur = c.execute(
                "INSERT INTO organizations (name, created_by, created_at) VALUES (?, ?, ?)",
                (body.name, user.id, ts),
            )
        except sqlite3.IntegrityError:
            # Concurrent creation of an organization with the same name.
            raise conflict("org_name_taken", "organization name is already taken")
        org_id = org_cur.lastrowid
        c.execute(
            "INSERT INTO memberships (org_id, user_id, role, status, created_at, updated_at)"
            " VALUES (?, ?, 'admin', 'active', ?, ?)",
            (org_id, user.id, ts, ts),
        )
        add_audit(
            c, org_id=org_id, actor_id=user.id, action="org.created",
            target_type="organization", target_id=org_id,
            before=None, after={"id": org_id, "name": body.name}, ts=ts,
        )
        return 201, {"id": org_id, "name": body.name, "role": "admin", "created_at": ts}

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_org_create(), idempotency_key, request_body,
        check_perm=lambda c: None, perform=_perform,
    )
    return resp


@app.get("/orgs")
def list_orgs(
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT o.id AS org_id, o.name AS org_name, o.created_at AS org_created_at,
               m.user_id, u.username, m.role, m.status, m.created_at, m.updated_at
        FROM memberships m
        JOIN organizations o ON o.id = m.org_id
        JOIN users u ON u.id = m.user_id
        WHERE m.user_id = ?
        ORDER BY o.id
        """,
        (user.id,),
    ).fetchall()
    return {
        "organizations": [
            {
                "id": r["org_id"],
                "name": r["org_name"],
                "role": r["role"],
                "status": r["status"],
                "created_at": r["org_created_at"],
            }
            for r in rows
        ]
    }


@app.get("/orgs/{org_id}/members")
def list_members(
    org_id: int,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    # Any ACTIVE member (admin or plain member) may read the roster.
    # Non-members and disabled members get the uniform 403.
    require_membership(conn, user, org_id)
    rows = conn.execute(
        """
        SELECT m.org_id, m.user_id, u.username, m.role, m.status,
               m.created_at, m.updated_at
        FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ?
        ORDER BY m.id
        """,
        (org_id,),
    ).fetchall()
    return {"members": [membership_dict(r) for r in rows]}


@app.get("/orgs/{org_id}/members/me")
def my_membership(
    org_id: int,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    # Organization queries for non-members and disabled members are
    # uniformly 403 (and never reveal whether the org exists).
    require_membership(conn, user, org_id)
    row = conn.execute(
        """
        SELECT m.org_id, m.user_id, u.username, m.role, m.status,
               m.created_at, m.updated_at
        FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.user_id = ?
        """,
        (org_id, user.id),
    ).fetchone()
    return {"membership": membership_dict(row)}


# ================================================================ invitations

@app.post("/orgs/{org_id}/invites", status_code=201)
def create_invite(
    org_id: int,
    body: CreateInviteRequest,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        raw_token = generate_invite_token()
        expires_at = ts + config.INVITE_TTL_SECONDS
        cur = c.execute(
            """
            INSERT INTO invites
                (org_id, token_hash, invite_username, role, status,
                 created_by, created_at, expires_at, used_at, used_by, revoked_at)
            VALUES (?, ?, ?, ?, 'available', ?, ?, ?, NULL, NULL, NULL)
            """,
            (org_id, hash_token(raw_token), body.username, body.role,
             user.id, ts, expires_at),
        )
        invite_id = cur.lastrowid
        add_audit(
            c, org_id=org_id, actor_id=user.id, action="invite.created",
            target_type="invite", target_id=invite_id,
            before=None,
            after={"id": invite_id, "username": body.username, "role": body.role,
                   "status": "available", "expires_at": expires_at},
            ts=ts,
        )
        return 201, {
            "id": invite_id,
            "org_id": org_id,
            "username": body.username,
            "role": body.role,
            "status": "available",
            "token": raw_token,  # returned only here / on idempotent replay
            "created_at": ts,
            "expires_at": expires_at,
        }

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_invite_create(org_id), idempotency_key, request_body,
        check_perm=lambda c: require_membership(c, user, org_id, admin=True),
        perform=_perform,
    )
    return resp


@app.post("/orgs/{org_id}/invites/revoke")
def revoke_invite(
    org_id: int,
    body: RevokeInviteRequest,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    with transaction(conn):
        require_membership(conn, user, org_id, admin=True)
        ts = now_ts()
        inv = conn.execute(
            "SELECT * FROM invites WHERE org_id = ? AND token_hash = ?",
            (org_id, hash_token(body.token)),
        ).fetchone()
        if inv is None or inv["status"] != "available" or inv["expires_at"] <= ts:
            # Missing, already used/revoked or expired: same stable code.
            raise conflict("invite_unavailable", "invite is not available")
        before = {"id": inv["id"], "status": inv["status"]}
        conn.execute(
            "UPDATE invites SET status = 'revoked', revoked_at = ? WHERE id = ?",
            (ts, inv["id"]),
        )
        add_audit(
            conn, org_id=org_id, actor_id=user.id, action="invite.revoked",
            target_type="invite", target_id=inv["id"],
            before=before, after={"id": inv["id"], "status": "revoked"}, ts=ts,
        )
    return {"id": inv["id"], "status": "revoked"}


@app.post("/invites/accept")
def accept_invite(
    body: AcceptInviteRequest,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    # Strict check order per spec:
    # 1) invite availability  2) username match  3) membership state
    with transaction(conn):
        ts = now_ts()
        inv = conn.execute(
            "SELECT * FROM invites WHERE token_hash = ?",
            (hash_token(body.token),),
        ).fetchone()
        if inv is None:
            raise conflict("invite_unavailable", "invite is not available")
        if inv["status"] != "available" or inv["expires_at"] <= ts:
            # expired / revoked / already used all share this code
            raise conflict("invite_unavailable", "invite is not available")
        if inv["invite_username"] != user.username:
            raise ApiError(403, "username_mismatch", "invite is bound to another user")
        existing = conn.execute(
            "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
            (inv["org_id"], user.id),
        ).fetchone()
        if existing is not None:
            # Existing membership (any role/status) is never overwritten.
            raise conflict("already_member", "user is already a member of the organization")

        # Conditional claim: only one concurrent acceptor can flip the row.
        cur = conn.execute(
            "UPDATE invites SET status = 'used', used_at = ?, used_by = ?"
            " WHERE id = ? AND status = 'available' AND ? < expires_at",
            (ts, user.id, inv["id"], ts),
        )
        if cur.rowcount == 0:
            raise conflict("invite_unavailable", "invite is not available")

        conn.execute(
            "INSERT INTO memberships (org_id, user_id, role, status, created_at, updated_at)"
            " VALUES (?, ?, ?, 'active', ?, ?)",
            (inv["org_id"], user.id, inv["role"], ts, ts),
        )
        add_audit(
            conn, org_id=inv["org_id"], actor_id=user.id, action="invite.accepted",
            target_type="membership", target_id=f"{inv['org_id']}:{user.id}",
            before=None,
            after={"org_id": inv["org_id"], "user_id": user.id,
                   "role": inv["role"], "status": "active", "invite_id": inv["id"]},
            ts=ts,
        )
        m_row = conn.execute(
            """
            SELECT m.org_id, m.user_id, u.username, m.role, m.status,
                   m.created_at, m.updated_at
            FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND m.user_id = ?
            """,
            (inv["org_id"], user.id),
        ).fetchone()
    return {"membership": membership_dict(m_row)}


# ========================================================== member management

@app.patch("/orgs/{org_id}/members/{target_user_id}")
def update_member(
    org_id: int,
    target_user_id: int,
    body: UpdateMemberRequest,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    if body.role is None and body.status is None:
        raise ApiError(422, "validation_error", "role or status is required")

    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        m = c.execute(
            """
            SELECT m.*, u.username FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND m.user_id = ?
            """,
            (org_id, target_user_id),
        ).fetchone()
        if m is None:
            raise not_found("member_not_found", "member not found")

        new_role = body.role or m["role"]
        new_status = body.status or m["status"]

        # Last-active-admin invariant (self-targeted operations included).
        # It applies to ANY change that turns the target from an active
        # administrator into something that is not an active administrator:
        # demotion, disabling, or both at once. The count excludes the
        # target, and the IMMEDIATE write lock serializes concurrent
        # demotions/disables so they cannot both pass this check.
        is_active_admin_now = m["role"] == "admin" and m["status"] == "active"
        is_active_admin_after = new_role == "admin" and new_status == "active"
        if is_active_admin_now and not is_active_admin_after:
            other_active_admins = c.execute(
                "SELECT COUNT(*) AS n FROM memberships"
                " WHERE org_id = ? AND role = 'admin' AND status = 'active'"
                " AND user_id != ?",
                (org_id, target_user_id),
            ).fetchone()["n"]
            if other_active_admins == 0:
                raise conflict(
                    "last_admin_required",
                    "organization must retain at least one active administrator",
                )

        before = {"role": m["role"], "status": m["status"]}
        if new_role != m["role"] or new_status != m["status"]:
            c.execute(
                "UPDATE memberships SET role = ?, status = ?, updated_at = ?"
                " WHERE id = ?",
                (new_role, new_status, ts, m["id"]),
            )
            add_audit(
                c, org_id=org_id, actor_id=user.id, action="member.updated",
                target_type="membership", target_id=m["id"],
                before=before, after={"role": new_role, "status": new_status}, ts=ts,
            )

        row = c.execute(
            """
            SELECT m.org_id, m.user_id, u.username, m.role, m.status,
                   m.created_at, m.updated_at
            FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? AND m.user_id = ?
            """,
            (org_id, target_user_id),
        ).fetchone()
        return 200, {"membership": membership_dict(row)}

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_member_update(org_id), idempotency_key, request_body,
        check_perm=lambda c: require_membership(c, user, org_id, admin=True),
        perform=_perform,
    )
    return resp


# ===================================================================== audit

@app.get("/orgs/{org_id}/audit")
def list_audit(
    org_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    # Read-only path (WAL readers never block writers); membership check
    # still raises the uniform 403 for non-members/disabled/non-admins.
    require_membership(conn, user, org_id, admin=True)
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ?", (org_id,)
    ).fetchone()["n"]
    rows = conn.execute(
        """
        SELECT a.*, u.username AS actor_username
        FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
        WHERE a.org_id = ?
        ORDER BY a.id ASC
        LIMIT ? OFFSET ?
        """,
        (org_id, page_size, (page - 1) * page_size),
    ).fetchall()
    items = [
        {
            "id": r["id"],
            "org_id": r["org_id"],
            "created_at": r["created_at"],
            "actor_id": r["actor_id"],
            "actor_username": r["actor_username"],
            "action": r["action"],
            "target_type": r["target_type"],
            "target_id": r["target_id"],
            "before": json.loads(r["before_state"]) if r["before_state"] else None,
            "after": json.loads(r["after_state"]) if r["after_state"] else None,
        }
        for r in rows
    ]
    return {"page": page, "page_size": page_size, "total": total, "items": items}
