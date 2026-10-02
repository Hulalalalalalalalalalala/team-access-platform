"""FastAPI application: organizations, memberships, invitations, audit.

Endpoints
---------
Auth
  POST /auth/register   register with unique username + password
  POST /auth/login      start a session (returns opaque token once)
  POST /auth/logout     invalidate the current session immediately
  POST /auth/password   change own password (revokes all sessions)

Organizations
  POST /orgs                 create an org (creator becomes admin) [idempotent]
  GET  /orgs                 list the caller's organizations
  GET  /orgs/{org_id}/members                 active members: roster
  GET  /orgs/{org_id}/members/me              own membership state
  PATCH /orgs/{org_id}/members/batch          batch role/status change [idempotent]
  PATCH /orgs/{org_id}/members/{user_id}      role/status change   [idempotent]
  DELETE /orgs/{org_id}/members/{user_id}     remove a member      [idempotent]

Invitations
  POST /orgs/{org_id}/invites         admin issues single-use invite [idempotent]
  POST /orgs/{org_id}/invites/revoke  admin revokes an invite
  POST /invites/accept                accept an invite (join the org)

Audit
  GET /orgs/{org_id}/audit?page=&page_size=   admins only, paged read-only
  GET /orgs/{org_id}/audit/scan?cursor=&page_size=
        admins only, snapshot-consistent cursor scan (read-only)
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
from .auth import CurrentUser, _extract_token, current_user, require_membership
from .db import get_conn, init_db, transaction
from .errors import (
    ApiError,
    conflict,
    forbidden,
    install_exception_handlers,
    not_found,
    unauthorized,
)
from .schemas import (
    AcceptInviteRequest,
    BatchUpdateMembersRequest,
    ChangePasswordRequest,
    CreateDelegationRequest,
    CreateInviteRequest,
    CreateOrgRequest,
    LoginRequest,
    RegisterRequest,
    RevokeInviteRequest,
    UpdateMemberRequest,
)
from .secret import sign_text, verify_signed_text
from .security import (
    generate_batch_id,
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
        # Re-read the password hash INSIDE the write transaction. BEGIN
        # IMMEDIATE serializes this login against a concurrent
        # POST /auth/password change, so exactly one of them commits first:
        # * the password change committed first -> the stored hash no longer
        #   matches the one just verified, and this login fails closed with
        #   the same 401 as a wrong password instead of issuing a session
        #   that would bypass the change;
        # * this login commits first -> the password change's own
        #   transaction revokes every live session of the account, the one
        #   created here included, so the returned token is dead on its next
        #   use.
        # Either way an old-password login can never leave a usable session
        # behind once the change has taken effect. (Hashes are salted, so
        # any password change also changes the stored string.)
        fresh = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_row["id"],)
        ).fetchone()
        if fresh is None or fresh["password_hash"] != user_row["password_hash"]:
            raise ApiError(401, "invalid_credentials", "invalid username or password")
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


@app.post("/auth/password")
def change_password(
    body: ChangePasswordRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    authorization: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
) -> dict[str, bool]:
    """Change the password of the account that owns the session.

    Works for any authenticated account — organization membership or member
    status is irrelevant. Body validation (422) happens before the session
    check, so malformed bodies never reveal session state. On success the
    password hash and the revocation of EVERY existing session of the
    account (including the one making this request) commit in ONE transaction:
    they take effect together or not at all. No replacement token is issued;
    the user must log in again with the new password.
    """
    # Hashing is a pure function of the new password; doing it before the
    # write transaction keeps the write-lock hold time short.
    new_hash = hash_password(body.new_password)
    token = _extract_token(authorization, x_session_token)
    if not token:
        raise unauthorized()
    ts = now_ts()
    with transaction(conn):
        # The session is (re-)validated INSIDE the write transaction.
        # BEGIN IMMEDIATE serializes concurrent changers, so a second
        # in-flight request for the same account observes the revocation
        # committed by the winner and fails closed with 401 — exactly one
        # concurrent change can succeed. A session that was logged out or
        # expired after the request started is likewise rejected here.
        row = conn.execute(
            """
            SELECT s.id AS session_id, s.expires_at, s.revoked_at,
                   u.id AS user_id, u.password_hash AS password_hash
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (hash_token(token),),
        ).fetchone()
        if row is None or row["revoked_at"] is not None or row["expires_at"] <= ts:
            raise unauthorized("invalid or expired session")
        if not verify_password(body.current_password, row["password_hash"]):
            # Wrong current password: nothing changes (session included).
            raise ApiError(403, "invalid_current_password", "current password is incorrect")
        if body.current_password == body.new_password:
            raise conflict(
                "password_unchanged", "new password must differ from the current password"
            )
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, row["user_id"]),
        )
        # Revoke every still-live session of THIS account on every device,
        # the requesting one included. Other accounts are untouched.
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, row["user_id"]),
        )
    return {"password_changed": True}


# ============================================================== organizations

def _run_idempotent(
    conn: sqlite3.Connection,
    user: CurrentUser,
    scope: str,
    key: Optional[str],
    body: bytes,
    check_perm: Callable[[sqlite3.Connection], None],
    perform: Callable[[sqlite3.Connection, int], tuple[int, dict[str, Any]]],
    replay_check: Optional[Callable[[sqlite3.Connection, sqlite3.Row], None]] = None,
) -> tuple[int, dict[str, Any]]:
    """Execute ``perform`` with Idempotency-Key semantics inside one txn.

    * same operator + scope + key + same body -> stored first success
    * same key, different body                -> 409 idempotency_conflict
    * permission is re-checked on every attempt, including stored replays
    * ``replay_check`` (when given) runs on a stored replay after the
      permission check, so an operation that was authorized at creation
      time can be re-authorized against current state (e.g. the delegation
      that backed an invite must still be active on replay)
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
        if replay_check is not None:
            replay_check(conn, row)
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


# ================================================================ delegations

DELEGATION_DURATION_MIN = 60
DELEGATION_DURATION_MAX = 86400


def delegation_dict(
    row: sqlite3.Row,
    *,
    grantor_username: Optional[str] = None,
    delegate_username: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "grantor_id": row["grantor_id"],
        "delegate_id": row["delegate_id"],
        "grantor_username": grantor_username,
        "delegate_username": delegate_username,
        "status": row["status"],
        "reason": row["invalid_reason"],
        "starts_at": row["starts_at"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "revoked_at": row["revoked_at"],
        "revoked_by": row["revoked_by"],
    }


def _active_delegation(c: sqlite3.Connection, org_id: int, user_id: int, ts: int) -> sqlite3.Row:
    """Return the caller's currently active delegation or raise 403.

    A delegation is active only while status is ``active`` AND the expiry
    instant has not arrived; from the expiry moment on it authorizes nothing.
    """
    d = c.execute(
        """
        SELECT * FROM delegations
        WHERE org_id = ? AND delegate_id = ? AND status = 'active'
        """,
        (org_id, user_id),
    ).fetchone()
    if d is None or d["expires_at"] <= ts:
        raise forbidden()
    return d


def _sweep_delegations(c: sqlite3.Connection, org_id: int, ts: int) -> None:
    """Lazy maintenance, called inside write transactions.

    * time expiry: active delegations past their expiry become ``expired``
      (automatic, no audit row);
    * eligibility: an active delegation whose grantor is no longer an active
      admin, or whose delegate is no longer an active ordinary member, is
      permanently ``invalidated``. The PATCH member endpoint performs the
      primary, actor-bearing invalidation; this sweep is the safety net for
      state changes that bypass it (e.g. direct on-disk manipulation), and
      it records the invalidation with a NULL actor.
    """
    c.execute(
        "UPDATE delegations SET status = 'expired'"
        " WHERE org_id = ? AND status = 'active' AND expires_at <= ?",
        (org_id, ts),
    )
    rows = c.execute(
        """
        SELECT d.id,
               gm.role AS g_role, gm.status AS g_status,
               dm.role AS d_role, dm.status AS d_status
        FROM delegations d
        LEFT JOIN memberships gm
               ON gm.org_id = d.org_id AND gm.user_id = d.grantor_id
        LEFT JOIN memberships dm
               ON dm.org_id = d.org_id AND dm.user_id = d.delegate_id
        WHERE d.org_id = ? AND d.status = 'active'
        """,
        (org_id,),
    ).fetchall()
    for r in rows:
        reasons: list[str] = []
        if r["g_role"] != "admin" or r["g_status"] != "active":
            reasons.append("grantor_not_admin")
        if r["d_role"] != "member" or r["d_status"] != "active":
            reasons.append("delegate_ineligible")
        if not reasons:
            continue
        reason = ",".join(reasons)
        c.execute(
            "UPDATE delegations SET status = 'invalidated', invalid_reason = ?, invalidated_at = ?"
            " WHERE id = ?",
            (reason, ts, r["id"]),
        )
        add_audit(
            c, org_id=org_id, actor_id=None, action="delegation.invalidated",
            target_type="delegation", target_id=r["id"],
            before={"status": "active"},
            after={"status": "invalidated", "reason": reason}, ts=ts,
        )


def _invalidate_delegations_for_member_change(
    c: sqlite3.Connection,
    *,
    org_id: int,
    target_user_id: int,
    new_role: str,
    new_status: str,
    actor_id: int,
    ts: int,
) -> None:
    """Invalidate active delegations affected by a member role/status change.

    Runs in the SAME transaction as the member change, so the change and the
    invalidation audit rows commit atomically. Invalidation is permanent:
    later restoring the role/status does not revive anything.
    """
    rows = c.execute(
        """
        SELECT d.id, d.grantor_id, d.delegate_id
        FROM delegations d
        WHERE d.org_id = ? AND d.status = 'active'
          AND (d.grantor_id = ? OR d.delegate_id = ?)
        """,
        (org_id, target_user_id, target_user_id),
    ).fetchall()
    for r in rows:
        reasons: list[str] = []
        if r["grantor_id"] == target_user_id and (new_role != "admin" or new_status != "active"):
            reasons.append("grantor_not_admin")
        if r["delegate_id"] == target_user_id and (new_role != "member" or new_status != "active"):
            reasons.append("delegate_ineligible")
        if not reasons:
            continue
        reason = ",".join(reasons)
        c.execute(
            "UPDATE delegations SET status = 'invalidated', invalid_reason = ?, invalidated_at = ?"
            " WHERE id = ?",
            (reason, ts, r["id"]),
        )
        add_audit(
            c, org_id=org_id, actor_id=actor_id, action="delegation.invalidated",
            target_type="delegation", target_id=r["id"],
            before={"status": "active"},
            after={"status": "invalidated", "reason": reason,
                   "triggered_by": target_user_id}, ts=ts,
        )


def _invalidate_delegations_for_batch(
    c: sqlite3.Connection,
    *,
    org_id: int,
    new_states: dict[int, tuple[str, str]],
    actor_id: int,
    batch_id: str,
    ts: int,
) -> None:
    """Invalidate active delegations affected by a batch member change.

    ``new_states`` maps user_id -> (new_role, new_status) for members that
    actually changed. Commits in the SAME transaction as the batch, so the
    member changes and every invalidation row live or die together. When one
    delegation's grantor AND delegate both lose eligibility in the same
    batch, exactly ONE invalidation row is written carrying BOTH reasons.
    Invalidation is permanent: restoring members in a later batch never
    revives anything.
    """
    if not new_states:
        return
    rows = c.execute(
        """
        SELECT d.id, d.grantor_id, d.delegate_id
        FROM delegations d
        WHERE d.org_id = ? AND d.status = 'active'
        """,
        (org_id,),
    ).fetchall()
    for r in rows:
        reasons: list[str] = []
        triggered: list[int] = []
        g_state = new_states.get(r["grantor_id"])
        if g_state is not None:
            if g_state[0] != "admin" or g_state[1] != "active":
                reasons.append("grantor_not_admin")
                triggered.append(r["grantor_id"])
        d_state = new_states.get(r["delegate_id"])
        if d_state is not None:
            if d_state[0] != "member" or d_state[1] != "active":
                reasons.append("delegate_ineligible")
                if r["delegate_id"] not in triggered:
                    triggered.append(r["delegate_id"])
        if not reasons:
            continue
        reason = ",".join(reasons)
        c.execute(
            "UPDATE delegations SET status = 'invalidated', invalid_reason = ?, invalidated_at = ?"
            " WHERE id = ?",
            (reason, ts, r["id"]),
        )
        add_audit(
            c, org_id=org_id, actor_id=actor_id, action="delegation.invalidated",
            target_type="delegation", target_id=r["id"],
            before={"status": "active"},
            after={"status": "invalidated", "reason": reason,
                   "triggered_by": triggered},
            batch_id=batch_id, ts=ts,
        )


@app.post("/orgs/{org_id}/delegations", status_code=201)
def create_delegation(
    org_id: int,
    body: CreateDelegationRequest,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        # Expired delegations no longer block a fresh grant.
        _sweep_delegations(c, org_id, ts)
        m = c.execute(
            "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, body.user_id),
        ).fetchone()
        if m is None or m["role"] != "member" or m["status"] != "active":
            # Missing user, non-member, disabled or administrator: one code.
            raise conflict("ineligible_member", "target is not an active ordinary member")
        existing = c.execute(
            "SELECT id FROM delegations"
            " WHERE org_id = ? AND delegate_id = ? AND status = 'active'",
            (org_id, body.user_id),
        ).fetchone()
        if existing is not None:
            raise conflict("delegation_exists", "member already has an active delegation")
        try:
            cur = c.execute(
                """
                INSERT INTO delegations
                    (org_id, grantor_id, delegate_id, status,
                     created_at, starts_at, expires_at)
                VALUES (?, ?, ?, 'active', ?, ?, ?)
                """,
                (org_id, user.id, body.user_id, ts, ts, ts + body.duration_seconds),
            )
        except sqlite3.IntegrityError:
            # Concurrent grant for the same member: unique partial index.
            raise conflict("delegation_exists", "member already has an active delegation")
        d_id = cur.lastrowid
        add_audit(
            c, org_id=org_id, actor_id=user.id, action="delegation.created",
            target_type="delegation", target_id=d_id, before=None,
            after={"id": d_id, "grantor_id": user.id, "delegate_id": body.user_id,
                   "starts_at": ts, "expires_at": ts + body.duration_seconds},
            ts=ts,
        )
        row = c.execute("SELECT * FROM delegations WHERE id = ?", (d_id,)).fetchone()
        return 201, delegation_dict(row)

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_delegation_create(org_id), idempotency_key, request_body,
        check_perm=lambda c: require_membership(c, user, org_id, admin=True),
        perform=_perform,
    )
    return resp


@app.get("/orgs/{org_id}/delegations")
def list_delegations(
    org_id: int,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    with transaction(conn):
        m = require_membership(conn, user, org_id)
        _sweep_delegations(conn, org_id, now_ts())
        if m["role"] == "admin":
            # Administrators see every delegation in the organization.
            rows = conn.execute(
                """
                SELECT d.*, gu.username AS grantor_username, du.username AS delegate_username
                FROM delegations d
                JOIN users gu ON gu.id = d.grantor_id
                JOIN users du ON du.id = d.delegate_id
                WHERE d.org_id = ?
                ORDER BY d.id DESC
                """,
                (org_id,),
            ).fetchall()
        else:
            # Delegates only ever see their own.
            rows = conn.execute(
                """
                SELECT d.*, gu.username AS grantor_username, du.username AS delegate_username
                FROM delegations d
                JOIN users gu ON gu.id = d.grantor_id
                JOIN users du ON du.id = d.delegate_id
                WHERE d.org_id = ? AND d.delegate_id = ?
                ORDER BY d.id DESC
                """,
                (org_id, user.id),
            ).fetchall()
    return {
        "delegations": [
            delegation_dict(
                r, grantor_username=r["grantor_username"],
                delegate_username=r["delegate_username"],
            )
            for r in rows
        ]
    }


@app.post("/orgs/{org_id}/delegations/{delegation_id}/revoke")
def revoke_delegation(
    org_id: int,
    delegation_id: int,
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    with transaction(conn):
        require_membership(conn, user, org_id, admin=True)
        ts = now_ts()
        d = conn.execute(
            "SELECT * FROM delegations WHERE id = ? AND org_id = ?",
            (delegation_id, org_id),
        ).fetchone()
        if d is None:
            # Missing or belongs to another org: uniform 404.
            raise not_found("not_found", "delegation not found")
        if d["status"] != "active":
            # Idempotent no-op: repeated revocation succeeds but writes no
            # state change and no second audit row.
            row = conn.execute(
                "SELECT * FROM delegations WHERE id = ?", (delegation_id,)
            ).fetchone()
            return delegation_dict(row)
        conn.execute(
            "UPDATE delegations SET status = 'revoked', revoked_at = ?, revoked_by = ?"
            " WHERE id = ?",
            (ts, user.id, delegation_id),
        )
        add_audit(
            conn, org_id=org_id, actor_id=user.id, action="delegation.revoked",
            target_type="delegation", target_id=delegation_id,
            before={"status": "active"},
            after={"status": "revoked", "revoked_by": user.id}, ts=ts,
        )
        row = conn.execute(
            "SELECT * FROM delegations WHERE id = ?", (delegation_id,)
        ).fetchone()
    return delegation_dict(row)


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
    # Delegation backing the current operation, captured by check_perm and
    # consumed by perform inside the SAME transaction (no race possible).
    backing: dict[str, Any] = {}

    def _check_perm(c: sqlite3.Connection) -> None:
        m = require_membership(c, user, org_id)
        if m["role"] == "admin":
            # Administrators need no delegation.
            backing["delegation"] = None
        else:
            # Ordinary members may only issue invites while their delegation
            # is active; from the expiry moment on this raises 403.
            backing["delegation"] = _active_delegation(c, org_id, user.id, now_ts())

    def _replay_check(c: sqlite3.Connection, row: sqlite3.Row) -> None:
        # An idempotent retry must still be authorized by the ORIGINAL
        # delegation that backed the stored response: if that delegation is
        # no longer active the retry is 403, even if a fresh delegation now
        # exists. Admin-issued replays require admin membership again.
        resp = idempotency.replay_body(row)
        d_id = resp.get("delegation_id")
        if d_id is None:
            require_membership(c, user, org_id, admin=True)
            return
        d = c.execute(
            "SELECT * FROM delegations WHERE id = ? AND org_id = ?", (d_id, org_id)
        ).fetchone()
        if d is None or d["status"] != "active" or d["expires_at"] <= now_ts():
            raise forbidden()

    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        d = backing.get("delegation")
        delegation_id = d["id"] if d is not None else None
        if d is not None and body.role != "member":
            # Delegates may only issue member invites.
            raise forbidden()
        raw_token = generate_invite_token()
        expires_at = ts + config.INVITE_TTL_SECONDS
        cur = c.execute(
            """
            INSERT INTO invites
                (org_id, token_hash, invite_username, role, status,
                 created_by, created_at, expires_at, used_at, used_by, revoked_at,
                 delegation_id)
            VALUES (?, ?, ?, ?, 'available', ?, ?, ?, NULL, NULL, NULL, ?)
            """,
            (org_id, hash_token(raw_token), body.username, body.role,
             user.id, ts, expires_at, delegation_id),
        )
        invite_id = cur.lastrowid
        add_audit(
            c, org_id=org_id, actor_id=user.id, action="invite.created",
            target_type="invite", target_id=invite_id,
            before=None,
            after={"id": invite_id, "username": body.username, "role": body.role,
                   "status": "available", "expires_at": expires_at,
                   "delegation_id": delegation_id},
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
            "delegation_id": delegation_id,
        }

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_invite_create(org_id), idempotency_key, request_body,
        check_perm=_check_perm, replay_check=_replay_check, perform=_perform,
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
        m = require_membership(conn, user, org_id)
        ts = now_ts()
        _sweep_delegations(conn, org_id, ts)
        inv = conn.execute(
            "SELECT * FROM invites WHERE org_id = ? AND token_hash = ?",
            (org_id, hash_token(body.token)),
        ).fetchone()
        if m["role"] == "admin":
            # Administrators revoke any invite in the organization.
            if inv is None or inv["status"] != "available" or inv["expires_at"] <= ts:
                # Missing, already used/revoked or expired: same stable code.
                raise conflict("invite_unavailable", "invite is not available")
            delegation_id = inv["delegation_id"]
        else:
            # Delegates may only revoke invites they issued by virtue of
            # their CURRENT delegation: other delegations' invites and
            # admin invites are out of scope (403); unavailable invites
            # follow the existing invite rules (409).
            d = _active_delegation(conn, org_id, user.id, ts)
            if inv is None or inv["delegation_id"] != d["id"]:
                raise forbidden()
            if inv["status"] != "available" or inv["expires_at"] <= ts:
                raise conflict("invite_unavailable", "invite is not available")
            delegation_id = d["id"]
        before = {"id": inv["id"], "status": inv["status"],
                  "delegation_id": inv["delegation_id"]}
        conn.execute(
            "UPDATE invites SET status = 'revoked', revoked_at = ? WHERE id = ?",
            (ts, inv["id"]),
        )
        add_audit(
            conn, org_id=org_id, actor_id=user.id, action="invite.revoked",
            target_type="invite", target_id=inv["id"],
            before=before,
            after={"id": inv["id"], "status": "revoked", "delegation_id": delegation_id},
            ts=ts,
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

@app.patch("/orgs/{org_id}/members/batch")
def batch_update_members(
    org_id: int,
    body: BatchUpdateMembersRequest,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    # Cross-item validation (item shape/enums and the 1..100 bound are already
    # enforced by pydantic -> same stable 422 envelope). These checks run
    # before authorization, matching the single-member entry point.
    seen: set[int] = set()
    for ch in body.changes:
        if ch.role is None and ch.status is None:
            raise ApiError(422, "validation_error", "role or status is required")
        if ch.user_id in seen:
            raise ApiError(422, "validation_error", "duplicate user_id in changes")
        seen.add(ch.user_id)

    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        # Load every target first; a target outside THIS organization fails
        # the whole batch with 404 and reveals nothing about other orgs.
        ordered: list[tuple[sqlite3.Row, str, str]] = []
        for ch in body.changes:
            m = c.execute(
                """
                SELECT m.*, u.username FROM memberships m JOIN users u ON u.id = m.user_id
                WHERE m.org_id = ? AND m.user_id = ?
                """,
                (org_id, ch.user_id),
            ).fetchone()
            if m is None:
                raise not_found("member_not_found", "member not found")
            new_role = ch.role or m["role"]
            new_status = ch.status or m["status"]
            ordered.append((m, new_role, new_status))

        # Order-independent last-active-admin invariant. Count active admins
        # that are untouched by the batch, then add targeted members whose
        # FINAL state is an active admin (a promotion in the same batch can
        # offset a demotion regardless of list order).
        total_active_admins = c.execute(
            "SELECT COUNT(*) AS n FROM memberships"
            " WHERE org_id = ? AND role = 'admin' AND status = 'active'",
            (org_id,),
        ).fetchone()["n"]
        targeted_active_admins = sum(
            1 for m, _, _ in ordered if m["role"] == "admin" and m["status"] == "active"
        )
        surviving_targeted = sum(
            1 for _, nr, ns in ordered if nr == "admin" and ns == "active"
        )
        untouched_admins = total_active_admins - targeted_active_admins
        if untouched_admins + surviving_targeted == 0:
            raise conflict(
                "last_admin_required",
                "organization must retain at least one active administrator",
            )

        batch_id = generate_batch_id()
        changed_states: dict[int, tuple[str, str]] = {}
        for m, new_role, new_status in ordered:
            before = {"role": m["role"], "status": m["status"]}
            if new_role != m["role"] or new_status != m["status"]:
                # Unchanged members are returned but keep updated_at and get
                # no audit row.
                c.execute(
                    "UPDATE memberships SET role = ?, status = ?, updated_at = ?"
                    " WHERE id = ?",
                    (new_role, new_status, ts, m["id"]),
                )
                changed_states[m["user_id"]] = (new_role, new_status)
                add_audit(
                    c, org_id=org_id, actor_id=user.id, action="member.updated",
                    target_type="membership", target_id=m["id"],
                    before=before, after={"role": new_role, "status": new_status},
                    batch_id=batch_id, ts=ts,
                )

        # Delegation invalidation commits in the SAME transaction; one row
        # per affected active delegation even when both parties lose
        # eligibility in this batch.
        _invalidate_delegations_for_batch(
            c, org_id=org_id, new_states=changed_states,
            actor_id=user.id, batch_id=batch_id, ts=ts,
        )

        # Final member info in SUBMISSION order.
        final_rows: dict[int, sqlite3.Row] = {}
        rows = c.execute(
            """
            SELECT m.org_id, m.user_id, u.username, m.role, m.status,
                   m.created_at, m.updated_at
            FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ?
            """,
            (org_id,),
        ).fetchall()
        for r in rows:
            final_rows[r["user_id"]] = r
        members_out = [membership_dict(final_rows[ch.user_id]) for ch in body.changes]
        return 200, {"batch_id": batch_id, "members": members_out}

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_member_batch_update(org_id),
        idempotency_key, request_body,
        check_perm=lambda c: require_membership(c, user, org_id, admin=True),
        perform=_perform,
    )
    return resp


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
        changed = new_role != m["role"] or new_status != m["status"]
        if changed:
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
            # Member change invalidates affected delegations in the SAME
            # transaction; the change and the invalidation audit commit or
            # roll back together.
            _invalidate_delegations_for_member_change(
                c, org_id=org_id, target_user_id=target_user_id,
                new_role=new_role, new_status=new_status, actor_id=user.id, ts=ts,
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


@app.delete("/orgs/{org_id}/members/{target_user_id}")
def remove_member(
    org_id: int,
    target_user_id: int,
    request_body: bytes = Depends(raw_body),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key", max_length=128),
) -> dict[str, Any]:
    """Permanently remove a member from the organization.

    Unlike disable/enable (which keep the membership row), removal deletes it:
    the target vanishes from the roster and from their own organization list,
    and every session loses access to THIS organization on the next request.
    The account, its sessions and its memberships in other organizations are
    untouched. Active admins may remove anyone — active, disabled, or
    themselves — except the organization's last active administrator.
    """

    def _perform(c: sqlite3.Connection, ts: int) -> tuple[int, dict[str, Any]]:
        m = c.execute(
            "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, target_user_id),
        ).fetchone()
        if m is None:
            # Target is not in THIS organization. Authorization has already
            # passed, so this reveals nothing about organization existence.
            raise not_found("member_not_found", "member not found")

        # Last-active-administrator invariant (self-removal included).
        # A DISABLED admin does not count toward the quota, so removing one
        # never trips this check; BEGIN IMMEDIATE serializes concurrent
        # removals/adjustments so zero active admins is impossible.
        if m["role"] == "admin" and m["status"] == "active":
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

        urow = c.execute(
            "SELECT username FROM users WHERE id = ?", (target_user_id,)
        ).fetchone()
        target_username = urow["username"] if urow is not None else None
        before = {
            "user_id": target_user_id,
            "username": target_username,
            "role": m["role"],
            "status": m["status"],
            "created_at": m["created_at"],
            "updated_at": m["updated_at"],
        }

        # Revoke every still-usable invite bound to the target's USERNAME that
        # exists at this instant. Used/revoked/expired invites keep their
        # state and rules; invites issued AFTER this removal commits are new
        # rows and stay usable (rejoining via a fresh invite is allowed).
        revoked_rows = c.execute(
            """
            SELECT id FROM invites
            WHERE org_id = ? AND invite_username = ?
              AND status = 'available' AND expires_at > ?
            """,
            (org_id, target_username, ts),
        ).fetchall()
        revoked_ids = [r["id"] for r in revoked_rows]
        if revoked_ids:
            placeholders = ",".join("?" for _ in revoked_ids)
            c.execute(
                f"UPDATE invites SET status = 'revoked', revoked_at = ?"
                f" WHERE id IN ({placeholders})",
                (ts, *revoked_ids),
            )
            for iid in revoked_ids:
                add_audit(
                    c, org_id=org_id, actor_id=user.id, action="invite.revoked",
                    target_type="invite", target_id=iid,
                    before={"status": "available"},
                    after={"status": "revoked", "reason": "member_removed",
                           "removed_user_id": target_user_id},
                    ts=ts,
                )

        # Permanently invalidate every active delegation in which the target
        # participates as grantor or delegate, reusing the existing
        # invalidation reasons. Rejoining later never revives them. Sweep
        # first so a merely time-expired delegation keeps its ``expired``
        # state instead of being mislabelled; only still-EFFECTIVE
        # delegations are invalidated here. A delegation never has the same
        # user as both grantor and delegate, so at most one reason applies
        # per row.
        _sweep_delegations(c, org_id, ts)
        deleg_rows = c.execute(
            """
            SELECT id, grantor_id, delegate_id FROM delegations
            WHERE org_id = ? AND status = 'active'
              AND (grantor_id = ? OR delegate_id = ?)
            """,
            (org_id, target_user_id, target_user_id),
        ).fetchall()
        invalidated: list[dict[str, Any]] = []
        for r in deleg_rows:
            reason = (
                "grantor_not_admin"
                if r["grantor_id"] == target_user_id
                else "delegate_ineligible"
            )
            c.execute(
                "UPDATE delegations SET status = 'invalidated', invalid_reason = ?,"
                " invalidated_at = ? WHERE id = ?",
                (reason, ts, r["id"]),
            )
            add_audit(
                c, org_id=org_id, actor_id=user.id, action="delegation.invalidated",
                target_type="delegation", target_id=r["id"],
                before={"status": "active"},
                after={"status": "invalidated", "reason": reason,
                       "triggered_by": target_user_id, "trigger": "member_removed"},
                ts=ts,
            )
            invalidated.append({"id": r["id"], "reason": reason})

        # The membership itself disappears (disable/enable keep the row;
        # removal does not). ON DELETE rules do not apply here: the user,
        # sessions, invites and historical audit rows all survive.
        c.execute("DELETE FROM memberships WHERE id = ?", (m["id"],))

        add_audit(
            c, org_id=org_id, actor_id=user.id, action="member.removed",
            target_type="membership", target_id=f"{org_id}:{target_user_id}",
            before=before,
            after={"org_id": org_id, "user_id": target_user_id,
                   "username": target_username,
                   "revoked_invite_ids": revoked_ids,
                   "invalidated_delegations": invalidated},
            ts=ts,
        )
        return 200, {"org_id": org_id, "user_id": target_user_id, "removed": True}

    def _replay_check(c: sqlite3.Connection, row: sqlite3.Row) -> None:
        # A DELETE carries no body, so the request fingerprint cannot
        # distinguish targets: a stored key replayed against a DIFFERENT
        # target (or org) is an idempotency conflict, never a second removal.
        resp = idempotency.replay_body(row)
        if resp.get("org_id") != org_id or resp.get("user_id") != target_user_id:
            raise conflict(
                "idempotency_conflict",
                "Idempotency-Key was already used for a different target",
            )

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_member_remove(org_id),
        idempotency_key, request_body,
        check_perm=lambda c: require_membership(c, user, org_id, admin=True),
        perform=_perform, replay_check=_replay_check,
    )
    return resp


# ===================================================================== audit

def _audit_item(r: sqlite3.Row) -> dict[str, Any]:
    """Public shape of one audit entry (shared by both read endpoints)."""
    return {
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
        "batch_id": r["batch_id"],
    }


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
    items = [_audit_item(r) for r in rows]
    return {"page": page, "page_size": page_size, "total": total, "items": items}


# ------------------------------------------------------------- audit scan

_CURSOR_VERSION = 1


def _encode_scan_cursor(org_id: int, end_id: int, position: int) -> str:
    """Opaque continuation token for an audit scan.

    The cursor only carries a read position: the organization, the scan's
    fixed upper id bound (the snapshot end) and the id of the last entry
    already returned. It is HMAC-signed with the server key, so clients can
    neither read nor alter it, and deterministic, so re-issuing a cursor for
    an unchanged position yields the identical string. It never substitutes
    for authentication — every batch re-checks the caller's current admin
    membership.
    """
    payload = json.dumps(
        {"v": _CURSOR_VERSION, "org": org_id, "end": end_id, "pos": position},
        separators=(",", ":"),
    )
    return sign_text(payload)


def _decode_scan_cursor(cursor: str, org_id: int) -> tuple[int, int]:
    """Validate a cursor for THIS organization, returning (end_id, position).

    Anything unrecognized, tampered with, or minted for another organization
    is the same 422 invalid_cursor and reveals no audit content.
    """
    try:
        payload = json.loads(verify_signed_text(cursor))
        end_id = payload["end"]
        position = payload["pos"]
        if (
            payload["v"] != _CURSOR_VERSION
            or payload["org"] != org_id
            or not isinstance(end_id, int)
            or not isinstance(position, int)
            or isinstance(end_id, bool)
            or isinstance(position, bool)
            or end_id < 0
            or position < 0
            or position > end_id
        ):
            raise ValueError
    except Exception:
        raise ApiError(422, "invalid_cursor", "cursor is invalid")
    return end_id, position


@app.get("/orgs/{org_id}/audit/scan")
def scan_audit(
    org_id: int,
    cursor: Optional[str] = Query(default=None),
    page_size: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    """Snapshot-consistent cursor scan of the organization's audit trail.

    The first request (no ``cursor``) fixes the range as every entry of this
    organization committed at that instant: audit ids are monotonic, so the
    range is exactly ``id <= end_id`` and entries written later — even with
    an identical timestamp — can never join it. Follow-up requests pass the
    returned ``next_cursor`` and read strictly after the previous batch's
    last id, so every in-range entry appears exactly once regardless of how
    ``page_size`` changes between batches. The cursor is stateless: repeating
    a request with the same cursor returns the same batch and does not
    consume progress. Authorization is re-checked on every batch against the
    caller's CURRENT membership.
    """
    require_membership(conn, user, org_id, admin=True)
    if cursor is None:
        # Fix the snapshot range [.., end_id] for this organization only;
        # rows committed by other orgs interleave in id space but are
        # filtered out without affecting order or completeness.
        snap = conn.execute(
            "SELECT MAX(id) AS end_id, COUNT(*) AS n FROM audit_logs WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        end_id = snap["end_id"] or 0
        total = snap["n"]
        position = 0
    else:
        end_id, position = _decode_scan_cursor(cursor, org_id)
        # Audit rows are never updated or deleted, so the in-range total is
        # identical for every batch of the scan.
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ? AND id <= ?",
            (org_id, end_id),
        ).fetchone()["n"]
    # Fetch one extra row to learn whether a further batch exists; this ends
    # the scan with next_cursor = null exactly when the final batch is full.
    rows = conn.execute(
        """
        SELECT a.*, u.username AS actor_username
        FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
        WHERE a.org_id = ? AND a.id > ? AND a.id <= ?
        ORDER BY a.id ASC
        LIMIT ?
        """,
        (org_id, position, end_id, page_size + 1),
    ).fetchall()
    has_more = len(rows) > page_size
    items = [_audit_item(r) for r in rows[:page_size]]
    next_cursor = (
        _encode_scan_cursor(org_id, end_id, items[-1]["id"]) if has_more else None
    )
    return {"items": items, "total": total, "next_cursor": next_cursor}
