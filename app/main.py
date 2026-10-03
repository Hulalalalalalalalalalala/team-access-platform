"""FastAPI application: organizations, memberships, invitations, audit.

Endpoints
---------
Auth
  POST /auth/register   register with unique username + password
  POST /auth/login      start a session (returns opaque token once)
  POST /auth/logout     invalidate the current session immediately
  POST /auth/logout-others
                        invalidate every OTHER live session of the account
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
from .auth import (
    CurrentUser,
    _extract_token,
    current_user,
    require_membership,
    revalidate_session,
)
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
    LogoutOthersRequest,
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


@app.post("/auth/logout-others")
def logout_others(
    body: LogoutOthersRequest,
    conn: sqlite3.Connection = Depends(get_conn),
    authorization: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
) -> dict[str, int]:
    """Revoke every OTHER live session of the caller's account.

    Keeps the session making the request (its expiry is untouched) while
    ending the same account's sessions on every other device, without
    changing the password. Works for any authenticated account — organization
    membership or member status is irrelevant. Body validation (422) happens
    before the session check, so malformed bodies never reveal session state.
    The revocation is a single UPDATE inside one transaction: every other
    live session is revoked together or, if the write fails, none is (the
    generic handler then answers 500 internal_error). Already logged-out or
    already expired sessions are not counted in ``revoked_sessions``.
    """
    token = _extract_token(authorization, x_session_token)
    if not token:
        raise unauthorized()
    ts = now_ts()
    with transaction(conn):
        # The session is (re-)validated INSIDE the write transaction.
        # BEGIN IMMEDIATE serializes concurrent logout-others requests (and
        # password changes) for the same account, so a second in-flight
        # request observes the revocation committed by the winner and fails closed
        # with 401 — exactly one concurrent attempt can succeed, and a
        # session that was logged out, revoked or expired after the request
        # started cannot go on to revoke the others.
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
            # Wrong current password: nothing changes (no session revoked).
            raise ApiError(403, "invalid_current_password", "current password is incorrect")
        # Revoke every still-live session of THIS account except the
        # requesting one. Sessions already revoked or already expired
        # (expires_at <= now) are left as they are and not counted. Other
        # accounts, the password, memberships and roles are untouched.
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ?"
            " WHERE user_id = ? AND id != ? AND revoked_at IS NULL AND expires_at > ?",
            (ts, row["user_id"], row["session_id"], ts),
        )
        revoked = cur.rowcount
    return {"revoked_sessions": revoked}


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
    authorization: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
) -> dict[str, Any]:
    # The one session actually carried by THIS request (Bearer or
    # X-Session-Token; ``_extract_token`` keeps the existing precedence).
    # ``user`` only proves it was valid when the request arrived; the
    # creation — and any idempotent replay — must be authorized by the
    # session state at the moment it runs inside the write transaction.
    request_token = _extract_token(authorization, x_session_token)
    if not request_token:  # defense in depth; current_user already 401s here
        raise unauthorized()

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

    def _check_session(c: sqlite3.Connection) -> None:
        # Re-validate INSIDE the IMMEDIATE transaction, before the name check,
        # the idempotency lookup and any write. BEGIN IMMEDIATE serializes us
        # against logout / logout-others / password-change writers: a session
        # revoked or expired while the request waited on the lock fails closed
        # with 401, leaving no organization, no admin membership, no audit and
        # no idempotency record. Another valid session of the account cannot
        # substitute — the check is keyed to this token alone. Runs on the
        # first attempt, the concurrent-key replay, and stored replays alike.
        revalidate_session(c, request_token, now_ts())

    _, resp = _run_idempotent(
        conn, user, idempotency.scope_org_create(), idempotency_key, request_body,
        check_perm=_check_session, perform=_perform,
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


# Eligibility rules behind a delegation, in ONE place. A delegation stays
# effective only while its grantor is an ACTIVE administrator and its
# delegate is an ACTIVE ordinary member of the same organization. Both the
# lazy sweep below and the member-change invalidation after PATCH (single
# and batch entry points) derive their reasons from these predicates, so a
# new eligibility rule is defined here once. Role/status may be None when a
# membership row is missing (e.g. direct on-disk manipulation) — that never
# qualifies.
def _grantor_qualifies(role: Optional[str], status: Optional[str]) -> bool:
    return role == "admin" and status == "active"


def _delegate_qualifies(role: Optional[str], status: Optional[str]) -> bool:
    return role == "member" and status == "active"


def _sweep_delegations(c: sqlite3.Connection, org_id: int, ts: int) -> None:
    """Lazy maintenance, called inside write transactions.

    * time expiry: active delegations past their expiry become ``expired``
      (automatic, no audit row);
    * eligibility: an active delegation whose grantor is no longer an active
      admin, or whose delegate is no longer an active ordinary member, is
      permanently ``invalidated``. The PATCH member endpoints perform the
      primary, actor-bearing invalidation; this sweep is the safety net for
      state changes that bypass them (e.g. direct on-disk manipulation), and
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
        if not _grantor_qualifies(r["g_role"], r["g_status"]):
            reasons.append("grantor_not_admin")
        if not _delegate_qualifies(r["d_role"], r["d_status"]):
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


def _invalidate_delegations_for_member_changes(
    c: sqlite3.Connection,
    *,
    org_id: int,
    changed_states: dict[int, tuple[str, str]],
    actor_id: int,
    ts: int,
    batch_id: Optional[str] = None,
) -> None:
    """Permanently invalidate active delegations hit by member role/status edits.

    Shared by BOTH PATCH member entry points (single member and batch) so the
    eligibility judgement, the delegation status change and the invalidation
    audit live in exactly one place; it runs in the SAME transaction as the
    membership writes, so the member changes and every invalidation row
    commit atomically or roll back together.

    ``changed_states`` maps user_id -> (new_role, new_status) for members
    that ACTUALLY changed. Only delegations tied to a changed member are
    touched: unchanged members get no timestamp update and no audit. Only
    ``active`` delegations qualify, so a row already revoked/invalidated is
    never recorded twice and its stored reason is never rewritten.
    Invalidation is permanent — later restoring role/status never revives
    the delegation (only a fresh grant can).

    When one delegation's grantor AND delegate both lose eligibility in the
    same change set, exactly ONE invalidation row is written; reasons appear
    in the fixed grantor-then-delegate order (``grantor_not_admin`` then
    ``delegate_ineligible``, comma-joined) and ``triggered_by`` lists the
    members actually responsible in that same order without duplicates. The
    audit shape follows the entry point: the single-member path (no
    ``batch_id``) records ``triggered_by`` as the one member id, while the
    batch path records it as a member-id list and stamps ``batch_id``.
    """
    if not changed_states:
        return
    affected_ids = list(changed_states.keys())
    marks = ",".join("?" for _ in affected_ids)
    rows = c.execute(
        f"""
        SELECT d.id, d.grantor_id, d.delegate_id
        FROM delegations d
        WHERE d.org_id = ? AND d.status = 'active'
          AND (d.grantor_id IN ({marks}) OR d.delegate_id IN ({marks}))
        """,
        (org_id, *affected_ids, *affected_ids),
    ).fetchall()
    for r in rows:
        reasons: list[str] = []
        triggered: list[int] = []
        g_state = changed_states.get(r["grantor_id"])
        if g_state is not None and not _grantor_qualifies(g_state[0], g_state[1]):
            reasons.append("grantor_not_admin")
            triggered.append(r["grantor_id"])
        d_state = changed_states.get(r["delegate_id"])
        if d_state is not None and not _delegate_qualifies(d_state[0], d_state[1]):
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
                   # Single-member path keeps the scalar member id; the batch
                   # path carries the ordered, de-duplicated id list.
                   "triggered_by": triggered[0] if batch_id is None else triggered},
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
    authorization: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
) -> dict[str, Any]:
    # The one session actually carried by THIS request (Bearer or
    # X-Session-Token; ``_extract_token`` keeps the existing precedence).
    # ``current_user`` only proves it was valid when the request arrived;
    # authorization must hold when the join takes effect below.
    request_token = _extract_token(authorization, x_session_token)
    if not request_token:  # defense in depth; current_user already 401s here
        raise unauthorized()

    # Strict check order per spec:
    # 0) the carried session is still live AT JOIN TIME (re-checked inside
    #    the write transaction)
    # 1) invite availability  2) username match  3) membership state
    with transaction(conn):
        ts = now_ts()
        # Re-validate the EXACT session carried by this request, INSIDE the
        # IMMEDIATE write transaction. BEGIN IMMEDIATE serializes this accept
        # against the logout / logout-others / password-change transactions
        # (all writers). Once this check reads the session as live and the
        # transaction goes on to claim the invite, no revocation can be
        # committed in between; and if a revocation committed first — this
        # session logged out, all sessions revoked by a password change, or
        # the expiry instant arrived (expires_at <= now) while the request
        # was waiting — the join fails closed with 401. Another valid login
        # of the same account cannot rescue this session: authorization is
        # keyed to this token hash alone. Nothing is written on this path,
        # so the invite stays available and reusable after a fresh login.
        sess = conn.execute(
            """
            SELECT s.id, s.expires_at, s.revoked_at,
                   u.id AS user_id, u.username AS username
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (hash_token(request_token),),
        ).fetchone()
        if sess is None or sess["revoked_at"] is not None or sess["expires_at"] <= ts:
            raise unauthorized("invalid or expired session")
        actor_id = sess["user_id"]
        actor_username = sess["username"]

        inv = conn.execute(
            "SELECT * FROM invites WHERE token_hash = ?",
            (hash_token(body.token),),
        ).fetchone()
        if inv is None:
            raise conflict("invite_unavailable", "invite is not available")
        if inv["status"] != "available" or inv["expires_at"] <= ts:
            # expired / revoked / already used all share this code
            raise conflict("invite_unavailable", "invite is not available")
        if inv["invite_username"] != actor_username:
            raise ApiError(403, "username_mismatch", "invite is bound to another user")
        existing = conn.execute(
            "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
            (inv["org_id"], actor_id),
        ).fetchone()
        if existing is not None:
            # Existing membership (any role/status) is never overwritten.
            raise conflict("already_member", "user is already a member of the organization")

        # Conditional claim: only one concurrent acceptor can flip the row.
        cur = conn.execute(
            "UPDATE invites SET status = 'used', used_at = ?, used_by = ?"
            " WHERE id = ? AND status = 'available' AND ? < expires_at",
            (ts, actor_id, inv["id"], ts),
        )
        if cur.rowcount == 0:
            raise conflict("invite_unavailable", "invite is not available")

        conn.execute(
            "INSERT INTO memberships (org_id, user_id, role, status, created_at, updated_at)"
            " VALUES (?, ?, ?, 'active', ?, ?)",
            (inv["org_id"], actor_id, inv["role"], ts, ts),
        )
        add_audit(
            conn, org_id=inv["org_id"], actor_id=actor_id, action="invite.accepted",
            target_type="membership", target_id=f"{inv['org_id']}:{actor_id}",
            before=None,
            after={"org_id": inv["org_id"], "user_id": actor_id,
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
            (inv["org_id"], actor_id),
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

    # The one session actually carried by THIS request (Bearer or
    # X-Session-Token; ``current_user`` already applied the existing
    # precedence and proved it valid when the request arrived). That arrival
    # check alone is not enough: the request may then wait behind the write
    # lock, and the session can be logged out, revoked by logout-others or a
    # password change, or reach its expiry while waiting. The batch must be
    # authorized by the session state when it actually takes effect, so the
    # SAME session is re-validated INSIDE the write transaction (see
    # ``_check_perm``) — exactly as the single-member entry point does.
    request_token = user.token

    def _check_perm(c: sqlite3.Connection) -> None:
        # Re-validate the EXACT session this request carries, INSIDE the
        # IMMEDIATE write transaction, before any other check. BEGIN
        # IMMEDIATE serializes this batch against the logout /
        # logout-others / password-change transactions (all writers): once
        # this check reads the session as live and the transaction goes on to
        # change members, no revocation can commit in between; and if a
        # revocation committed first — or the expiry instant arrived
        # (expires_at <= now) while the request was waiting — the whole batch
        # fails closed with 401. Another still-valid session of the same
        # account, or an unchanged administrator identity, cannot rescue this
        # one: authorization is keyed to this token hash alone. Conversely,
        # revoking only the account's OTHER sessions leaves this one live and
        # the batch proceeds.
        #
        # This runs ahead of the membership check (403), the per-target
        # lookups (404), the last-admin invariant (409) and the idempotency
        # lookup (409 / stored replay), so an invalid session is always
        # answered 401 first; and it runs before anything is written, so a
        # 401 here leaves every target's role/status/updated_at untouched,
        # invalidates no delegation and stores no idempotency record — on
        # first attempts (keyed or not) and on replays of a stored success
        # alike (``_run_idempotent`` calls ``check_perm`` on every path
        # before any replay is returned, and a rejected replay never rewrites
        # the stored success).
        revalidate_session(c, request_token, now_ts())
        require_membership(c, user, org_id, admin=True)

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
        _invalidate_delegations_for_member_changes(
            c, org_id=org_id, changed_states=changed_states,
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
        check_perm=_check_perm,
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

    # The one session actually carried by THIS request (Bearer or
    # X-Session-Token; ``current_user`` already applied the existing
    # precedence and proved it valid when the request arrived). That arrival
    # check alone is not enough: the request may then wait behind the write
    # lock, and the session can be logged out, revoked by logout-others or a
    # password change, or reach its expiry while waiting. The adjustment must
    # be authorized by the session state when it actually takes effect, so
    # the SAME session is re-validated INSIDE the write transaction (see
    # ``_check_perm``).
    request_token = user.token

    def _check_perm(c: sqlite3.Connection) -> None:
        # Re-validate the EXACT session this request carries, INSIDE the
        # IMMEDIATE write transaction, before any other check. BEGIN
        # IMMEDIATE serializes this adjustment against the logout /
        # logout-others / password-change transactions (all writers): once
        # this check reads the session as live and the transaction goes on to
        # change the member, no revocation can commit in between; and if a
        # revocation committed first — or the expiry instant arrived
        # (expires_at <= now) while the request was waiting — the adjustment
        # fails closed with 401. Another still-valid session of the same
        # account cannot rescue this one: authorization is keyed to this
        # token hash alone. Conversely, revoking only the account's OTHER
        # sessions leaves this one live and the adjustment proceeds.
        #
        # This runs ahead of the membership check (403), the target lookup
        # (404), the last-admin invariant (409) and the idempotency lookup
        # (409 / stored replay), so an invalid session is always answered 401
        # first; and it runs before anything is written, so a 401 here keeps
        # the target's role/status/updated_at untouched, invalidates no
        # delegation and stores no idempotency record — on first attempts
        # (keyed or not) and on replays of a stored success alike
        # (``_run_idempotent`` calls ``check_perm`` on every path before any
        # replay is returned, and a rejected replay never rewrites the stored
        # success).
        revalidate_session(c, request_token, now_ts())
        require_membership(c, user, org_id, admin=True)

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
            # roll back together. The single-member path passes a one-entry
            # change set and no batch_id, so the audit keeps its scalar
            # member-id ``triggered_by`` shape.
            _invalidate_delegations_for_member_changes(
                c, org_id=org_id,
                changed_states={target_user_id: (new_role, new_status)},
                actor_id=user.id, ts=ts,
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
        check_perm=_check_perm,
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
    # The one session actually carried by THIS request (Bearer or
    # X-Session-Token; ``current_user`` already applied the existing
    # precedence and proved it valid when the request arrived). That arrival
    # check alone is not enough: the request may then wait behind the write
    # lock, and the session can be logged out, revoked by logout-others or a
    # password change, or reach its expiry while waiting. Authorization must
    # hold when the removal takes effect, so the SAME session is re-validated
    # INSIDE the write transaction (see ``_check_perm``).
    request_token = user.token

    def _check_perm(c: sqlite3.Connection) -> None:
        # Re-validate the EXACT session this request carries, INSIDE the
        # IMMEDIATE write transaction, before any other check. BEGIN
        # IMMEDIATE serializes this removal against the logout /
        # logout-others / password-change transactions (all writers): once
        # this check reads the session as live and the transaction goes on
        # to remove the member, no revocation can commit in between; and if
        # a revocation committed first — or the expiry instant arrived
        # (expires_at <= now) while the request was waiting — the removal
        # fails closed with 401. Another still-valid session of the same
        # account cannot rescue this one: authorization is keyed to this
        # token hash alone. Conversely, revoking only the account's OTHER
        # sessions leaves this one live and the removal proceeds.
        #
        # This runs ahead of the membership check (403), the target lookup
        # (404) and the last-admin invariant (409), so an invalid session is
        # always answered 401 first; and it runs before anything is written,
        # so a 401 here deletes nothing, revokes no invite, invalidates no
        # delegation and stores no idempotency record — on first attempts
        # and on replays of a stored success alike (``_run_idempotent``
        # calls ``check_perm`` on every path, before any replay is
        # returned).
        ts = now_ts()
        sess = c.execute(
            "SELECT revoked_at, expires_at FROM sessions WHERE token_hash = ?",
            (hash_token(request_token),),
        ).fetchone()
        if sess is None or sess["revoked_at"] is not None or sess["expires_at"] <= ts:
            raise unauthorized("invalid or expired session")
        require_membership(c, user, org_id, admin=True)

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
        check_perm=_check_perm,
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

# Version 1 cursors predate batch filtering and carry no "batch" field; they
# remain valid for unfiltered scans only. Version 2 embeds the filter (the
# exact batch_id, or null for an unfiltered scan) so follow-up requests need
# only carry the cursor.
_CURSOR_VERSION = 2
_CURSOR_VERSION_LEGACY = 1


def _encode_scan_cursor(
    org_id: int, end_id: int, position: int, batch_id: Optional[str]
) -> str:
    """Opaque continuation token for an audit scan.

    The cursor only carries a read position: the organization, the scan's
    fixed upper id bound (the snapshot end), the id of the last entry already
    returned and the batch filter in effect. It is HMAC-signed with the
    server key, so clients can neither read nor alter it, and deterministic,
    so re-issuing a cursor for an unchanged position yields the identical
    string. It never substitutes for authentication — every batch re-checks
    the caller's current admin membership.
    """
    payload = json.dumps(
        {"v": _CURSOR_VERSION, "org": org_id, "end": end_id,
         "pos": position, "batch": batch_id},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sign_text(payload)


def _decode_scan_cursor(cursor: str, org_id: int) -> tuple[int, int, Optional[str]]:
    """Validate a cursor's shape for THIS organization.

    Returns ``(end_id, position, batch_id)`` where ``batch_id`` is the filter
    the scan was started with (``None`` for an unfiltered scan). Anything
    unrecognized, tampered with, or minted for another organization raises
    422 invalid_cursor and reveals no audit content. Whether the request is
    ALSO allowed to present its own ``batch_id`` beside the cursor is decided
    by the caller: it must exactly equal the embedded one, and an omitted
    parameter simply adopts it. Legacy (pre-upgrade) cursors embed ``None``,
    so they continue only unfiltered scans.
    """
    try:
        payload = json.loads(verify_signed_text(cursor))
        version = payload["v"]
        end_id = payload["end"]
        position = payload["pos"]
        if not isinstance(version, int) or isinstance(version, bool):
            raise ValueError
        if version == _CURSOR_VERSION_LEGACY:
            cursor_batch: Optional[str] = None
        elif version == _CURSOR_VERSION:
            cursor_batch = payload["batch"]
            if cursor_batch is not None and not isinstance(cursor_batch, str):
                raise ValueError
        else:
            raise ValueError
        if (
            payload["org"] != org_id
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
    return end_id, position, cursor_batch


@app.get("/orgs/{org_id}/audit/scan")
def scan_audit(
    org_id: int,
    cursor: Optional[str] = Query(default=None),
    batch_id: Optional[str] = Query(default=None, min_length=1, max_length=128),
    page_size: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    """Snapshot-consistent cursor scan of the organization's audit trail.

    The first request (no ``cursor``) fixes the range as every entry of this
    organization committed at that instant: audit ids are monotonic, so the
    range is exactly ``id <= end_id`` and entries written later — even with
    an identical timestamp — can never join it. Passing ``batch_id`` narrows
    the range to this organization's rows whose batch marker matches it
    byte-for-byte (no trimming or case folding); no match — including a marker
    that only exists in another organization — yields an empty result rather
    than any hint about other organizations. Follow-up requests pass the
    returned ``next_cursor`` (the filter rides inside it, so ``batch_id`` is
    neither needed nor allowed to change) and read strictly after the previous
    batch's last id, so every in-range entry appears exactly once regardless
    of how ``page_size`` changes between batches. The cursor is stateless:
    repeating a request with the same cursor returns the same batch and does
    not consume progress. Authorization is re-checked on every batch against
    the caller's CURRENT membership.
    """
    # Every batch — cursor continuations included — is freshly authorized
    # against the caller's current membership. A cursor never stands in for
    # authorization: a member demoted or disabled mid-scan is refused on the
    # next batch with the uniform 403.
    require_membership(conn, user, org_id, admin=True)
    if cursor is None:
        # Fix the snapshot range [.., end_id] for THIS organization (and, when
        # given, this batch) only; rows committed by other orgs interleave in
        # id space but are filtered out without affecting order/completeness.
        if batch_id is None:
            snap = conn.execute(
                "SELECT MAX(id) AS end_id, COUNT(*) AS n FROM audit_logs WHERE org_id = ?",
                (org_id,),
            ).fetchone()
        else:
            # Bound the range at the filtered set's own last id. This keeps
            # the (position > end_id) cursor invariant meaningful and changes
            # nothing about visibility: later rows of the SAME batch cannot
            # exist (its rows commit in one transaction), and later batches
            # never carry this marker.
            snap = conn.execute(
                "SELECT MAX(id) AS end_id, COUNT(*) AS n FROM audit_logs"
                " WHERE org_id = ? AND batch_id = ?",
                (org_id, batch_id),
            ).fetchone()
        end_id = snap["end_id"] or 0
        total = snap["n"]
        position = 0
    else:
        # Raises 422 invalid_cursor on malformed/tampered/foreign cursors.
        # Happens AFTER the membership check, so a cursor never bypasses it.
        end_id, position, cursor_batch = _decode_scan_cursor(cursor, org_id)
        # Follow-up requests normally omit batch_id and simply inherit the
        # filter frozen into the cursor. Explicitly presenting one is allowed
        # only when it reproduces the FIRST request's filter byte-for-byte;
        # switching batches, adding a filter to an unfiltered scan or dropping
        # the filter from a filtered one (covered by the embedded value below)
        # are all invalid_cursor.
        if batch_id is not None and batch_id != cursor_batch:
            raise ApiError(422, "invalid_cursor", "cursor is invalid")
        batch_id = cursor_batch
        # Audit rows are never updated or deleted, so the in-range total is
        # identical for every batch of the scan.
        if batch_id is None:
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ? AND id <= ?",
                (org_id, end_id),
            ).fetchone()["n"]
        else:
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM audit_logs"
                " WHERE org_id = ? AND batch_id = ? AND id <= ?",
                (org_id, batch_id, end_id),
            ).fetchone()["n"]
    # Fetch one extra row to learn whether a further batch exists; this ends
    # the scan with next_cursor = null exactly when the final batch is full.
    if batch_id is None:
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
    else:
        # Exact-match, case/space-sensitive parameter comparison; the org
        # predicate guarantees another organization's batch can never appear.
        rows = conn.execute(
            """
            SELECT a.*, u.username AS actor_username
            FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
            WHERE a.org_id = ? AND a.batch_id = ? AND a.id > ? AND a.id <= ?
            ORDER BY a.id ASC
            LIMIT ?
            """,
            (org_id, batch_id, position, end_id, page_size + 1),
        ).fetchall()
    has_more = len(rows) > page_size
    items = [_audit_item(r) for r in rows[:page_size]]
    next_cursor = (
        _encode_scan_cursor(org_id, end_id, items[-1]["id"], batch_id)
        if has_more
        else None
    )
    return {"items": items, "total": total, "next_cursor": next_cursor}
