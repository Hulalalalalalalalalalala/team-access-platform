"""Session validity at EXECUTION TIME for POST /orgs/{org_id}/invites.

Regression: the ``current_user`` dependency only proves the carried session
was live when the request arrived. The issue may then wait behind SQLite's
single write lock, and while it waits the session can be logged out, revoked
by "logout other sessions" or a password change, or simply reach its expiry
instant. Issuing an invite — and returning a previously stored successful
result via Idempotency-Key — must instead be authorized by the session state
at the moment it actually runs. The re-check therefore happens INSIDE the
IMMEDIATE write transaction, before the membership/delegation checks, the
idempotency lookup and every write.

Determinism: the test process takes the write lock with ``BEGIN IMMEDIATE``
and only then starts the issue request. The server endpoint cannot enter its
own write transaction (it queues behind the lock with busy_timeout), so
whatever the test commits before releasing the lock is guaranteed visible to
the in-transaction session re-check — no thread scheduling or sleep-based
race. Same harness as test_org_session.py / test_invite_session.py.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

import httpx

from app.idempotency import scope_invite_create
from app.security import hash_password
from tests.conftest import Api


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _writer(db_path: Path) -> sqlite3.Connection:
    # isolation_level=None -> explicit autocommit; we drive BEGIN/COMMIT
    # ourselves exactly like the application does.
    conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _reader(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _make_org(api: Api):
    """Admin + org + a registered (not-yet-invited) invitee.

    Returns ``(admin_name, admin_token, org, invitee)``.
    """
    admin_name, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"iv-{api.unique()}"}).json()
    invitee, _ = api.new_user()
    return admin_name, admin_token, org, invitee


def _make_delegate(api: Api, admin: str, org_id: int):
    """An active member holding a fresh delegation.

    The join invite issued by the admin counts as one org invite/audit row.
    Returns ``(delegate_name, token, user_id, delegation_id)``.
    """
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin,
                      json={"username": name, "role": "member"}).json()
    r = api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    member_id = r.json()["membership"]["user_id"]
    d = api.request("POST", f"/orgs/{org_id}/delegations", token=admin,
                    json={"user_id": member_id, "duration_seconds": 3600})
    assert d.status_code == 201, d.text
    return name, token, member_id, d.json()["id"]


def _issue(api: Api, token: str, org_id: int, username: str, *, role: str = "member",
           key: str | None = None, header: str = "bearer"):
    headers = (
        {"Authorization": f"Bearer {token}"}
        if header == "bearer"
        else {"X-Session-Token": token}
    )
    if key is not None:
        headers["Idempotency-Key"] = key
    return api.request("POST", f"/orgs/{org_id}/invites", headers=headers,
                       json={"username": username, "role": role})


def _blocked_issue(
    api: Api,
    token: str,
    org_id: int,
    body: dict,
    *,
    key: str | None = None,
    header: str = "bearer",
):
    """Start an invite request in a thread while the caller holds the lock."""
    headers = (
        {"Authorization": f"Bearer {token}"}
        if header == "bearer"
        else {"X-Session-Token": token}
    )
    if key is not None:
        headers["Idempotency-Key"] = key
    outcome: dict[str, object] = {}

    def _run() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            outcome["response"] = c.post(
                f"/orgs/{org_id}/invites", headers=headers, json=body
            )

    t = threading.Thread(target=_run)
    t.start()
    # Pass the dependency (a WAL read that does not block), then queue on
    # BEGIN IMMEDIATE behind OUR lock. Correctness does not rely on the sleep:
    # the endpoint cannot issue anything until we COMMIT.
    time.sleep(0.3)
    return t, outcome


def _join(t: threading.Thread, outcome: dict[str, object]) -> httpx.Response:
    t.join(timeout=30)
    assert not t.is_alive(), "invite request hung"
    return outcome["response"]  # type: ignore[return-value]


def _user_id(ro: sqlite3.Connection, username: str) -> int:
    return ro.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def _counts(ro: sqlite3.Connection, org_id: int) -> tuple[int, int]:
    n_inv = ro.execute(
        "SELECT COUNT(*) AS n FROM invites WHERE org_id = ?", (org_id,)
    ).fetchone()["n"]
    n_audit = ro.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'invite.created'",
        (org_id,),
    ).fetchone()["n"]
    return n_inv, n_audit


def _revoke_session(lock: sqlite3.Connection, token: str) -> None:
    lock.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
        (int(time.time()), _hash(token)),
    )


# ------------------------------------------------------------ admin: timing

def test_session_logged_out_while_waiting_is_401_and_issues_nothing(api: Api, server):
    _, admin, org, invitee = _make_org(api)

    ro = _reader(server.db_path)
    before = _counts(ro, org["id"])
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, admin, org["id"],
                                    {"username": invitee, "role": "member"})
        # Same effect as POST /auth/logout for this session.
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}
    assert "token" not in r.json()

    ro = _reader(server.db_path)
    try:
        assert _counts(ro, org["id"]) == before  # no invite, no invite.created
    finally:
        ro.close()

    # A dead session stays dead on a direct retry.
    assert _issue(api, admin, org["id"], invitee).status_code == 401


def test_session_revoked_by_logout_others_while_waiting_is_401(api: Api, server):
    """Committed logout-others state: the waiting session dies, another lives."""
    admin_name, admin, org, invitee = _make_org(api)
    survivor = api.token_for(admin_name)  # a second session that stays live

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, admin, org["id"],
                                    {"username": invitee, "role": "admin"})
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    ro = _reader(server.db_path)
    try:
        # No invite was issued by the dead session...
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM invites WHERE org_id = ?", (org["id"],)
        ).fetchone()["n"] == 0
        # ...and retrying that dead token is still 401 even though another
        # session of the same account is live.
        assert _issue(api, admin, org["id"], invitee, role="admin").status_code == 401
    finally:
        ro.close()

    # The other, still-valid session issues its OWN invite exactly.
    r = _issue(api, survivor, org["id"], invitee, role="admin")
    assert r.status_code == 201, r.text
    ro = _reader(server.db_path)
    try:
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM invites WHERE org_id = ?", (org["id"],)
        ).fetchone()["n"] == 1
    finally:
        ro.close()


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, server):
    admin_name, admin, org, invitee = _make_org(api)

    ro = _reader(server.db_path)
    uid = _user_id(ro, admin_name)
    before = _counts(ro, org["id"])
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, admin, org["id"],
                                    {"username": invitee, "role": "member"})
        # Exact committed end state of POST /auth/password: new hash plus
        # revoked_at on every live session of the account, together.
        ts = int(time.time())
        lock.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (hash_password("N3wPass!"), uid))
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        assert _counts(ro, org["id"]) == before
    finally:
        ro.close()

    # Old password is dead; after a fresh login the same request goes through.
    assert api.login(admin_name, "Passw0rd!").status_code == 401
    new_token = api.token_for(admin_name, "N3wPass!")
    r = _issue(api, new_token, org["id"], invitee)
    assert r.status_code == 201, r.text


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, server):
    _, admin, org, invitee = _make_org(api)
    ro = _reader(server.db_path)
    before = _counts(ro, org["id"])
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, admin, org["id"],
                                    {"username": invitee, "role": "member"})
        # The expiry instant ITSELF is invalid (expires_at <= now).
        lock.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(admin)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        assert _counts(ro, org["id"]) == before
    finally:
        ro.close()


def test_revoking_an_unrelated_session_while_waiting_keeps_success(api: Api, server):
    admin_name, admin, org, invitee = _make_org(api)
    other = api.token_for(admin_name)

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, admin, org["id"],
                                    {"username": invitee, "role": "member"})
        # Only the OTHER session is revoked; the carried one is untouched.
        _revoke_session(lock, other)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "available" and r.json()["role"] == "member"


def test_issue_committed_first_then_session_invalidated_keeps_invite(api: Api):
    _, admin, org, invitee = _make_org(api)
    r = _issue(api, admin, org["id"], invitee)
    assert r.status_code == 201, r.text
    invite = r.json()
    # Session dies only AFTER the issue committed: the result must stand.
    assert api.request("POST", "/auth/logout", token=admin).status_code == 200
    assert _issue(api, admin, org["id"], invitee).status_code == 401

    # The invitee can still accept exactly as before.
    itok = api.token_for(invitee)
    r = api.request("POST", "/invites/accept", token=itok, json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["org_id"] == org["id"]


# ------------------------------------------------------------ header parity

def test_x_session_token_issues_invite(api: Api):
    _, admin, org, invitee = _make_org(api)
    r = _issue(api, admin, org["id"], invitee, role="admin", header="x")
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "admin"


def test_401_via_x_session_token_header_uses_error_envelope(api: Api, server):
    _, admin, org, invitee = _make_org(api)
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, admin, org["id"], {"username": invitee, "role": "member"}, header="x"
        )
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}


# ------------------------------------------------- 401 precedence (admin path)

def test_unauthorized_takes_precedence_over_org_permission(api: Api, server):
    # An outsider (no membership): live -> 403, dead while waiting -> 401.
    _, admin, org, invitee = _make_org(api)
    outsider_name, outsider = api.new_user()

    # With a live session the membership check answers 403 as always.
    assert _issue(api, outsider, org["id"], invitee).status_code == 403

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(api, outsider, org["id"],
                                    {"username": invitee, "role": "member"})
        _revoke_session(lock, outsider)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # After re-login the ordinary 403 is back.
    assert _issue(api, api.token_for(outsider_name), org["id"], invitee).status_code == 403


def test_unauthorized_takes_precedence_over_idempotency_conflict(api: Api, server):
    admin_name, admin, org, invitee = _make_org(api)
    key = f"k-{api.unique()}"
    first = _issue(api, admin, org["id"], invitee, role="member", key=key)
    assert first.status_code == 201, first.text

    # Same key, DIFFERENT body, session dies while waiting: 401 wins over 409.
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, admin, org["id"], {"username": invitee, "role": "admin"}, key=key
        )
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"

    new_token = api.token_for(admin_name)
    # Live session: the different body is now the ordinary conflict...
    r = _issue(api, new_token, org["id"], invitee, role="admin", key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    # ...and the original key+body still replays the ORIGINAL result.
    r = _issue(api, new_token, org["id"], invitee, role="member", key=key)
    assert r.status_code == 201 and r.json()["token"] == first.json()["token"]


# ------------------------------------------------------------- idempotency

def test_replay_of_stored_success_requires_a_live_session(api: Api, server):
    admin_name, admin, org, invitee = _make_org(api)
    key = f"k-{api.unique()}"
    first = _issue(api, admin, org["id"], invitee, role="member", key=key)
    assert first.status_code == 201, first.text
    token1 = first.json()["token"]

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, admin, org["id"], {"username": invitee, "role": "member"}, key=key
        )
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    # Even though the key holds a success, a dead session gets 401 and the
    # cached invite token is never returned.
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert token1 not in r.text

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, admin_name)
        # Stored success is intact: still exactly one row.
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM idempotency_keys"
            " WHERE operator_id = ? AND scope = ? AND idempotency_key = ?",
            (uid, scope_invite_create(org["id"]), key),
        ).fetchone()["n"] == 1
        # No second invite / audit.
        assert _counts(ro, org["id"]) == (1, 1)
    finally:
        ro.close()

    # After a fresh login the same key+body returns the ORIGINAL invite token.
    new_token = api.token_for(admin_name)
    r = _issue(api, new_token, org["id"], invitee, role="member", key=key)
    assert r.status_code == 201, r.text
    assert r.json()["token"] == token1
    ro = _reader(server.db_path)
    try:
        assert _counts(ro, org["id"]) == (1, 1)
    finally:
        ro.close()


def test_unused_key_is_not_consumed_by_401_and_reusable_after_relogin(api: Api, server):
    admin_name, admin, org, invitee = _make_org(api)
    key = f"k-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, admin, org["id"], {"username": invitee, "role": "member"}, key=key
        )
        _revoke_session(lock, admin)
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, admin_name)
        assert _counts(ro, org["id"]) == (0, 0)
        # The rejected attempt did not occupy the unused key.
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM idempotency_keys"
            " WHERE operator_id = ? AND scope = ? AND idempotency_key = ?",
            (uid, scope_invite_create(org["id"]), key),
        ).fetchone()["n"] == 0
    finally:
        ro.close()

    new_token = api.token_for(admin_name)
    r = _issue(api, new_token, org["id"], invitee, role="member", key=key)
    assert r.status_code == 201, r.text
    assert r.json()["username"] == invitee


# -------------------------------------------------------------- delegate path

def test_delegate_session_revoked_while_waiting_is_401_and_changes_nothing(
    api: Api, server
):
    _, admin, org, _ = _make_org(api)
    _, delegate, _, delegation_id = _make_delegate(api, admin, org["id"])
    invitee, _ = api.new_user()

    ro = _reader(server.db_path)
    before = _counts(ro, org["id"])
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, delegate, org["id"], {"username": invitee, "role": "member"}
        )
        _revoke_session(lock, delegate)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        assert _counts(ro, org["id"]) == before
        # The delegation that was backing the attempt is untouched.
        d = ro.execute("SELECT status FROM delegations WHERE id = ?",
                       (delegation_id,)).fetchone()
        assert d["status"] == "active"
    finally:
        ro.close()


def test_unauthorized_beats_delegation_unavailable_for_delegate(api: Api, server):
    _, admin, org, _ = _make_org(api)
    delegate_name, delegate, _, delegation_id = _make_delegate(api, admin, org["id"])
    invitee, _ = api.new_user()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, delegate, org["id"], {"username": invitee, "role": "member"}
        )
        ts = int(time.time())
        # Session AND backing delegation both become unusable while waiting:
        # the session rule (401) must win over delegation availability (403).
        _revoke_session(lock, delegate)
        lock.execute(
            "UPDATE delegations SET status = 'revoked', revoked_at = ? WHERE id = ?",
            (ts, delegation_id),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # A LIVE session with a dead delegation is the ordinary 403.
    assert _issue(api, api.token_for(delegate_name), org["id"], invitee).status_code == 403


def test_delegate_replay_of_stored_success_requires_live_session(api: Api, server):
    _, admin, org, _ = _make_org(api)
    delegate_name, delegate, _, delegation_id = _make_delegate(api, admin, org["id"])
    invitee, _ = api.new_user()
    key = f"k-{api.unique()}"
    first = _issue(api, delegate, org["id"], invitee, role="member", key=key)
    assert first.status_code == 201, first.text
    token1 = first.json()["token"]

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_issue(
            api, delegate, org["id"], {"username": invitee, "role": "member"}, key=key
        )
        # Revoke ONLY this session; the original delegation stays active, so
        # the rejection is purely the session rule.
        _revoke_session(lock, delegate)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and token1 not in r.text

    ro = _reader(server.db_path)
    try:
        assert ro.execute("SELECT status FROM delegations WHERE id = ?",
                          (delegation_id,)).fetchone()["status"] == "active"
        # The join invite (admin) plus the delegate's one invite, nothing more.
        assert _counts(ro, org["id"]) == (2, 2)
    finally:
        ro.close()

    # Re-login: the ORIGINAL delegation still authorizes the stored replay.
    new_token = api.token_for(delegate_name)
    r = _issue(api, new_token, org["id"], invitee, role="member", key=key)
    assert r.status_code == 201 and r.json()["token"] == token1


# ------------------------------------------------------- body validation 422

def test_invalid_body_is_still_422(api: Api):
    _, admin, org, _ = _make_org(api)
    # role outside the enum is rejected at validation time, before sessions.
    r = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                    json={"username": "abc", "role": "owner"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"
