"""Session validity at JOIN TIME for POST /invites/accept.

Regression: a session that is valid when the request arrives may be revoked
(logout / logout-others / password change) or may reach its expiry instant
while the request is waiting to perform the join. The acceptance must be
authorized by the session state at the moment the membership actually takes
effect, re-checked inside the serialized write transaction — not by the
earlier dependency check.

Determinism: the test process opens its own connection, takes SQLite's single
write lock with ``BEGIN IMMEDIATE`` and only then starts the accept request.
The server endpoint cannot enter its write transaction (it queues behind the
lock with busy_timeout), so whatever the test commits before releasing the
lock is guaranteed to be visible to the in-transaction session re-check:
no thread scheduling or sleep-based race.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

import httpx

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


def _setup(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"sx-{api.unique()}"}).json()
    name, member_token = api.new_user()
    invite = api.request(
        "POST", f"/orgs/{org['id']}/invites", token=admin_token,
        json={"username": name, "role": "member"},
    ).json()
    return org, name, member_token, invite


def _blocked_accept(api: Api, token: str, invite_token: str, *, header: str = "bearer"):
    """Start an accept request in a thread while the caller holds the lock."""
    if header == "bearer":
        headers = {"Authorization": f"Bearer {token}"}
    else:
        headers = {"X-Session-Token": token}
    outcome: dict[str, object] = {}

    def _run() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            outcome["response"] = c.post(
                "/invites/accept", headers=headers, json={"token": invite_token}
            )

    t = threading.Thread(target=_run)
    t.start()
    # The server must first pass the dependency (a WAL read that does not
    # block) and then queue on BEGIN IMMEDIATE behind OUR lock. A short settle
    # is enough; correctness does not rely on it — the endpoint cannot perform
    # the join until we COMMIT, at which point it reads the rows we wrote.
    time.sleep(0.3)
    return t, outcome


def _join(t: threading.Thread, outcome: dict[str, object]) -> httpx.Response:
    t.join(timeout=30)
    assert not t.is_alive(), "accept request hung"
    return outcome["response"]  # type: ignore[return-value]


def _assert_invite_untouched(ro: sqlite3.Connection, org_id: int, invite_id: int) -> None:
    inv = ro.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
    assert inv["status"] == "available"
    assert inv["used_at"] is None and inv["used_by"] is None
    n_members = ro.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ?", (org_id,)
    ).fetchone()["n"]
    assert n_members == 1  # creator only
    n_audit = ro.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'invite.accepted'",
        (org_id,),
    ).fetchone()["n"]
    assert n_audit == 0


def test_session_revoked_while_waiting_is_401_and_invite_stays_usable(api: Api, server):
    org, name, token, invite = _setup(api)
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token, invite["token"])
        # Same effect as POST /auth/logout for this session.
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    err = r.json()["error"]
    assert err["code"] == "unauthorized"
    assert "membership" not in r.json()

    ro = _reader(server.db_path)
    try:
        _assert_invite_untouched(ro, org["id"], invite["id"])
        # A second rejected attempt changes nothing either.
        r2 = api.request("POST", "/invites/accept", token=token,
                         json={"token": invite["token"]})
        assert r2.status_code == 401
        _assert_invite_untouched(ro, org["id"], invite["id"])
    finally:
        ro.close()

    # After a fresh login the SAME invite still joins the org.
    new_token = api.token_for(name)
    r = api.request("POST", "/invites/accept", token=new_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    m = r.json()["membership"]
    assert m["org_id"] == org["id"] and m["username"] == name


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, server):
    """Models the committed end state of POST /auth/password for the account.

    The password endpoint commits a new hash AND revoked_at on every session
    of the account in one transaction; reproduce that exact committed state
    while the accept is queued, then log in with the new password and reuse
    the invite.
    """
    org, name, token, invite = _setup(api)
    ro = _reader(server.db_path)
    user_id = ro.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()["id"]
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token, invite["token"])
        ts = int(time.time())
        lock.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (hash_password("N3wPass!"), user_id))
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, user_id),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        _assert_invite_untouched(ro, org["id"], invite["id"])
    finally:
        ro.close()

    # Old password no longer works; new password logs in and the invite joins.
    assert api.login(name, "Passw0rd!").status_code == 401
    new_token = api.token_for(name, "N3wPass!")
    r = api.request("POST", "/invites/accept", token=new_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, server):
    org, name, token, invite = _setup(api)
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token, invite["token"])
        # The expiry instant ITSELF is invalid (expires_at <= now).
        lock.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        _assert_invite_untouched(ro, org["id"], invite["id"])
    finally:
        ro.close()

    # A new session (the invite's own 24h expiry is untouched) can still use it.
    new_token = api.token_for(name)
    r = api.request("POST", "/invites/accept", token=new_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text


def test_another_live_session_cannot_authorize_a_revoked_one(api: Api, server):
    org, name, token1, invite = _setup(api)
    token2 = api.token_for(name)  # second live session of the same account

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token1, invite["token"])
        # Only session 1 is revoked (e.g. logout on that device); session 2
        # stays live and must not retroactively authorize session 1.
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token1)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    # Retrying the dead session is still 401 even though session 2 is valid.
    assert api.request("POST", "/invites/accept", token=token1,
                       json={"token": invite["token"]}).status_code == 401
    # The other, still-valid session accepts the same invite exactly once.
    r = api.request("POST", "/invites/accept", token=token2,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    ro = _reader(server.db_path)
    try:
        n_members = ro.execute(
            "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND user_id = ?",
            (org["id"], ro.execute("SELECT id FROM users WHERE username = ?", (name,))
             .fetchone()["id"]),
        ).fetchone()["n"]
        assert n_members == 1
        n_audit = ro.execute(
            "SELECT COUNT(*) AS n FROM audit_logs"
            " WHERE org_id = ? AND action = 'invite.accepted'", (org["id"],)
        ).fetchone()["n"]
        assert n_audit == 1
    finally:
        ro.close()


def test_revoking_an_unrelated_session_while_waiting_keeps_success(api: Api, server):
    org, name, token1, invite = _setup(api)
    token2 = api.token_for(name)

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token1, invite["token"])
        # Session 2 is revoked while session 1's accept is waiting; session 1
        # is untouched, so the join succeeds.
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token2)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["username"] == name

    # The single-use invite is consumed; the revoked other session can never
    # get a second join (it fails on session validity first, and the invite
    # is used anyway).
    assert api.request("POST", "/invites/accept", token=token2,
                       json={"token": invite["token"]}).status_code == 401
    fresh = api.token_for(name)
    r = api.request("POST", "/invites/accept", token=fresh,
                    json={"token": invite["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


def test_401_via_x_session_token_header_uses_error_envelope(api: Api, server):
    org, name, token, invite = _setup(api)
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_accept(api, token, invite["token"], header="x")
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}


def test_join_committed_first_then_logout_keeps_membership(api: Api):
    # Join wins the transaction ordering; a later revocation only ends the
    # session and never removes the membership already established.
    org, name, token, invite = _setup(api)
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": invite["token"]})
    assert r.status_code == 200
    assert api.request("POST", "/auth/logout", token=token).status_code == 200

    # Membership survives; a fresh session sees it.
    new_token = api.token_for(name)
    r = api.request("GET", f"/orgs/{org['id']}/members/me", token=new_token)
    assert r.status_code == 200
    assert r.json()["membership"]["status"] == "active"
    assert api.request("POST", "/invites/accept", token=token,
                       json={"token": invite["token"]}).status_code == 401
