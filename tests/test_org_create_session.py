"""Session validity at CREATION TIME for POST /orgs.

Regression: a session that is valid when the request arrives may be revoked
(logout / logout-others / password change) or may reach its expiry instant
while the request is waiting to enter its write transaction. Organization
creation must be authorized by the session state at the moment the org is
actually inserted, re-checked inside the serialized write transaction — not
by the arrival-time dependency check — on both first creation and
Idempotency-Key replays.

Determinism: the test process opens its own connection, takes SQLite's single
write lock with ``BEGIN IMMEDIATE`` and only then starts the create request.
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
import uuid
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


def _user_id(ro: sqlite3.Connection, username: str) -> int:
    return ro.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def _blocked_create(
    api: Api, token: str, name: str, *, key: str | None = None, header: str = "bearer"
):
    """Start an org-create request in a thread while the caller holds the lock."""
    if header == "bearer":
        headers = {"Authorization": f"Bearer {token}"}
    else:
        headers = {"X-Session-Token": token}
    if key is not None:
        headers["Idempotency-Key"] = key
    outcome: dict[str, object] = {}

    def _run() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            outcome["response"] = c.post("/orgs", headers=headers, json={"name": name})

    t = threading.Thread(target=_run)
    t.start()
    # The server must first pass the dependency (a WAL read that does not
    # block) and then queue on BEGIN IMMEDIATE behind OUR lock. A short settle
    # is enough; correctness does not rely on it — the endpoint cannot create
    # the org until we COMMIT, at which point it reads the rows we wrote.
    time.sleep(0.3)
    return t, outcome


def _join(t: threading.Thread, outcome: dict[str, object]) -> httpx.Response:
    t.join(timeout=30)
    assert not t.is_alive(), "create request hung"
    return outcome["response"]  # type: ignore[return-value]


def _assert_nothing_created(ro: sqlite3.Connection, username: str, name: str) -> None:
    uid = _user_id(ro, username)
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM organizations WHERE name = ?", (name,)
    ).fetchone()["n"] == 0
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE user_id = ?", (uid,)
    ).fetchone()["n"] == 0
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'org.created'"
        " AND actor_id = ?",
        (uid,),
    ).fetchone()["n"] == 0


def _revoke(lock: sqlite3.Connection, token: str) -> None:
    # Same committed effect as POST /auth/logout for this session.
    lock.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
        (int(time.time()), _hash(token)),
    )


def test_session_revoked_while_waiting_is_401_and_creates_nothing(api: Api, server):
    name_prefix = f"sx-{api.unique()}"
    username, token = api.new_user()
    name = f"{name_prefix}-org"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name)
        _revoke(lock, token)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    err = r.json()["error"]
    assert err["code"] == "unauthorized"
    assert "id" not in r.json()

    ro = _reader(server.db_path)
    try:
        _assert_nothing_created(ro, username, name)
        # A second rejected attempt changes nothing either.
        r2 = api.request("POST", "/orgs", token=token, json={"name": name})
        assert r2.status_code == 401
        _assert_nothing_created(ro, username, name)
    finally:
        ro.close()

    # After a fresh login the same org name can still be created.
    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json={"name": name})
    assert r.status_code == 201, r.text
    assert r.json()["name"] == name and r.json()["role"] == "admin"


def test_logout_others_revoking_this_session_while_waiting_is_401(api: Api, server):
    """Models the committed end state of POST /auth/logout-others.

    The request carries session 1; a logout-others performed on session 2
    keeps session 2 and revokes session 1. The queued create must fail.
    """
    username, token1 = api.new_user()
    token2 = api.token_for(username)
    ro = _reader(server.db_path)
    s1 = ro.execute("SELECT id FROM sessions WHERE token_hash = ?", (_hash(token1),)).fetchone()["id"]
    ro.close()
    name = f"lo-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, name)
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ?",
            (int(time.time()), s1),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401
    ro = _reader(server.db_path)
    try:
        _assert_nothing_created(ro, username, name)
    finally:
        ro.close()
    # The session that performed logout-others is untouched and can create.
    r = api.request("POST", "/orgs", token=token2, json={"name": name})
    assert r.status_code == 201, r.text


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, server):
    """Models the committed end state of POST /auth/password for the account."""
    username, token = api.new_user()
    ro = _reader(server.db_path)
    user_id = _user_id(ro, username)
    ro.close()
    name = f"pw-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name)
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
        _assert_nothing_created(ro, username, name)
    finally:
        ro.close()

    # Old password no longer works; the new password logs in and creates it.
    assert api.login(username, "Passw0rd!").status_code == 401
    new_token = api.token_for(username, "N3wPass!")
    r = api.request("POST", "/orgs", token=new_token, json={"name": name})
    assert r.status_code == 201, r.text


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, server):
    username, token = api.new_user()
    name = f"ex-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name)
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
        _assert_nothing_created(ro, username, name)
    finally:
        ro.close()

    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json={"name": name})
    assert r.status_code == 201, r.text


def test_another_live_session_cannot_authorize_a_revoked_one(api: Api, server):
    username, token1 = api.new_user()
    token2 = api.token_for(username)  # second live session of the same account
    name = f"as-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, name)
        _revoke(lock, token1)
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    # Retrying the dead session is still 401 even though session 2 is valid.
    assert api.request("POST", "/orgs", token=token1, json={"name": name}).status_code == 401
    ro = _reader(server.db_path)
    try:
        _assert_nothing_created(ro, username, name)
    finally:
        ro.close()

    # The other, still-valid session creates the org normally.
    r = api.request("POST", "/orgs", token=token2, json={"name": name})
    assert r.status_code == 201, r.text


def test_revoking_an_unrelated_session_while_waiting_keeps_success(api: Api, server):
    username, token1 = api.new_user()
    token2 = api.token_for(username)
    name = f"us-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, name)
        # Session 2 is revoked while session 1's create is waiting; session 1
        # is untouched, so the creation succeeds.
        _revoke(lock, token2)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 201, r.text
    assert r.json()["name"] == name and r.json()["role"] == "admin"


def test_401_via_x_session_token_header_uses_error_envelope(api: Api, server):
    _, token = api.new_user()
    name = f"xh-{api.unique()}"

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name, header="x")
        _revoke(lock, token)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}


# ------------------------------------------------------------- idempotency

def test_rejected_create_with_unused_key_does_not_consume_key(api: Api, server):
    username, token = api.new_user()
    name = f"ku-{api.unique()}"
    key = uuid.uuid4().hex
    ro = _reader(server.db_path)
    uid = _user_id(ro, username)
    ro.close()

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name, key=key)
        _revoke(lock, token)
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    ro = _reader(server.db_path)
    try:
        # The rejected attempt neither created anything nor stored a record.
        _assert_nothing_created(ro, username, name)
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM idempotency_keys WHERE operator_id = ?", (uid,)
        ).fetchone()["n"] == 0
    finally:
        ro.close()

    # After a fresh login the SAME key with the SAME request still creates.
    new_token = api.token_for(username)
    r1 = api.request("POST", "/orgs", token=new_token, json={"name": name},
                     headers={"Idempotency-Key": key})
    assert r1.status_code == 201, r1.text
    org_id = r1.json()["id"]
    # And the key now replays the first success instead of creating again.
    r2 = api.request("POST", "/orgs", token=new_token, json={"name": name},
                     headers={"Idempotency-Key": key})
    assert r2.status_code == 201, r2.text
    assert r2.json()["id"] == org_id
    ro = _reader(server.db_path)
    try:
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM organizations WHERE name = ?", (name,)
        ).fetchone()["n"] == 1
    finally:
        ro.close()


def test_replay_of_stored_success_with_dead_session_is_401_and_record_kept(api: Api):
    username, token = api.new_user()
    name = f"rp-{api.unique()}"
    key = uuid.uuid4().hex
    headers = {"Idempotency-Key": key}

    r1 = api.request("POST", "/orgs", token=token, json={"name": name}, headers=headers)
    assert r1.status_code == 201, r1.text
    org_id = r1.json()["id"]

    # The session dies AFTER the creation committed; the result stands.
    assert api.request("POST", "/auth/logout", token=token).status_code == 200

    # A replay carrying the dead session gets 401 — not the stored org — and
    # the stored success record is neither returned nor overwritten.
    r2 = api.request("POST", "/orgs", token=token, json={"name": name}, headers=headers)
    assert r2.status_code == 401, r2.text
    assert r2.json()["error"]["code"] == "unauthorized"
    assert "id" not in r2.json()

    # Fresh login: the same key + same request still replays the first result.
    new_token = api.token_for(username)
    r3 = api.request("POST", "/orgs", token=new_token, json={"name": name},
                     headers={"Idempotency-Key": key})
    assert r3.status_code == 201, r3.text
    assert r3.json()["id"] == org_id


def test_401_takes_precedence_over_name_conflict(api: Api, server):
    _, other_token = api.new_user()
    name = f"nc-{api.unique()}"
    assert api.request("POST", "/orgs", token=other_token,
                       json={"name": name}).status_code == 201

    username, token = api.new_user()
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, name)
        _revoke(lock, token)
        lock.execute("COMMIT")
    finally:
        lock.close()

    # Invalid session wins over the taken name: 401, not 409.
    r = _join(t, outcome)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_401_takes_precedence_over_idempotency_conflict(api: Api, server):
    username, token = api.new_user()
    key = uuid.uuid4().hex
    first_name = f"ic1-{api.unique()}"
    r1 = api.request("POST", "/orgs", token=token, json={"name": first_name},
                     headers={"Idempotency-Key": key})
    assert r1.status_code == 201, r1.text

    # Same key, DIFFERENT request body would be 409 for a live session; with
    # the session dying while waiting it must be 401 first.
    other_name = f"ic2-{api.unique()}"
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, other_name, key=key)
        _revoke(lock, token)
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        # The conflicting request created nothing; the stored record survives.
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM organizations WHERE name = ?", (other_name,)
        ).fetchone()["n"] == 0
    finally:
        ro.close()

    # After re-login the original key + body still replays the first org.
    new_token = api.token_for(username)
    r2 = api.request("POST", "/orgs", token=new_token, json={"name": first_name},
                     headers={"Idempotency-Key": key})
    assert r2.status_code == 201, r2.text
    assert r2.json()["name"] == first_name


def test_successful_creation_survives_later_logout(api: Api):
    username, token = api.new_user()
    name = f"kept-{api.unique()}"
    r = api.request("POST", "/orgs", token=token, json={"name": name})
    assert r.status_code == 201
    org_id = r.json()["id"]
    assert api.request("POST", "/auth/logout", token=token).status_code == 200

    # The completed creation is retained; a fresh session sees the admin
    # membership, and the dead session can no longer do anything.
    new_token = api.token_for(username)
    orgs = api.request("GET", "/orgs", token=new_token).json()["organizations"]
    mine = next(o for o in orgs if o["id"] == org_id)
    assert mine["name"] == name and mine["role"] == "admin" and mine["status"] == "active"
    assert api.request("POST", "/orgs", token=token,
                       json={"name": f"{name}-x"}).status_code == 401
