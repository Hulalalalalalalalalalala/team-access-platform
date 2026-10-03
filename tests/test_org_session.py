"""Session validity at EXECUTION TIME for POST /orgs.

Regression: a session that is valid when the request arrives may be logged
out, revoked via "logout other sessions" / a password change, or reach its
expiry instant while the request is waiting to enter its serialized write
transaction. Organization creation (and any Idempotency-Key replay) must be
authorized by the session state at the moment it actually runs — the
re-check happens inside the IMMEDIATE transaction, before the name check,
the idempotency lookup and every write.

Determinism: the test process takes SQLite's single write lock with
``BEGIN IMMEDIATE`` and only then starts the create request. The server
endpoint cannot enter its own write transaction (it queues behind the lock
with busy_timeout), so whatever the test commits before releasing the lock
is guaranteed to be visible to the in-transaction session re-check — no
thread scheduling or sleep-based race. This is the same harness as
test_invite_session.py.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import httpx

from app.idempotency import scope_org_create
from app.security import hash_password
from tests.conftest import Api


def _hash(token: str) -> str:
    import hashlib

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


def _blocked_create(
    api: Api,
    token: str,
    body: dict,
    *,
    key: str | None = None,
    header: str = "bearer",
):
    """Start a create-org request in a thread while the caller holds the lock."""
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
            outcome["response"] = c.post("/orgs", headers=headers, json=body)

    t = threading.Thread(target=_run)
    t.start()
    # Pass the dependency (a WAL read that does not block), then queue on
    # BEGIN IMMEDIATE behind OUR lock. Correctness does not rely on the sleep:
    # the endpoint cannot create anything until we COMMIT.
    time.sleep(0.3)
    return t, outcome


def _join(t: threading.Thread, outcome: dict[str, object]) -> httpx.Response:
    t.join(timeout=30)
    assert not t.is_alive(), "create request hung"
    return outcome["response"]  # type: ignore[return-value]


def _user_id(ro: sqlite3.Connection, username: str) -> int:
    return ro.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def _assert_nothing_created(ro: sqlite3.Connection, user_id: int) -> None:
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM organizations WHERE created_by = ?", (user_id,)
    ).fetchone()["n"] == 0
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE user_id = ?", (user_id,)
    ).fetchone()["n"] == 0
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE actor_id = ? AND action = 'org.created'",
        (user_id,),
    ).fetchone()["n"] == 0


def _assert_key_absent(ro: sqlite3.Connection, user_id: int, key: str) -> None:
    assert ro.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE operator_id = ? AND scope = ? AND idempotency_key = ?",
        (user_id, scope_org_create(), key),
    ).fetchone()["n"] == 0


# ----------------------------------------------------- first create timing

def test_session_logged_out_while_waiting_is_401_and_creates_nothing(api: Api, server):
    username, token = api.new_user()
    body = {"name": f"lo-{api.unique()}"}
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body)
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
    assert r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        _assert_nothing_created(ro, _user_id(ro, username))
    finally:
        ro.close()


def test_session_revoked_by_logout_others_while_waiting_is_401(api: Api, server):
    """Models the committed end state of POST /auth/logout-others.

    The waiting session is revoked while another session of the same account
    stays live; only the session actually carried by this request matters.
    """
    username, token1 = api.new_user()
    token2 = api.token_for(username)  # the surviving session
    body = {"name": f"lo2-{api.unique()}"}
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, body)
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token1)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, username)
        _assert_nothing_created(ro, uid)
        # The dead session is still dead on retry; the other one is fine.
        assert api.request("POST", "/orgs", token=token1, json=body).status_code == 401
        assert api.request("GET", "/orgs", token=token2).status_code == 200
        _assert_nothing_created(ro, uid)
    finally:
        ro.close()


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, server):
    username, token = api.new_user()
    ro = _reader(server.db_path)
    uid = _user_id(ro, username)
    ro.close()
    body = {"name": f"pw-{api.unique()}"}

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body)
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
        _assert_nothing_created(ro, uid)
    finally:
        ro.close()

    # Old password is gone; logging in with the new one leaves the name free.
    assert api.login(username, "Passw0rd!").status_code == 401
    new_token = api.token_for(username, "N3wPass!")
    r = api.request("POST", "/orgs", token=new_token, json=body)
    assert r.status_code == 201, r.text


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, server):
    username, token = api.new_user()
    body = {"name": f"ex-{api.unique()}"}
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body)
        # The expiry instant ITSELF is invalid (expires_at <= now).
        lock.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    ro = _reader(server.db_path)
    try:
        _assert_nothing_created(ro, _user_id(ro, username))
    finally:
        ro.close()


def test_another_live_session_cannot_authorize_a_revoked_one(api: Api, server):
    username, token1 = api.new_user()
    token2 = api.token_for(username)
    body = {"name": f"as-{api.unique()}"}

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, body)
        # Only the carried session is revoked; the other live session must
        # not stand in for it.
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token1)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, username)
        _assert_nothing_created(ro, uid)
    finally:
        ro.close()

    # The still-valid session performs its own creation exactly once.
    r = api.request("POST", "/orgs", token=token2, json=body)
    assert r.status_code == 201, r.text


def test_revoking_an_unrelated_session_while_waiting_keeps_success(api: Api, server):
    username, token1 = api.new_user()
    token2 = api.token_for(username)

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token1, {"name": f"un-{api.unique()}"})
        # The other session is revoked; the carried one is untouched.
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token2)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "admin"


def test_create_committed_first_then_session_invalidated_keeps_org(api: Api):
    username, token = api.new_user()
    body = {"name": f"kept-{api.unique()}"}
    r = api.request("POST", "/orgs", token=token, json=body)
    assert r.status_code == 201, r.text
    org = r.json()
    # Session dies only AFTER the creation committed: the result stands.
    assert api.request("POST", "/auth/logout", token=token).status_code == 200

    new_token = api.token_for(username)
    orgs = api.request("GET", "/orgs", token=new_token).json()["organizations"]
    mine = [o for o in orgs if o["id"] == org["id"]]
    assert len(mine) == 1 and mine[0]["role"] == "admin"


# --------------------------------------------------------- idempotency timing

def test_replay_of_stored_success_requires_a_live_session(api: Api, server):
    username, token = api.new_user()
    key = f"k-{api.unique()}"
    body = {"name": f"rs-{api.unique()}"}
    first = api.request("POST", "/orgs", token=token, json=body,
                        headers={"Idempotency-Key": key})
    assert first.status_code == 201, first.text

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body, key=key)
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    # Even though the key holds a success, a dead session gets 401 and no
    # organization information; the stored success is not rewritten.
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert str(first.json()["id"]) not in r.text

    # After a fresh login the same key+body still returns the ORIGINAL result.
    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json=body,
                    headers={"Idempotency-Key": key})
    assert r.status_code == 201, r.text
    assert r.json() == first.json()

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, username)
        # The replay neither created a second org nor added a second audit.
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM organizations WHERE created_by = ?", (uid,)
        ).fetchone()["n"] == 1
        assert ro.execute(
            "SELECT COUNT(*) AS n FROM audit_logs"
            " WHERE actor_id = ? AND action = 'org.created'", (uid,)
        ).fetchone()["n"] == 1
    finally:
        ro.close()


def test_unused_key_is_not_consumed_by_401_and_reusable_after_relogin(api: Api, server):
    username, token = api.new_user()
    key = f"k-{api.unique()}"
    body = {"name": f"uc-{api.unique()}"}

    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body, key=key)
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    assert _join(t, outcome).status_code == 401

    ro = _reader(server.db_path)
    try:
        uid = _user_id(ro, username)
        _assert_nothing_created(ro, uid)
        _assert_key_absent(ro, uid, key)
    finally:
        ro.close()

    # Re-login and reuse the SAME key with the SAME request: it now succeeds.
    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json=body,
                    headers={"Idempotency-Key": key})
    assert r.status_code == 201, r.text
    assert r.json()["name"] == body["name"]


def test_unauthorized_takes_precedence_over_name_taken(api: Api, server):
    _, owner = api.new_user()
    name = f"nt-{api.unique()}"
    assert api.request("POST", "/orgs", token=owner, json={"name": name}).status_code == 201

    username, token = api.new_user()
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, {"name": name})
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
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
        _assert_nothing_created(ro, _user_id(ro, username))
    finally:
        ro.close()

    # With a live session the same name is reported as the ordinary conflict.
    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json={"name": name})
    assert r.status_code == 409 and r.json()["error"]["code"] == "org_name_taken"


def test_unauthorized_takes_precedence_over_idempotency_conflict(api: Api, server):
    username, token = api.new_user()
    key = f"k-{api.unique()}"
    first_body = {"name": f"ic1-{api.unique()}"}
    first = api.request("POST", "/orgs", token=token, json=first_body,
                        headers={"Idempotency-Key": key})
    assert first.status_code == 201, first.text

    # Same key, DIFFERENT body, session dies while waiting: the session check
    # wins; no idempotency_conflict and the stored record is untouched.
    other_body = {"name": f"ic2-{api.unique()}"}
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, other_body, key=key)
        lock.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (int(time.time()), _hash(token)),
        )
        lock.execute("COMMIT")
    finally:
        lock.close()

    r = _join(t, outcome)
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"

    # Live session: the different body is now the ordinary 409, and the
    # original key+body still replays the original result.
    new_token = api.token_for(username)
    r = api.request("POST", "/orgs", token=new_token, json=other_body,
                    headers={"Idempotency-Key": key})
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    r = api.request("POST", "/orgs", token=new_token, json=first_body,
                    headers={"Idempotency-Key": key})
    assert r.status_code == 201 and r.json() == first.json()


# ------------------------------------------------------- header compatibility

def test_x_session_token_creates_org(api: Api):
    username, token = api.new_user()
    r = api.request(
        "POST", "/orgs", json={"name": f"xh-{api.unique()}"},
        headers={"X-Session-Token": token},
    )
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "admin"


def test_401_via_x_session_token_header_uses_error_envelope(api: Api, server):
    _, token = api.new_user()
    body = {"name": f"xe-{api.unique()}"}
    lock = _writer(server.db_path)
    lock.execute("BEGIN IMMEDIATE")
    try:
        t, outcome = _blocked_create(api, token, body, header="x")
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
