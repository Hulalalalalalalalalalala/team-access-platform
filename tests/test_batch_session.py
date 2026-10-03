"""Session validity at EXECUTION TIME for the batch member PATCH endpoint.

Regression for PATCH /orgs/{org_id}/members/batch: a session that is valid
when the request arrives may be logged out, revoked via "logout other
sessions" / a password change, or reach its expiry instant while the request
is waiting to enter its serialized write transaction. The whole batch (and
any Idempotency-Key replay) must be authorized by the session state at the
moment it actually runs — the re-check happens inside the IMMEDIATE
transaction, before the membership check, the target lookups, the last-admin
invariant and the idempotency lookup. Same rule as the single-member
endpoint (see test_member_session.py).

Determinism: the test process holds SQLite's single write lock with
``BEGIN IMMEDIATE`` and only then starts the PATCH request. The server
endpoint cannot enter its own write transaction (it queues behind the lock
with busy_timeout), so whatever the test commits before releasing the lock
is guaranteed to be visible to the in-transaction session re-check — no
thread scheduling or sleep-based race.
"""
from __future__ import annotations

import hashlib
import threading
import time

from app.security import hash_password
from tests.conftest import Api


# --------------------------------------------------------------- test helpers

def _key() -> str:
    return f"k-{time.time_ns()}"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _new_org(api: Api, prefix: str = "mb-sess"):
    name, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    return name, token, org


def _add_member(api: Api, admin_token: str, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    return name, token, r.json()["membership"]["user_id"]


def _two_admins(api: Api, prefix: str = "mb2"):
    """Org with two ACTIVE admins A (creator) and B; returns names/tokens/ids."""
    a_name, a_token = api.new_user()
    org = api.request("POST", "/orgs", token=a_token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    b_name, b_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=a_token,
                      json={"username": b_name, "role": "admin"}).json()
    assert api.request("POST", "/invites/accept", token=b_token,
                       json={"token": inv["token"]}).status_code == 200
    ids = _member_ids(api, a_token, org["id"])
    return org, a_name, a_token, ids[a_name], b_name, b_token, ids[b_name]


def _member_ids(api: Api, token: str, org_id: int) -> dict[str, int]:
    rows = api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]
    return {m["username"]: m["user_id"] for m in rows}


def _roster(api: Api, token: str, org_id: int) -> list[dict]:
    return api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]


def _audit_grouped(api: Api, token: str, org_id: int) -> dict[str, list[dict]]:
    items = api.request("GET", f"/orgs/{org_id}/audit?page=1&page_size=100",
                        token=token).json()["items"]
    grouped: dict[str, list[dict]] = {}
    for it in items:
        grouped.setdefault(it["action"], []).append(it)
    return grouped


def _batch(api: Api, token, org_id: int, changes: list[dict],
           *, key: str | None = None, headers: dict | None = None):
    h = dict(headers or {})
    if token is not None and "X-Session-Token" not in h:
        h["Authorization"] = f"Bearer {token}"
    if key is not None:
        h["Idempotency-Key"] = key
    return api.request("PATCH", f"/orgs/{org_id}/members/batch",
                       headers=h, json={"changes": changes})


def _grant(api: Api, admin_token: str, org_id: int, user_id: int):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": user_id, "duration_seconds": 3600})


def _revoke(db, token: str, ts: int | None = None) -> None:
    db.execute("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
               (ts if ts is not None else int(time.time()), _token_hash(token)))


def _blocked_batch(api: Api, db, send, mutate):
    """Run a batch PATCH ``send()`` while the database write lock is held.

    The request passes its arrival-time session check and then blocks on the
    write lock; ``mutate()`` runs under the lock and commits together with
    the lock release, so the PATCH's in-transaction session re-check
    observes the mutated state exactly as if it had landed while the request
    was waiting its turn.
    """
    db.commit()  # close any reader transaction the fixture connection opened
    db.execute("BEGIN IMMEDIATE")
    out: dict[str, object] = {}

    def worker() -> None:
        out["r"] = send()

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(1.0)  # let the request arrive, pass the dependency, and queue
    mutate()
    db.commit()
    t.join(timeout=30)
    assert not t.is_alive(), "batch PATCH request hung"
    return out["r"]


def _member_row(db, org_id: int, user_id: int):
    return db.execute(
        "SELECT role, status, updated_at FROM memberships"
        " WHERE org_id = ? AND user_id = ?",
        (org_id, user_id),
    ).fetchone()


# ----------------------------------------------------------- first-use timing

def test_session_logged_out_while_waiting_is_401_and_changes_nothing(api: Api, db):
    _, admin, org = _new_org(api)
    _, _, t1 = _add_member(api, admin, org["id"])
    _, _, t2 = _add_member(api, admin, org["id"])
    before1 = _member_row(db, org["id"], t1)
    before2 = _member_row(db, org["id"], t2)

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"],
                            [{"user_id": t1, "status": "disabled"},
                             {"user_id": t2, "role": "admin"}]),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    # No member info or batch result leaks on the 401 path.
    assert "members" not in r.text and "batch_id" not in r.text

    # The whole batch is rejected: NEITHER target's role/status/updated_at
    # moved (atomicity of the refused batch).
    assert tuple(_member_row(db, org["id"], t1)) == tuple(before1)
    assert tuple(_member_row(db, org["id"], t2)) == tuple(before2)
    # No member-change or delegation-invalidation audit was produced by the
    # rejected batch (org.created / invite.created rows predate it).
    assert db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action IN ('member.updated', 'delegation.invalidated')",
        (org["id"],),
    ).fetchone()["n"] == 0


def test_session_revoked_by_logout_others_while_waiting_is_401(api: Api, db):
    """Models the committed end state of POST /auth/logout-others.

    The waiting session is revoked while another session of the same account
    stays live; only the session actually carried by this request matters.
    """
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)  # the surviving session
    _, _, tid = _add_member(api, s1, org["id"])

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, s1, org["id"], [{"user_id": tid, "status": "disabled"}]),
        mutate=lambda: _revoke(db, s1),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # The dead session stays dead; the other one cannot stand in for it but
    # works fine on its own.
    assert _batch(api, s1, org["id"],
                  [{"user_id": tid, "status": "disabled"}]).status_code == 401
    assert _member_row(db, org["id"], tid)["status"] == "active"
    r = _batch(api, s2, org["id"], [{"user_id": tid, "status": "disabled"}])
    assert r.status_code == 200 and r.json()["members"][0]["status"] == "disabled"


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api)
    _, _, tid = _add_member(api, admin, org["id"])
    uid = _member_ids(api, admin, org["id"])[aname]
    before = _member_row(db, org["id"], tid)

    def _change_password() -> None:
        # Exact committed end state of POST /auth/password: new hash plus
        # revoked_at on every live session of the account, together.
        ts = int(time.time())
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (hash_password("N3wPass!"), uid))
        db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"], [{"user_id": tid, "role": "admin"}]),
        mutate=_change_password,
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert tuple(_member_row(db, org["id"], tid)) == tuple(before)

    # Old password is gone; after logging in with the new one the account is
    # still an active admin and the same batch now succeeds.
    assert api.login(aname, "Passw0rd!").status_code == 401
    new_token = api.token_for(aname, "N3wPass!")
    r = _batch(api, new_token, org["id"], [{"user_id": tid, "role": "admin"}])
    assert r.status_code == 200 and r.json()["members"][0]["role"] == "admin"


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    _, admin, org = _new_org(api)
    _, _, tid = _add_member(api, admin, org["id"])
    before = _member_row(db, org["id"], tid)

    # Valid when the request arrives; the expiry instant ITSELF is invalid.
    db.commit()
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _token_hash(admin)))
    db.commit()
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"], [{"user_id": tid, "status": "disabled"}]),
        mutate=lambda: time.sleep(3),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert tuple(_member_row(db, org["id"], tid)) == tuple(before)


def test_another_live_session_cannot_authorize_a_revoked_one(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    _, _, tid = _add_member(api, s1, org["id"])

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, s1, org["id"], [{"user_id": tid, "status": "disabled"}]),
        mutate=lambda: _revoke(db, s1),
    )
    assert r.status_code == 401
    assert _member_row(db, org["id"], tid)["status"] == "active"

    # The still-valid session performs its own batch normally.
    r = _batch(api, s2, org["id"], [{"user_id": tid, "status": "disabled"}])
    assert r.status_code == 200 and r.json()["members"][0]["status"] == "disabled"


def test_revoking_only_other_sessions_lets_batch_proceed(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    _, _, tid = _add_member(api, s1, org["id"])

    # Only the OTHER session is revoked while this request waits: this
    # session is still live, so the batch proceeds normally.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, s1, org["id"], [{"user_id": tid, "status": "disabled"}]),
        mutate=lambda: _revoke(db, s2),
    )
    assert r.status_code == 200, r.text
    assert r.json()["members"][0]["status"] == "disabled"
    # s1 is untouched and still usable.
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=s1).status_code == 200


# ----------------------------------------------------- delegations stay intact

def test_401_invalidates_no_delegation(api: Api, db):
    org, _, a_token, _, _, _, _ = _two_admins(api)
    _, _, c_id = _add_member(api, a_token, org["id"])

    # An active delegation to ordinary member C exists.
    d = _grant(api, a_token, org["id"], c_id).json()
    assert d["status"] == "active"

    # Disabling the DELEGATE via a batch is rejected by a dead session: the
    # delegation survives and no invalidation audit is written.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, a_token, org["id"],
                            [{"user_id": c_id, "status": "disabled"}]),
        mutate=lambda: _revoke(db, a_token),
    )
    assert r.status_code == 401
    assert db.execute("SELECT status FROM delegations WHERE id = ?",
                      (d["id"],)).fetchone()["status"] == "active"
    assert db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'delegation.invalidated'",
        (org["id"],),
    ).fetchone()["n"] == 0


# ------------------------------------------------------------- idempotency key

def test_unused_key_is_not_consumed_by_401_and_reusable_after_relogin(api: Api, db):
    aname, admin, org = _new_org(api)
    _, _, tid = _add_member(api, admin, org["id"])
    key = _key()

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"],
                            [{"user_id": tid, "status": "disabled"}], key=key),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401

    # The rejected first attempt did not occupy the key.
    assert db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE scope = ? AND idempotency_key = ?",
        (f"org:{org['id']}:member.batch_update", key),
    ).fetchone()["n"] == 0

    # Re-login and reuse the SAME key with the SAME request: it now succeeds.
    new_token = api.token_for(aname)
    r = _batch(api, new_token, org["id"],
               [{"user_id": tid, "status": "disabled"}], key=key)
    assert r.status_code == 200 and r.json()["members"][0]["status"] == "disabled"


def test_replay_of_stored_success_requires_a_live_session(api: Api, db):
    aname, admin, org = _new_org(api)
    _, _, tid = _add_member(api, admin, org["id"])
    key = _key()
    changes = [{"user_id": tid, "status": "disabled"}]
    first = _batch(api, admin, org["id"], changes, key=key)
    assert first.status_code == 200, first.text
    first_body = first.json()

    # A replay of the stored success whose carrying session dies while
    # waiting: 401, never the cached batch result.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"], changes, key=key),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert "members" not in r.text and "batch_id" not in r.text

    # The stored record is untouched: after a fresh login the same key
    # replays the ORIGINAL success, with no second change and no second audit.
    new_token = api.token_for(aname)
    r = _batch(api, new_token, org["id"], changes, key=key)
    assert r.status_code == 200
    assert r.json() == first_body
    grouped = _audit_grouped(api, new_token, org["id"])
    assert len(grouped.get("member.updated", [])) == 1


# --------------------------------------------------------- 401 takes priority

def test_401_takes_precedence_over_403(api: Api, db):
    _, admin, org = _new_org(api)
    _, mtoken, _ = _add_member(api, admin, org["id"])
    _, _, tid = _add_member(api, admin, org["id"])

    # A live ordinary member would get 403; with the session revoked while
    # waiting, the answer is 401.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, mtoken, org["id"], [{"user_id": tid, "role": "admin"}]),
        mutate=lambda: _revoke(db, mtoken),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Unknown organization likewise: a live session gets the uniform 403, a
    # dead one gets 401 first.
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]["user_id"]
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, 999999, [{"user_id": me, "status": "disabled"}]),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"


def test_401_takes_precedence_over_404_missing_target(api: Api, db):
    _, admin, org = _new_org(api)
    # A live session would get 404 member_not_found here.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"], [{"user_id": 999999, "role": "member"}]),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"


def test_401_takes_precedence_over_last_admin(api: Api, db):
    _, admin, org = _new_org(api)
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]["user_id"]
    # A live session disabling the sole active admin gets 409; a dead one
    # gets 401 and the admin stays in place.
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, admin, org["id"], [{"user_id": me, "status": "disabled"}]),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    row = _member_row(db, org["id"], me)
    assert row["role"] == "admin" and row["status"] == "active"


def test_401_takes_precedence_over_idempotency_conflict(api: Api, db):
    org, aname, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    first_changes = [{"user_id": b_id, "role": "member"}]
    first = _batch(api, a_token, org["id"], first_changes, key=key)
    assert first.status_code == 200, first.text

    # Same key, DIFFERENT body, session dies while waiting: the session check
    # wins; no idempotency_conflict and the stored record is untouched.
    other_changes = [{"user_id": b_id, "status": "disabled"}]
    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, a_token, org["id"], other_changes, key=key),
        mutate=lambda: _revoke(db, a_token),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # With a live session the different body is the ordinary 409, while the
    # original key+body still replays the original result.
    new_token = api.token_for(aname)
    r = _batch(api, new_token, org["id"], other_changes, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    r = _batch(api, new_token, org["id"], first_changes, key=key)
    assert r.status_code == 200 and r.json() == first.json()


# ------------------------------------------------------- header compatibility

def test_x_session_token_revoked_while_waiting_is_401(api: Api, db):
    _, admin, org = _new_org(api)
    _, _, tid = _add_member(api, admin, org["id"])

    r = _blocked_batch(
        api, db,
        send=lambda: _batch(api, None, org["id"],
                            [{"user_id": tid, "status": "disabled"}],
                            headers={"X-Session-Token": admin}),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}
    assert _member_row(db, org["id"], tid)["status"] == "active"


# ------------------------------------------------- success precedes invalidation

def test_batch_committed_first_then_session_invalidated_keeps_changes(api: Api):
    aname, admin, org = _new_org(api)
    _, _, t1 = _add_member(api, admin, org["id"])
    _, _, t2 = _add_member(api, admin, org["id"])

    r = _batch(api, admin, org["id"],
               [{"user_id": t1, "status": "disabled"},
                {"user_id": t2, "role": "admin"}])
    assert r.status_code == 200, r.text
    batch_id = r.json()["batch_id"]
    # The session dies only AFTER the batch committed: the changes and their
    # audit rows stand and are not rolled back.
    assert api.request("POST", "/auth/logout", token=admin).status_code == 200

    new_token = api.token_for(aname)
    members = {m["user_id"]: m for m in _roster(api, new_token, org["id"])}
    assert members[t1]["status"] == "disabled"
    assert members[t2]["role"] == "admin"
    grouped = _audit_grouped(api, new_token, org["id"])
    updates = grouped.get("member.updated", [])
    assert len(updates) == 2
    # Both changes keep the shared batch_id of the committed batch.
    assert {u["batch_id"] for u in updates} == {batch_id}
