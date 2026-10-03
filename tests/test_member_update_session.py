"""Session validity at EXECUTION TIME for PATCH /orgs/{org_id}/members/{id}.

Regression: when an administrator submits a role/status adjustment, the
carried session may be logged out, revoked via "logout other sessions" or a
password change, or simply reach its expiry instant while the request is
waiting to enter its serialized write transaction (or waiting on a prior
request in the same server). The adjustment must be authorized by the
session state at the moment it actually runs — the re-check happens inside
the IMMEDIATE transaction, before the enabled-admin membership check, the
target lookup, the last-admin invariant, the idempotency lookup and every
write.

Determinism: the test process takes SQLite's single write lock with
``BEGIN IMMEDIATE`` and only then sends the PATCH. The server endpoint
queues behind the lock (busy_timeout), so whatever the test commits before
releasing it is guaranteed to be visible to the in-transaction session
re-check — no thread scheduling or sleep-based race. This is the same
harness as test_member_remove.py.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid

import httpx

from app.idempotency import scope_member_update
from app.security import hash_password
from tests.conftest import Api


# --------------------------------------------------------------- test helpers

def _key() -> str:
    return uuid.uuid4().hex


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _new_org(api: Api, prefix: str = "mu"):
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


def _two_admins(api: Api):
    a_name, a_token = api.new_user()
    org = api.request("POST", "/orgs", token=a_token,
                      json={"name": f"mu2-{api.unique()}"}).json()
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


def _member(api: Api, token: str, org_id: int, user_id: int) -> dict:
    return next(m for m in _roster(api, token, org_id) if m["user_id"] == user_id)


def _grant(api: Api, admin_token: str, org_id: int, user_id: int, duration: int = 3600):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": user_id, "duration_seconds": duration})


def _patch(api: Api, token: str | None, org_id: int, user_id: int, body: dict,
           *, key: str | None = None, headers: dict | None = None) -> httpx.Response:
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if key is not None:
        h["Idempotency-Key"] = key
    return api.request("PATCH", f"/orgs/{org_id}/members/{user_id}",
                       headers=h, json=body)


def _audit_grouped(api: Api, token: str, org_id: int) -> dict[str, list[dict]]:
    items = api.request("GET", f"/orgs/{org_id}/audit?page=1&page_size=100",
                        token=token).json()["items"]
    grouped: dict[str, list[dict]] = {}
    for it in items:
        grouped.setdefault(it["action"], []).append(it)
    return grouped


def _revoke_session(db, token: str) -> None:
    db.execute("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
               (int(time.time()), _hash(token)))


def _blocked(api: Api, db, send, mutate) -> httpx.Response:
    """Send a request in a thread while the write lock is held.

    The request passes its arrival-time session check and then blocks on the
    write lock; ``mutate()`` runs under the lock and commits together with
    the lock release, so the endpoint's in-transaction session re-check
    observes the mutated state exactly as if it had landed while the request
    waited its turn.
    """
    db.execute("BEGIN IMMEDIATE")
    out: dict[str, httpx.Response] = {}

    def worker() -> None:
        out["r"] = send()

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(1.0)  # let the request arrive and block on the write lock
    mutate()
    db.commit()
    t.join(timeout=30)
    assert not t.is_alive(), "request hung"
    return out["r"]


_DISABLE = {"status": "disabled"}


# ============================================================ invalidation

def test_session_logged_out_while_waiting_is_401_and_changes_nothing(api: Api, db):
    aname, admin, org = _new_org(api, "mu-lo")
    tname, _, tid = _add_member(api, admin, org["id"])
    before = _member(api, admin, org["id"], tid)
    key = _key()

    r = _blocked(api, db,
                 send=lambda: _patch(api, admin, org["id"], tid, _DISABLE, key=key),
                 mutate=lambda: _revoke_session(db, admin))
    assert r.status_code == 401, r.text
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}

    # The target's role, status AND updated_at are exactly as they were.
    admin2 = api.token_for(aname)
    after = _member(api, admin2, org["id"], tid)
    assert after["role"] == before["role"] == "member"
    assert after["status"] == before["status"] == "active"
    assert after["updated_at"] == before["updated_at"]

    # No member-change or delegation audit was produced, and the key is free.
    grouped = _audit_grouped(api, admin2, org["id"])
    assert "member.updated" not in grouped
    n = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE scope = ? AND idempotency_key = ?",
        (scope_member_update(org["id"]), key),
    ).fetchone()["n"]
    assert n == 0

    # Re-logged-in (still enabled admin) reuses the same key + request.
    r = _patch(api, admin2, org["id"], tid, _DISABLE, key=key)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


def test_session_revoked_by_logout_others_while_waiting_is_401(api: Api, db):
    aname, s1, org = _new_org(api, "mu-lo2")
    s2 = api.token_for(aname)  # a second, independent session of the same admin
    _, _, tid = _add_member(api, s1, org["id"])

    # Models the committed end state of POST /auth/logout-others made from s2:
    # the OTHER session (this request's) is revoked, s2 stays live.
    r = _blocked(api, db,
                 send=lambda: _patch(api, s1, org["id"], tid, _DISABLE),
                 mutate=lambda: _revoke_session(db, s1))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # The carried session stays dead; the surviving session is unaffected and
    # the member was not changed.
    assert _patch(api, s1, org["id"], tid, _DISABLE).status_code == 401
    assert _member(api, s2, org["id"], tid)["status"] == "active"


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api, "mu-pw")
    _, _, tid = _add_member(api, admin, org["id"])
    uid = db.execute("SELECT id FROM users WHERE username = ?", (aname,)).fetchone()["id"]

    def mutate():
        # Exact committed end state of POST /auth/password: new hash plus
        # revoked_at on every live session of the account, together.
        ts = int(time.time())
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (hash_password("N3wPass!"), uid))
        db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )

    r = _blocked(api, db,
                 send=lambda: _patch(api, admin, org["id"], tid, _DISABLE),
                 mutate=mutate)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert db.execute("SELECT status FROM memberships WHERE org_id = ? AND user_id = ?",
                      (org["id"], tid)).fetchone()["status"] == "active"

    # Old password no longer works; with the new password the adjustment
    # proceeds under the normal rules.
    assert api.login(aname, "Passw0rd!").status_code == 401
    new_token = api.token_for(aname, "N3wPass!")
    r = _patch(api, new_token, org["id"], tid, _DISABLE)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api, "mu-exp")
    _, _, tid = _add_member(api, admin, org["id"])

    # Valid on arrival; the expiry instant ITSELF (expires_at <= now) passes
    # while the PATCH waits for the write lock.
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _hash(admin)))
    db.commit()
    r = _blocked(api, db,
                 send=lambda: _patch(api, admin, org["id"], tid, _DISABLE),
                 mutate=lambda: time.sleep(3))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    admin2 = api.token_for(aname)
    assert _member(api, admin2, org["id"], tid)["status"] == "active"


def test_another_live_session_cannot_substitute(api: Api, db):
    aname, s1, org = _new_org(api, "mu-as")
    s2 = api.token_for(aname)
    _, _, tid = _add_member(api, s1, org["id"])

    r = _blocked(api, db,
                 send=lambda: _patch(api, s1, org["id"], tid, _DISABLE),
                 mutate=lambda: _revoke_session(db, s1))
    assert r.status_code == 401

    # The other, still-valid session cannot rescue the rejected one, but it
    # can perform its own adjustment exactly once.
    assert _patch(api, s1, org["id"], tid, _DISABLE).status_code == 401
    r = _patch(api, s2, org["id"], tid, _DISABLE)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


def test_revoking_only_other_sessions_lets_adjustment_proceed(api: Api, db):
    aname, s1, org = _new_org(api, "mu-others")
    s2 = api.token_for(aname)
    tname, _, tid = _add_member(api, s1, org["id"])

    # Only the OTHER session is revoked while this request waits: the carried
    # session is still live, so the adjustment proceeds normally.
    r = _blocked(api, db,
                 send=lambda: _patch(api, s1, org["id"], tid, _DISABLE),
                 mutate=lambda: _revoke_session(db, s2))
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"
    assert _member(api, s1, org["id"], tid)["status"] == "disabled"


# ============================================================ side effects

def test_rejected_adjustment_neither_changes_member_nor_invalidates_delegation(api: Api, db):
    aname, admin, org = _new_org(api, "mu-del")
    tname, _, tid = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], tid).json()
    before = _member(api, admin, org["id"], tid)

    # Disabling the delegate would invalidate the delegation; a 401 must do
    # neither.
    r = _blocked(api, db,
                 send=lambda: _patch(api, admin, org["id"], tid, _DISABLE),
                 mutate=lambda: _revoke_session(db, admin))
    assert r.status_code == 401

    admin2 = api.token_for(aname)
    after = _member(api, admin2, org["id"], tid)
    assert after["role"] == "member" and after["status"] == "active"
    assert after["updated_at"] == before["updated_at"]
    entry = next(x for x in api.request("GET", f"/orgs/{org['id']}/delegations",
                                        token=admin2).json()["delegations"]
                 if x["id"] == d["id"])
    assert entry["status"] == "active" and entry["reason"] is None
    grouped = _audit_grouped(api, admin2, org["id"])
    assert "member.updated" not in grouped
    assert "delegation.invalidated" not in grouped


# ============================================================ idempotency

def test_replay_of_stored_success_requires_a_live_session(api: Api, db):
    org, aname, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    body = {"role": "member"}
    first = _patch(api, a_token, org["id"], b_id, body, key=key)
    assert first.status_code == 200, first.text
    # Restore B so a successful retry would have something to report.
    assert _patch(api, a_token, org["id"], b_id, {"role": "admin"}).status_code == 200

    # A replay of the stored success whose carrying session died while
    # waiting: 401, never the cached membership snapshot.
    r = _blocked(api, db,
                 send=lambda: _patch(api, a_token, org["id"], b_id, body, key=key),
                 mutate=lambda: _revoke_session(db, a_token))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert str(b_id) not in r.text  # no cached member info leaked

    # The stored record is untouched: after a fresh login the same key
    # replays the ORIGINAL result and produces no second member-change audit.
    a2 = api.token_for(aname)
    r = _patch(api, a2, org["id"], b_id, body, key=key)
    assert r.status_code == 200 and r.json() == first.json()
    n = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys WHERE scope = ? AND idempotency_key = ?",
        (scope_member_update(org["id"]), key),
    ).fetchone()["n"]
    assert n == 1
    assert len(_audit_grouped(api, a2, org["id"])["member.updated"]) == 2  # demote + restore


def test_unused_key_is_not_consumed_by_401_and_reusable_after_relogin(api: Api, db):
    aname, admin, org = _new_org(api, "mu-key")
    _, _, tid = _add_member(api, admin, org["id"])
    key = _key()

    r = _blocked(api, db,
                 send=lambda: _patch(api, admin, org["id"], tid, _DISABLE, key=key),
                 mutate=lambda: _revoke_session(db, admin))
    assert r.status_code == 401
    assert db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE operator_id = ? AND scope = ? AND idempotency_key = ?",
        (db.execute("SELECT id FROM users WHERE username = ?", (aname,)).fetchone()["id"],
         scope_member_update(org["id"]), key),
    ).fetchone()["n"] == 0

    new_token = api.token_for(aname)
    r = _patch(api, new_token, org["id"], tid, _DISABLE, key=key)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


# ============================================================ 401 precedence

def test_unauthorized_takes_precedence_over_other_failures(api: Api, db):
    # 403 for a non-admin (ordinary active member).
    org, _, a_token, _, b_name, b_token, b_id = _two_admins(api)
    m_name, m_token, m_id = _add_member(api, a_token, org["id"], "member")
    r = _blocked(api, db,
                 send=lambda: _patch(api, m_token, org["id"], b_id, _DISABLE),
                 mutate=lambda: _revoke_session(db, m_token))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # 403 for a disabled admin (target state is otherwise valid).
    org2, _, a2_token, a2_id, _, b2_token, b2_id = _two_admins(api)
    assert _patch(api, a2_token, org2["id"], b2_id, _DISABLE).status_code == 200
    r = _blocked(api, db,
                 send=lambda: _patch(api, b2_token, org2["id"], a2_id,
                                     {"role": "member"}),
                 mutate=lambda: _revoke_session(db, b2_token))
    assert r.status_code == 401
    # A is untouched and a fresh login sees B still disabled.
    assert _member(api, a2_token, org2["id"], a2_id)["role"] == "admin"
    assert _member(api, a2_token, org2["id"], b2_id)["status"] == "disabled"

    # 403 for an unknown organization.
    aname2, admin2, org2 = _new_org(api, "mu-uorg")
    r = _blocked(api, db,
                 send=lambda: _patch(api, admin2, 999999, 1, _DISABLE),
                 mutate=lambda: _revoke_session(db, admin2))
    assert r.status_code == 401

    # 404 for a target outside the organization.
    aname3, admin3, org3 = _new_org(api, "mu-404")
    r = _blocked(api, db,
                 send=lambda: _patch(api, admin3, org3["id"], 999999, _DISABLE),
                 mutate=lambda: _revoke_session(db, admin3))
    assert r.status_code == 401

    # 409 last_admin_required for the sole admin's self-demotion.
    aname4, admin4, org4 = _new_org(api, "mu-la")
    me = _member(api, admin4, org4["id"], _member_ids(api, admin4, org4["id"])[aname4])["user_id"]
    r = _blocked(api, db,
                 send=lambda: _patch(api, admin4, org4["id"], me, {"role": "member"}),
                 mutate=lambda: _revoke_session(db, admin4))
    assert r.status_code == 401
    # The last admin is still in place after re-login.
    admin5 = api.token_for(aname4)
    m = _member(api, admin5, org4["id"], me)
    assert m["role"] == "admin" and m["status"] == "active"


def test_unauthorized_takes_precedence_over_idempotency_conflict(api: Api, db):
    org, aname, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    first_body = {"status": "disabled"}
    assert _patch(api, a_token, org["id"], b_id, first_body, key=key).status_code == 200
    assert _patch(api, a_token, org["id"], b_id, {"status": "active"}).status_code == 200

    # Same key, DIFFERENT body, session dies while waiting: the session check
    # wins; no idempotency_conflict and the stored record is untouched.
    other_body = {"role": "member"}
    r = _blocked(api, db,
                 send=lambda: _patch(api, a_token, org["id"], b_id, other_body, key=key),
                 mutate=lambda: _revoke_session(db, a_token))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Live session: the different body is now the ordinary 409, and the
    # original key+body still replays the original result.
    a2 = api.token_for(aname)
    r = _patch(api, a2, org["id"], b_id, other_body, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    r = _patch(api, a2, org["id"], b_id, first_body, key=key)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


# ======================================================== header compatibility

def test_x_session_token_revoked_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api, "mu-xst")
    _, _, tid = _add_member(api, admin, org["id"])

    r = _blocked(
        api, db,
        send=lambda: api.request("PATCH", f"/orgs/{org['id']}/members/{tid}",
                                 headers={"X-Session-Token": admin}, json=_DISABLE),
        mutate=lambda: _revoke_session(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    admin2 = api.token_for(aname)
    assert _member(api, admin2, org["id"], tid)["status"] == "active"


# ============================================================ commit ordering

def test_adjustment_committed_then_session_invalidated_keeps_change(api: Api):
    aname, admin, org = _new_org(api, "mu-kept")
    _, _, tid = _add_member(api, admin, org["id"])
    r = _patch(api, admin, org["id"], tid, _DISABLE)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"

    # Session dies only AFTER the adjustment committed: nothing is undone.
    assert api.request("POST", "/auth/logout", token=admin).status_code == 200
    admin2 = api.token_for(aname)
    assert _member(api, admin2, org["id"], tid)["status"] == "disabled"
    assert len(_audit_grouped(api, admin2, org["id"])["member.updated"]) == 1
