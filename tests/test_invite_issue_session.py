"""Session validity at EXECUTION TIME for POST /orgs/{org_id}/invites.

Regression for invite ISSUANCE (as opposed to acceptance, covered by
test_invite_session.py): a session that is valid when the request arrives may
be logged out, revoked via "logout other sessions" / a password change, or
reach its expiry instant while the request is waiting to enter its serialized
write transaction. The issuance — and any Idempotency-Key replay, including
one whose key already holds a success with its cached invite token — must be
authorized by the session state at the moment it actually runs. The re-check
happens inside the IMMEDIATE transaction, before the membership/role check,
the delegate's active-delegation lookup, the idempotency lookup and every
write.

Determinism: the test process holds SQLite's single write lock with
``BEGIN IMMEDIATE`` and only then starts the issue request. The server
endpoint cannot enter its own write transaction (it queues behind the lock
with busy_timeout), so whatever the test commits before releasing the lock
is guaranteed to be visible to the in-transaction session re-check — no
thread scheduling or sleep-based race. Same harness as
test_org_session.py / test_member_session.py.
"""
from __future__ import annotations

import hashlib
import threading
import time

from app.idempotency import scope_invite_create
from app.security import hash_password
from tests.conftest import Api


# --------------------------------------------------------------- test helpers

def _key() -> str:
    return f"k-{time.time_ns()}"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _new_org(api: Api, prefix: str = "is"):
    name, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    return name, token, org


def _add_member(api: Api, admin_token: str, org_id: int, role: str = "member"):
    """Register a user, invite them and accept. Returns (name, token, id)."""
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    return name, token, r.json()["membership"]["user_id"]


def _member_id(api: Api, token: str, org_id: int, username: str) -> int:
    rows = api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]
    return next(m["user_id"] for m in rows if m["username"] == username)


def _grant(api: Api, admin_token: str, org_id: int, user_id: int,
           duration: int = 3600):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": user_id, "duration_seconds": duration})


def _issue(api: Api, token: str | None, org_id: int, username: str,
           role: str = "member", *, key: str | None = None,
           headers: dict | None = None):
    h = dict(headers or {})
    if token is not None and "X-Session-Token" not in h:
        h["Authorization"] = f"Bearer {token}"
    if key is not None:
        h["Idempotency-Key"] = key
    return api.request("POST", f"/orgs/{org_id}/invites", headers=h,
                       json={"username": username, "role": role})


def _revoke(db, token: str, ts: int | None = None) -> None:
    db.execute("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
               (ts if ts is not None else int(time.time()), _token_hash(token)))


def _blocked_issue(api: Api, db, send, mutate):
    """Run an issue ``send()`` while the database write lock is held.

    The request passes its arrival-time session check and then blocks on the
    write lock; ``mutate()`` runs under the lock and commits together with
    the lock release, so the endpoint's in-transaction session re-check
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
    assert not t.is_alive(), "invite request hung"
    return out["r"]


def _invites_for(db, org_id: int, username: str) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM invites WHERE org_id = ? AND invite_username = ?",
        (org_id, username),
    ).fetchone()["n"]


def _created_audits(db, org_id: int, actor_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'invite.created' AND actor_id = ?",
        (org_id, actor_id),
    ).fetchone()["n"]


def _key_count(db, operator_id: int, org_id: int, key: str) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE operator_id = ? AND scope = ? AND idempotency_key = ?",
        (operator_id, scope_invite_create(org_id), key),
    ).fetchone()["n"]


# ----------------------------------------------------------- first-use timing

def test_session_logged_out_while_waiting_is_401_and_issues_nothing(api: Api, db):
    aname, admin, org = _new_org(api)
    admin_id = _member_id(api, admin, org["id"], aname)
    invitee, _ = api.new_user()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], invitee),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert "token" not in r.json()

    # No invite row and no invite.created audit came out of the rejection.
    assert _invites_for(db, org["id"], invitee) == 0
    assert _created_audits(db, org["id"], admin_id) == 0

    # The dead session is still rejected on a direct retry and still writes
    # nothing.
    assert _issue(api, admin, org["id"], invitee).status_code == 401
    assert _invites_for(db, org["id"], invitee) == 0


def test_session_revoked_by_logout_others_while_waiting_is_401(api: Api, db):
    """Models the committed end state of POST /auth/logout-others.

    The waiting session is revoked while another session of the same account
    stays live; only the session actually carried by this request matters.
    """
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)  # the surviving session
    invitee, _ = api.new_user()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, s1, org["id"], invitee),
        mutate=lambda: _revoke(db, s1),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, org["id"], invitee) == 0

    # The dead session stays dead; the other one cannot stand in for it but
    # issues its own invite normally.
    assert _issue(api, s1, org["id"], invitee).status_code == 401
    r = _issue(api, s2, org["id"], invitee)
    assert r.status_code == 201, r.text
    assert r.json()["username"] == invitee


def test_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api)
    uid = _member_id(api, admin, org["id"], aname)
    invitee, _ = api.new_user()

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

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], invitee),
        mutate=_change_password,
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, org["id"], invitee) == 0

    # Old password is gone; after logging in with the new one the account is
    # still an admin and the same issuance succeeds.
    assert api.login(aname, "Passw0rd!").status_code == 401
    new_token = api.token_for(aname, "N3wPass!")
    r = _issue(api, new_token, org["id"], invitee)
    assert r.status_code == 201, r.text


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    _, admin, org = _new_org(api)
    invitee, _ = api.new_user()

    # Valid when the request arrives; the expiry instant ITSELF is invalid.
    db.commit()
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _token_hash(admin)))
    db.commit()
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], invitee),
        mutate=lambda: time.sleep(3),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, org["id"], invitee) == 0


def test_another_live_session_cannot_authorize_a_revoked_one(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    invitee, _ = api.new_user()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, s1, org["id"], invitee),
        mutate=lambda: _revoke(db, s1),
    )
    assert r.status_code == 401
    assert _invites_for(db, org["id"], invitee) == 0

    # The still-valid session issues the invite itself, exactly once.
    r = _issue(api, s2, org["id"], invitee)
    assert r.status_code == 201, r.text
    assert _invites_for(db, org["id"], invitee) == 1


def test_revoking_only_other_sessions_lets_issuance_proceed(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    invitee, _ = api.new_user()

    # Only the OTHER session is revoked while this request waits; this one is
    # untouched, and an admin invite (the other existing role) is issued.
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, s1, org["id"], invitee, role="admin"),
        mutate=lambda: _revoke(db, s2),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["role"] == "admin" and body["status"] == "available"
    # s1 is untouched and still usable.
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=s1).status_code == 200


# ------------------------------------------------------------- idempotency key

def test_unused_key_is_not_consumed_by_401_and_reusable_after_relogin(api: Api, db):
    aname, admin, org = _new_org(api)
    uid = _member_id(api, admin, org["id"], aname)
    invitee, _ = api.new_user()
    key = _key()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], invitee, key=key),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401

    # Neither an invite nor an idempotency record occupies the key.
    assert _invites_for(db, org["id"], invitee) == 0
    assert _key_count(db, uid, org["id"], key) == 0

    # Re-login and reuse the SAME key with the SAME request: it now succeeds.
    new_token = api.token_for(aname)
    r = _issue(api, new_token, org["id"], invitee, key=key)
    assert r.status_code == 201, r.text
    assert r.json()["username"] == invitee and len(r.json()["token"]) >= 40


def test_replay_of_stored_success_requires_a_live_session(api: Api, db):
    aname, admin, org = _new_org(api)
    admin_id = _member_id(api, admin, org["id"], aname)
    invitee, _ = api.new_user()
    key = _key()

    first = _issue(api, admin, org["id"], invitee, key=key)
    assert first.status_code == 201, first.text
    first_body = first.json()

    # A replay of the stored success whose carrying session dies while
    # waiting: 401, and the cached invite TOKEN is never returned.
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], invitee, key=key),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert first_body["token"] not in r.text

    # The stored record is untouched: after a fresh login the same key
    # replays the ORIGINAL success — same token, no second invite or audit.
    new_token = api.token_for(aname)
    r = _issue(api, new_token, org["id"], invitee, key=key)
    assert r.status_code == 201, r.text
    assert r.json() == first_body
    assert _invites_for(db, org["id"], invitee) == 1
    assert _created_audits(db, org["id"], admin_id) == 1


def test_401_takes_precedence_over_idempotency_conflict(api: Api, db):
    aname, admin, org = _new_org(api)
    key = _key()
    first_invitee, _ = api.new_user()
    first = _issue(api, admin, org["id"], first_invitee, key=key)
    assert first.status_code == 201, first.text

    # Same key, DIFFERENT body, session dies while waiting: the session check
    # wins; no idempotency_conflict, no token, stored record untouched.
    other_invitee, _ = api.new_user()
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, org["id"], other_invitee, key=key),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, org["id"], other_invitee) == 0

    # With a live session the different body is the ordinary 409, while the
    # original key+body still replays the original result.
    new_token = api.token_for(aname)
    r = _issue(api, new_token, org["id"], other_invitee, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    r = _issue(api, new_token, org["id"], first_invitee, key=key)
    assert r.status_code == 201 and r.json() == first.json()


# --------------------------------------------------------- 401 takes priority

def test_401_takes_precedence_over_org_permission_403(api: Api, db):
    _, admin, org = _new_org(api)
    mname, member_token, _ = _add_member(api, admin, org["id"])  # no delegation
    invitee, _ = api.new_user()

    # A live plain member gets 403; the same request with the session
    # revoked while waiting gets 401 first.
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, member_token, org["id"], invitee),
        mutate=lambda: _revoke(db, member_token),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # After a fresh login the member request is the ordinary 403.
    new_member_token = api.token_for(mname)
    assert _issue(api, new_member_token, org["id"], invitee).status_code == 403

    # Unknown organization: a live session gets the uniform 403, a dead one
    # gets 401 before the membership lookup.
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, admin, 99999999, invitee),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, 99999999, invitee) == 0


def test_401_takes_precedence_over_unavailable_delegation(api: Api, db):
    _, admin, org = _new_org(api)
    _, mtoken, mid = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], mid).json()
    invitee, _ = api.new_user()

    # While the delegate's request waits, BOTH happen: the delegation is
    # revoked (a live retry would then be 403) and the carried session is
    # revoked. The session rule wins: 401, no invite, no audit.
    def _mutate() -> None:
        db.execute("UPDATE delegations SET status = 'revoked', revoked_at = ?"
                   " WHERE id = ?", (int(time.time()), d["id"]))
        _revoke(db, mtoken)

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, mtoken, org["id"], invitee),
        mutate=_mutate,
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert _invites_for(db, org["id"], invitee) == 0

    # A fresh session no longer has a delegation: the same issuance is now 403.
    rows = api.request("GET", f"/orgs/{org['id']}/members",
                       token=admin).json()["members"]
    mname = next(m["username"] for m in rows if m["user_id"] == mid)
    new_token = api.token_for(mname)
    r = _issue(api, new_token, org["id"], invitee)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"


def test_422_validation_still_short_circuits_without_write_txn(api: Api, db):
    """Content validation / 422 behavior is unchanged by the session rule."""
    _, admin, org = _new_org(api)
    invitee, _ = api.new_user()

    # Pydantic-level 422 (unsupported role) is answered before the write
    # transaction and its session re-check; a live token is enough. Nothing
    # is written.
    r = _issue(api, admin, org["id"], invitee, role="superadmin")
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    assert _invites_for(db, org["id"], invitee) == 0

    # Missing username likewise stays 422 and never reaches the session rule.
    r = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                    json={"role": "member"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


# ----------------------------------------------------------------- delegates

def test_delegate_session_revoked_while_waiting_is_401_and_changes_nothing(api: Api, db):
    _, admin, org = _new_org(api)
    mname, mtoken, mid = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], mid).json()
    invitee, _ = api.new_user()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, mtoken, org["id"], invitee),
        mutate=lambda: _revoke(db, mtoken),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # No invite/audit, and the existing delegation is untouched and still
    # effective for a fresh session.
    assert _invites_for(db, org["id"], invitee) == 0
    assert _created_audits(db, org["id"], mid) == 0
    row = db.execute("SELECT status FROM delegations WHERE id = ?",
                     (d["id"],)).fetchone()
    assert row["status"] == "active"

    new_token = api.token_for(mname)
    r = _issue(api, new_token, org["id"], invitee)
    assert r.status_code == 201, r.text
    assert r.json()["delegation_id"] == d["id"]


def test_delegate_replay_needs_live_session_and_still_the_original_delegation(api: Api, db):
    _, admin, org = _new_org(api)
    mname, mtoken, mid = _add_member(api, admin, org["id"])
    d1 = _grant(api, admin, org["id"], mid).json()
    invitee, _ = api.new_user()
    key = _key()

    first = _issue(api, mtoken, org["id"], invitee, key=key)
    assert first.status_code == 201, first.text
    assert first.json()["delegation_id"] == d1["id"]

    # Original delegation revoked; a NEW delegation for the same delegate
    # cannot take over the key's authorization.
    assert api.request(
        "POST", f"/orgs/{org['id']}/delegations/{d1['id']}/revoke",
        token=admin,
    ).status_code == 200
    d2 = _grant(api, admin, org["id"], mid).json()
    assert d2["id"] != d1["id"]

    # Live retry with the same key: 403 — the retry is still bound to the
    # original delegation, which is gone.
    r = _issue(api, mtoken, org["id"], invitee, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Dead session while waiting: 401 wins over the delegation 403 and the
    # cached token is not returned.
    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, mtoken, org["id"], invitee, key=key),
        mutate=lambda: _revoke(db, mtoken),
    )
    assert r.status_code == 401, r.text
    assert first.json()["token"] not in r.text
    assert _invites_for(db, org["id"], invitee) == 1

    # After re-login the replay is still authorized by the ORIGINAL
    # delegation, so it remains 403 even though d2 is active.
    new_token = api.token_for(mname)
    r = _issue(api, new_token, org["id"], invitee, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"


# ------------------------------------------------------- header compatibility

def test_401_via_x_session_token_header_uses_error_envelope(api: Api, db):
    _, admin, org = _new_org(api)
    invitee, _ = api.new_user()

    r = _blocked_issue(
        api, db,
        send=lambda: _issue(api, None, org["id"], invitee,
                            headers={"X-Session-Token": admin}),
        mutate=lambda: _revoke(db, admin),
    )
    assert r.status_code == 401
    assert r.json() == {"error": {"code": "unauthorized",
                                  "message": "invalid or expired session"}}
    assert _invites_for(db, org["id"], invitee) == 0


# ------------------------------------------------- success precedes invalidation

def test_admin_invite_committed_first_then_logout_keeps_invite(api: Api):
    _, admin, org = _new_org(api)
    invitee_name, _ = api.new_user()

    r = _issue(api, admin, org["id"], invitee_name)
    assert r.status_code == 201, r.text
    invite = r.json()
    # The session dies only AFTER the issuance committed: the invite and its
    # audit stand and are not rolled back.
    assert api.request("POST", "/auth/logout", token=admin).status_code == 200

    # The invitee can still accept the invite under the existing rules.
    invitee_token = api.token_for(invitee_name)
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["org_id"] == org["id"]


def test_delegate_invite_committed_first_then_logout_keeps_invite(api: Api):
    _, admin, org = _new_org(api)
    mname, mtoken, mid = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], mid).json()
    invitee_name, _ = api.new_user()

    r = _issue(api, mtoken, org["id"], invitee_name)
    assert r.status_code == 201, r.text
    invite = r.json()
    assert invite["delegation_id"] == d["id"]
    # Session dies only after the issuance committed: the invite survives.
    assert api.request("POST", "/auth/logout", token=mtoken).status_code == 200

    invitee_token = api.token_for(invitee_name)
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["role"] == "member"
