"""Session validity at EXECUTION TIME for POST /orgs/{org_id}/invites/revoke.

Regression for invite REVOCATION (issuance is covered by
test_invite_issue_session.py, acceptance by test_invite_session.py): a
session that is valid when the revoke request arrives may be logged out,
revoked via "logout other sessions" / a password change, or reach its expiry
instant while the request is waiting to enter its serialized write
transaction. The revocation — flipping the invite and writing
``invite.revoked`` — must be authorized by the session state at the moment it
actually runs. The re-check happens inside the IMMEDIATE transaction, before
the membership/role check, the delegation sweep, the delegate's
active-delegation lookup, the invite availability check and every write.

Consequences pinned here:

* the 401 precedes 403 (org permission / delegate eligibility) and 409
  (invite unavailable), and carries no invite information;
* the invite keeps status/``revoked_at``, no ``invite.revoked`` audit is
  written, no delegation changes state and no ``delegation.invalidated``
  audit is produced;
* the still-usable invite remains acceptable, and after a fresh login the
  operator (still permitted) can revoke again;
* another live session of the same account never substitutes for the dead
  one, while revoking only OTHER sessions leaves this request successful;
* Bearer and X-Session-Token behave identically; administrators and
  delegates follow the same rule;
* a revocation that commits BEFORE its session later dies stands.

Determinism: same lock harness as test_invite_issue_session.py — the test
holds SQLite's single write lock with ``BEGIN IMMEDIATE`` and only then
starts the request, so whatever the test commits before releasing the lock
is guaranteed visible to the in-transaction session re-check (no sleeps or
thread-scheduling races beyond the settle delay).
"""
from __future__ import annotations

import hashlib
import threading
import time

from app.security import hash_password
from tests.conftest import Api


# --------------------------------------------------------------- test helpers

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _new_org(api: Api, prefix: str = "rs"):
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


def _grant(api: Api, admin_token: str, org_id: int, user_id: int,
           duration: int = 3600):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": user_id, "duration_seconds": duration})


def _issue(api: Api, token: str, org_id: int, username: str, role: str = "member"):
    return api.request("POST", f"/orgs/{org_id}/invites", token=token,
                       json={"username": username, "role": role})


def _revoke_invite(api: Api, token: str | None, org_id: int, invite_token: str,
                   *, headers: dict | None = None):
    h = dict(headers or {})
    if token is not None and "X-Session-Token" not in h:
        h["Authorization"] = f"Bearer {token}"
    return api.request("POST", f"/orgs/{org_id}/invites/revoke", headers=h,
                       json={"token": invite_token})


def _revoke_session(db, token: str, ts: int | None = None) -> None:
    db.execute("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
               (ts if ts is not None else int(time.time()), _token_hash(token)))


def _blocked(api: Api, db, send, mutate):
    """Run a request while the database write lock is held.

    The request passes its arrival-time session check and blocks on the write
    lock; ``mutate()`` runs under the lock and commits together with the
    release, so the endpoint's in-transaction re-check observes the mutated
    state exactly as if it had landed while the request was waiting.
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
    assert not t.is_alive(), "revoke request hung"
    return out["r"]


def _assert_is_401_envelope(r) -> None:
    assert r.status_code == 401, r.text
    assert set(r.json()) == {"error"}
    assert r.json()["error"] == {"code": "unauthorized",
                                 "message": "invalid or expired session"}


def _invite_still_available(db, invite: dict) -> None:
    row = db.execute("SELECT status, revoked_at FROM invites WHERE id = ?",
                     (invite["id"],)).fetchone()
    assert row["status"] == "available"
    assert row["revoked_at"] is None


def _revoked_audits(db, org_id: int, invite_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'invite.revoked' AND target_id = ?",
        (org_id, str(invite_id)),
    ).fetchone()["n"]


def _invalidation_audits(db, org_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'delegation.invalidated'",
        (org_id,),
    ).fetchone()["n"]


def _user_id(db, token: str) -> int:
    return db.execute(
        "SELECT user_id FROM sessions WHERE token_hash = ?",
        (_token_hash(token),),
    ).fetchone()["user_id"]


# ============================================================== administrator

def test_admin_session_logged_out_while_waiting_is_401_and_revokes_nothing(api: Api, db):
    _, admin, org = _new_org(api)
    invitee_name, invitee_token = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, admin),
    )
    _assert_is_401_envelope(r)
    assert invite["token"] not in r.text and str(invite["id"]) not in r.text

    # The invite is untouched...
    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0

    # ...the dead session keeps failing directly...
    assert _revoke_invite(api, admin, org["id"], invite["token"]).status_code == 401
    _invite_still_available(db, invite)

    # ...the invitee can still accept under the original rules...
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["org_id"] == org["id"]


def test_admin_revokes_again_after_relogin(api: Api, db):
    aname, admin, org = _new_org(api)
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, admin),
    )
    assert r.status_code == 401

    # A fresh login that is still an enabled admin revokes successfully;
    # the response keeps the original shape: invite id + revoked status.
    new_admin = api.token_for(aname)
    r = _revoke_invite(api, new_admin, org["id"], invite["token"])
    assert r.status_code == 200, r.text
    assert r.json() == {"id": invite["id"], "status": "revoked"}
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1
    # A second revoke now follows the ordinary 409 rule.
    r = _revoke_invite(api, new_admin, org["id"], invite["token"])
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


def test_admin_session_revoked_by_logout_others_while_waiting_is_401(api: Api, db):
    """Models the committed end state of POST /auth/logout-others.

    The waiting session is revoked while another session of the same account
    stays live; only the session actually carried by this request matters.
    """
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)  # surviving session
    invitee_name, _ = api.new_user()
    invite = _issue(api, s1, org["id"], invitee_name).json()

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, s1, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, s1),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)

    # The dead session stays dead even though session 2 is valid; session 2
    # cannot stand in for it but performs its own revocation exactly once.
    assert _revoke_invite(api, s1, org["id"], invite["token"]).status_code == 401
    r = _revoke_invite(api, s2, org["id"], invite["token"])
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1


def test_admin_all_sessions_revoked_by_password_change_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api)
    uid = _user_id(db, admin)
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    def _change_password() -> None:
        # Exact committed end state of POST /auth/password: a new hash plus
        # revoked_at on every live session of the account, together.
        ts = int(time.time())
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (hash_password("N3wPass!"), uid))
        db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=_change_password,
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0

    # Old password is dead; after logging in with the new one the still-admin
    # account can revoke.
    assert api.login(aname, "Passw0rd!").status_code == 401
    new_token = api.token_for(aname, "N3wPass!")
    r = _revoke_invite(api, new_token, org["id"], invite["token"])
    assert r.status_code == 200, r.text


def test_admin_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    _, admin, org = _new_org(api)
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    # Valid when the request arrives; the expiry instant ITSELF is invalid.
    db.commit()
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _token_hash(admin)))
    db.commit()
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=lambda: time.sleep(3),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0


def test_admin_another_live_session_cannot_authorize_a_revoked_one(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    invitee_name, _ = api.new_user()
    invite = _issue(api, s1, org["id"], invitee_name).json()

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, s1, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, s1),
    )
    assert r.status_code == 401

    # The still-valid session 2 revokes the invite itself, exactly once.
    r = _revoke_invite(api, s2, org["id"], invite["token"])
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1
    # The dead session is still 401 even though the invite is now gone too.
    assert _revoke_invite(api, s1, org["id"], invite["token"]).status_code == 401


def test_admin_revoking_only_other_sessions_lets_revocation_proceed(api: Api, db):
    aname, s1, org = _new_org(api)
    s2 = api.token_for(aname)
    invitee_name, _ = api.new_user()
    invite = _issue(api, s1, org["id"], invitee_name).json()

    # Only the OTHER session is revoked while this request waits; this one is
    # untouched, so permission is evaluated normally and the revoke succeeds.
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, s1, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, s2),
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"id": invite["id"], "status": "revoked"}
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1
    # s1 itself is untouched and still usable.
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=s1).status_code == 200


def test_admin_401_via_x_session_token_header(api: Api, db):
    _, admin, org = _new_org(api)
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, None, org["id"], invite["token"],
                                    headers={"X-Session-Token": admin}),
        mutate=lambda: _revoke_session(db, admin),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)


def test_admin_401_takes_precedence_over_org_permission_403(api: Api, db):
    _, admin, org = _new_org(api)
    _, outsider = api.new_user()
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    # A live outsider gets 403; the same request with its session revoked
    # while waiting gets 401 first.
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, outsider, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, outsider),
    )
    _assert_is_401_envelope(r)

    # A fresh login of the same outsider makes the live 403 ordering clear.
    outsider_name = db.execute(
        "SELECT username FROM users u JOIN sessions s ON s.user_id = u.id"
        " WHERE s.token_hash = ?", (_token_hash(outsider),)
    ).fetchone()["username"]
    live = api.token_for(outsider_name)
    assert _revoke_invite(api, live, org["id"], invite["token"]).status_code == 403

    # Unknown organization: a live session gets the uniform 403, a dead one
    # gets 401 before the membership lookup, and nothing is written.
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, 99999999, invite["token"]),
        mutate=lambda: _revoke_session(db, admin),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)


def test_admin_401_takes_precedence_over_invite_unavailable_409(api: Api, db):
    _, admin, org = _new_org(api)
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()
    # Revoke it up front so a live retry would be 409.
    assert _revoke_invite(api, admin, org["id"], invite["token"]).status_code == 200

    # Session dies while waiting: 401 wins over the 409, and no second
    # invite.revoked audit is produced by the rejected request.
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, admin),
    )
    _assert_is_401_envelope(r)
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1

    # An unknown token follows the same ordering: dead session -> 401, not 409.
    name2, tok2 = api.new_user()
    org2 = api.request("POST", "/orgs", token=tok2,
                       json={"name": f"rsx-{api.unique()}"}).json()
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, tok2, org2["id"], "0" * 40),
        mutate=lambda: _revoke_session(db, tok2),
    )
    _assert_is_401_envelope(r)


def test_admin_revocation_committed_first_then_logout_keeps_result(api: Api, db):
    _, admin, org = _new_org(api)
    invitee_name, invitee_token = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    r = _revoke_invite(api, admin, org["id"], invite["token"])
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # The session dies only AFTER the revocation committed: the result and
    # its audit stand and are not rolled back.
    assert api.request("POST", "/auth/logout", token=admin).status_code == 200
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1

    # The invite is permanently unavailable to its invitee.
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


def test_revoke_422_validation_still_short_circuits(api: Api, db):
    """Content validation / 422 behavior is unchanged by the session rule."""
    _, admin, org = _new_org(api)

    # Missing/short token stays 422 and never reaches the session rule.
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin,
                    json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin,
                    json={"token": "short"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


# ================================================================== delegates

def _delegate_with_invite(api: Api):
    """Admin + org, a delegate with an active delegation and their own invite."""
    _, admin, org = _new_org(api)
    dname, dtoken, did = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], did).json()
    invitee_name, invitee_token = api.new_user()
    invite = _issue(api, dtoken, org["id"], invitee_name).json()
    assert invite["delegation_id"] == d["id"]
    return admin, org, dname, dtoken, did, d, invitee_name, invitee_token, invite


def test_delegate_session_logged_out_while_waiting_is_401_and_changes_nothing(api: Api, db):
    admin, org, dname, dtoken, did, d, _, invitee_token, invite = _delegate_with_invite(api)

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, dtoken, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, dtoken),
    )
    _assert_is_401_envelope(r)

    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0
    # The delegation itself is untouched and keeps authorizing a fresh login.
    row = db.execute("SELECT status, invalid_reason, revoked_at FROM delegations WHERE id = ?",
                     (d["id"],)).fetchone()
    assert row["status"] == "active" and row["invalid_reason"] is None
    assert row["revoked_at"] is None
    assert _invalidation_audits(db, org["id"]) == 0

    # The dead session stays dead; after re-login the SAME delegation still
    # lets the delegate revoke the invite.
    assert _revoke_invite(api, dtoken, org["id"], invite["token"]).status_code == 401
    new_token = api.token_for(dname)
    r = _revoke_invite(api, new_token, org["id"], invite["token"])
    assert r.status_code == 200 and r.json() == {"id": invite["id"], "status": "revoked"}


def test_delegate_session_password_change_while_waiting_is_401(api: Api, db):
    _, org, dname, dtoken, _, _, _, _, invite = _delegate_with_invite(api)
    uid = _user_id(db, dtoken)

    def _change_password() -> None:
        ts = int(time.time())
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (hash_password("N3wPass!"), uid))
        db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, dtoken, org["id"], invite["token"]),
        mutate=_change_password,
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0

    new_token = api.token_for(dname, "N3wPass!")
    r = _revoke_invite(api, new_token, org["id"], invite["token"])
    assert r.status_code == 200, r.text


def test_delegate_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    _, org, _, dtoken, _, _, _, _, invite = _delegate_with_invite(api)
    db.commit()
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _token_hash(dtoken)))
    db.commit()
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, dtoken, org["id"], invite["token"]),
        mutate=lambda: time.sleep(3),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)


def test_delegate_401_takes_precedence_over_delegate_eligibility_403(api: Api, db):
    admin, org, dname, dtoken, did, d, _, _, own_invite = _delegate_with_invite(api)

    # A second member with their own delegation: the first delegate may not
    # revoke the second's invite (403 while live).
    _, other_token, other_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], other_id)
    other_invitee, _ = api.new_user()
    other_invite = _issue(api, other_token, org["id"], other_invitee).json()

    # Session dies while waiting: 401 wins over the out-of-scope 403.
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, dtoken, org["id"], other_invite["token"]),
        mutate=lambda: _revoke_session(db, dtoken),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, other_invite)
    assert _revoked_audits(db, org["id"], other_invite["id"]) == 0

    # A fresh login no longer changes scope: out-of-other-delegation is 403.
    live = api.token_for(dname)
    assert _revoke_invite(api, live, org["id"], other_invite["token"]).status_code == 403

    # Same precedence when the delegate has NO active delegation at all: the
    # delegation is revoked and the session dies while waiting.
    assert api.request(
        "POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke", token=admin
    ).status_code == 200
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, live, org["id"], own_invite["token"]),
        mutate=lambda: _revoke_session(db, live),
    )
    _assert_is_401_envelope(r)


def test_delegate_401_takes_precedence_over_unavailable_invite_409(api: Api, db):
    _, org, _, dtoken, _, _, invitee_name, invitee_token, invite = _delegate_with_invite(api)
    # Consume the delegate's invite first; a live revoke would then be 409.
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, dtoken, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, dtoken),
    )
    _assert_is_401_envelope(r)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0


def test_delegate_revoking_only_other_sessions_succeeds(api: Api, db):
    _, org, _, s1, _, _, _, _, invite = _delegate_with_invite(api)
    # A second live session of the SAME delegate account.
    row = db.execute(
        "SELECT username FROM users u JOIN sessions s ON s.user_id = u.id"
        " WHERE s.token_hash = ?", (_token_hash(s1),)
    ).fetchone()
    s2 = api.token_for(row["username"])

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, s1, org["id"], invite["token"]),
        mutate=lambda: _revoke_session(db, s2),
    )
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1
    # The carrying session is untouched.
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=s1).status_code == 200


def test_delegate_401_via_x_session_token_header(api: Api, db):
    _, org, _, dtoken, _, _, _, _, invite = _delegate_with_invite(api)
    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, None, org["id"], invite["token"],
                                    headers={"X-Session-Token": dtoken}),
        mutate=lambda: _revoke_session(db, dtoken),
    )
    _assert_is_401_envelope(r)
    db.commit()
    _invite_still_available(db, invite)


def test_401_runs_before_delegation_sweep_no_delegation_state_changes(api: Api, db):
    """The rejected request must not sweep/invalidate any delegation.

    Setup: an admin is about to revoke an invite while the org has an active
    delegation whose delegate becomes ineligible (disabled) at the same
    committed instant the admin's session is revoked. With a LIVE session the
    endpoint's lazy sweep would invalidate that delegation; because the
    session check runs first and fails, neither the delegation status, its
    timestamps nor any invalidation audit may change.
    """
    aname, admin, org = _new_org(api)
    _, dtoken, did = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], did).json()
    invitee_name, _ = api.new_user()
    invite = _issue(api, admin, org["id"], invitee_name).json()

    def _mutate() -> None:
        ts = int(time.time())
        _revoke_session(db, admin, ts)
        db.execute(
            "UPDATE memberships SET status = 'disabled', updated_at = ?"
            " WHERE org_id = ? AND user_id = ?",
            (ts, org["id"], did),
        )

    r = _blocked(
        api, db,
        send=lambda: _revoke_invite(api, admin, org["id"], invite["token"]),
        mutate=_mutate,
    )
    _assert_is_401_envelope(r)

    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0
    row = db.execute(
        "SELECT status, invalid_reason, invalidated_at, revoked_at"
        " FROM delegations WHERE id = ?", (d["id"],)
    ).fetchone()
    assert row["status"] == "active"
    assert row["invalid_reason"] is None and row["invalidated_at"] is None
    assert row["revoked_at"] is None
    assert _invalidation_audits(db, org["id"]) == 0

    # Re-login: the admin can still revoke (the delegate being disabled is
    # evaluated on that fresh, live request as usual — unrelated to the 401).
    new_admin = api.token_for(aname)
    r = _revoke_invite(api, new_admin, org["id"], invite["token"])
    assert r.status_code == 200, r.text


def test_new_delegation_cannot_revoke_old_delegations_invite(api: Api, db):
    """Existing rule, retained: revoke authority is bound to the CURRENT
    delegation that issued the invite; a replacement grant gets no power over
    invites issued under the old one."""
    admin, org, dname, dtoken, did, d1, _, _, invite = _delegate_with_invite(api)

    # Replace the delegate's grant: revoke d1, grant d2.
    assert api.request(
        "POST", f"/orgs/{org['id']}/delegations/{d1['id']}/revoke", token=admin
    ).status_code == 200
    d2 = _grant(api, admin, org["id"], did).json()
    assert d2["id"] != d1["id"]

    # The invite issued under d1 cannot be revoked under d2.
    r = _revoke_invite(api, dtoken, org["id"], invite["token"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    db.commit()
    _invite_still_available(db, invite)
    assert _revoked_audits(db, org["id"], invite["id"]) == 0

    # The admin still can.
    r = _revoke_invite(api, admin, org["id"], invite["token"])
    assert r.status_code == 200 and r.json()["status"] == "revoked"


def test_delegate_revocation_committed_first_then_logout_keeps_result(api: Api, db):
    _, org, _, dtoken, _, _, invitee_name, invitee_token, invite = _delegate_with_invite(api)
    r = _revoke_invite(api, dtoken, org["id"], invite["token"])
    assert r.status_code == 200, r.text
    assert api.request("POST", "/auth/logout", token=dtoken).status_code == 200
    db.commit()
    assert _revoked_audits(db, org["id"], invite["id"]) == 1
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": invite["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"
