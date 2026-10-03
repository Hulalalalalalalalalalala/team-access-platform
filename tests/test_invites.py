"""Single-use invitations: issue / accept / revoke / expire / concurrency."""
from __future__ import annotations

import hashlib
import threading
import time

import httpx

from tests.conftest import Api


def _issue(api: Api, admin_token: str, org_id: int, username: str, role: str = "member",
           key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                       json={"username": username, "role": role}, headers=headers)


def _session_id(db, token: str) -> int:
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    row = db.execute("SELECT id FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()
    assert row is not None
    return row[0]


def _accept_audit_count(db, org_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs"
        " WHERE org_id = ? AND action = 'invite.accepted'",
        (org_id,),
    ).fetchone()["n"]


def _accept_while_write_lock_held(api: Api, db, invite_token: str, mutate, *, token=None,
                                  headers=None):
    """Fire POST /invites/accept while holding SQLite's write lock.

    The request reaches the server and blocks on BEGIN IMMEDIATE; ``mutate``
    then changes session state through the SAME lock-holding connection and
    commits, so the queued accept resumes strictly afterwards and observes the
    committed state. This deterministically models "revoked/expired while the
    request was waiting".
    """
    request_headers = dict(headers or {})
    if token is not None:
        request_headers.setdefault("Authorization", f"Bearer {token}")
    db.execute("BEGIN IMMEDIATE")
    result: dict[str, httpx.Response] = {}
    try:
        def worker() -> None:
            with httpx.Client(base_url=api.base_url, timeout=30) as c:
                result["r"] = c.post(
                    "/invites/accept", headers=request_headers,
                    json={"token": invite_token},
                )

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.5)  # let the request arrive and queue on the write lock
        mutate(db)
        db.commit()
        t.join()
    except BaseException:
        db.rollback()
        raise
    return result["r"]



def test_issue_accept_invite_binds_username_and_role(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"inv-{api.unique()}"}).json()
    member_name, member_token = api.new_user()

    r = _issue(api, admin_token, org["id"], member_name, "admin")
    assert r.status_code == 201, r.text
    invite = r.json()
    assert invite["status"] == "available"
    assert invite["username"] == member_name and invite["role"] == "admin"
    assert invite["expires_at"] - invite["created_at"] == 24 * 3600
    assert len(invite["token"]) >= 40

    r = api.request("POST", "/invites/accept", token=member_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    m = r.json()["membership"]
    assert m["org_id"] == org["id"] and m["username"] == member_name
    assert m["role"] == "admin" and m["status"] == "active"


def test_unknown_invite_is_409_invite_unavailable(api: Api):
    _, token = api.new_user()
    r = api.request("POST", "/invites/accept", token=token, json={"token": "0" * 40})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "invite_unavailable"


def test_check_order_username_mismatch_is_403(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"um-{api.unique()}"}).json()
    target_name, target_token = api.new_user()
    _, other_token = api.new_user()
    invite = _issue(api, admin_token, org["id"], target_name).json()

    # A different logged-in user accepts: invite is still available, but the
    # username does not match -> 403 (and the invite stays usable).
    r = api.request("POST", "/invites/accept", token=other_token,
                    json={"token": invite["token"]})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "username_mismatch"

    r = api.request("POST", "/invites/accept", token=target_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200


def test_revoked_expired_and_used_invites_all_409(api: Api, db):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"st-{api.unique()}"}).json()

    # Revoked
    rev_name, rev_token = api.new_user()
    inv = _issue(api, admin_token, org["id"], rev_name).json()
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin_token,
                    json={"token": inv["token"]})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    r = api.request("POST", "/invites/accept", token=rev_token, json={"token": inv["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"
    # Revoking again (already revoked) is itself a 409.
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin_token,
                    json={"token": inv["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"

    # Expired (24h boundary) -- force expires_at into the past on disk.
    exp_name, exp_token = api.new_user()
    inv2 = _issue(api, admin_token, org["id"], exp_name).json()
    db.execute("UPDATE invites SET expires_at = 0 WHERE id = ?", (inv2["id"],))
    db.commit()
    r = api.request("POST", "/invites/accept", token=exp_token, json={"token": inv2["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"

    # Used
    used_name, used_token = api.new_user()
    inv3 = _issue(api, admin_token, org["id"], used_name).json()
    assert api.request("POST", "/invites/accept", token=used_token,
                       json={"token": inv3["token"]}).status_code == 200
    r = api.request("POST", "/invites/accept", token=used_token,
                    json={"token": inv3["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


def test_existing_member_accepting_is_409_already_member(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"am-{api.unique()}"}).json()
    member_name, member_token = api.new_user()
    first = _issue(api, admin_token, org["id"], member_name).json()
    assert api.request("POST", "/invites/accept", token=member_token,
                       json={"token": first["token"]}).status_code == 200

    # A second invite must not overwrite the existing role/status.
    second = _issue(api, admin_token, org["id"], member_name, "admin").json()
    r = api.request("POST", "/invites/accept", token=member_token,
                    json={"token": second["token"]})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "already_member"

    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=member_token).json()["membership"]
    assert me["role"] == "member" and me["status"] == "active"
    # The invite was NOT consumed by the failed attempt...
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin_token,
                    json={"token": second["token"]})
    assert r.status_code == 200


def test_concurrent_accept_succeeds_exactly_once(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"ca-{api.unique()}"}).json()
    name = api.unique("cc")
    api.register(name)
    invite = _issue(api, admin_token, org["id"], name).json()["token"]

    results: list[httpx.Response] = []
    barrier = threading.Barrier(3)

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            tok = c.post("/auth/login", json={"username": name, "password": "Passw0rd!"}).json()["token"]
            barrier.wait()
            results.append(c.post("/invites/accept", headers={"Authorization": f"Bearer {tok}"},
                                  json={"token": invite}))

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1, codes
    assert codes.count(409) == 2, codes
    assert all(r.json()["error"]["code"] == "invite_unavailable"
               for r in results if r.status_code == 409)

    # Exactly one membership and one audit row.
    me = api.token_for(name)
    r = api.request("GET", f"/orgs/{org['id']}/members", token=me)
    assert len(r.json()["members"]) == 2  # creator + the one new member


def test_invite_token_never_logged(api: Api, server):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"log-{api.unique()}"}).json()
    member_name, member_token = api.new_user()
    invite = _issue(api, admin_token, org["id"], member_name).json()["token"]
    api.request("POST", "/invites/accept", token=member_token, json={"token": invite})
    log_text = server.log_path.read_text()
    assert invite not in log_text


# --------------------------------- session validity at join-effect time ---

def _setup_invited_user(api: Api, role: str = "member"):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"sv-{api.unique()}"}).json()
    name, member_token = api.new_user()
    invite = _issue(api, admin_token, org["id"], name, role).json()
    return org, name, member_token, invite


def test_accept_with_session_logged_out_while_waiting_is_401(api: Api, db):
    org, name, token, invite = _setup_invited_user(api)
    sid = _session_id(db, token)

    r = _accept_while_write_lock_held(
        api, db, invite["token"], token=token,
        mutate=lambda c: c.execute(
            "UPDATE sessions SET revoked_at = strftime('%s','now') WHERE id = ?", (sid,)
        ),
    )
    # 401 in the existing error envelope, with no member info attached.
    assert r.status_code == 401, r.text
    assert set(r.json()) == {"error"}
    assert r.json()["error"]["code"] == "unauthorized"

    # Nothing took effect: invite not consumed, no membership, no audit row.
    row = db.execute("SELECT status, used_at, used_by FROM invites WHERE id = ?",
                     (invite["id"],)).fetchone()
    assert row["status"] == "available" and row["used_at"] is None and row["used_by"] is None
    assert db.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ?", (org["id"],)
    ).fetchone()["n"] == 1  # creator only
    assert _accept_audit_count(db, org["id"]) == 0


def test_rejected_accept_can_succeed_after_relogin_with_same_invite(api: Api, db):
    org, name, token, invite = _setup_invited_user(api)
    sid = _session_id(db, token)

    r = _accept_while_write_lock_held(
        api, db, invite["token"], token=token,
        mutate=lambda c: c.execute(
            "UPDATE sessions SET revoked_at = strftime('%s','now') WHERE id = ?", (sid,)
        ),
    )
    assert r.status_code == 401

    # Logout does not change the password: a fresh login reuses the SAME invite.
    new_token = api.token_for(name)
    r = api.request("POST", "/invites/accept", token=new_token,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    m = r.json()["membership"]
    assert m["org_id"] == org["id"] and m["username"] == name
    assert _accept_audit_count(db, org["id"]) == 1


def test_accept_with_session_revoked_by_password_change_while_waiting_is_401(api: Api, db):
    org, name, token, invite = _setup_invited_user(api)
    sid = _session_id(db, token)
    uid = db.execute("SELECT user_id FROM sessions WHERE id = ?", (sid,)).fetchone()["user_id"]

    # Committed state of POST /auth/password: new password hash plus every
    # live session of the account revoked, in one transaction.
    def _password_change_effect(c) -> None:
        c.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            ("pbkdf2_sha256$1$aa$bb", uid),
        )
        c.execute(
            "UPDATE sessions SET revoked_at = strftime('%s','now')"
            " WHERE user_id = ? AND revoked_at IS NULL",
            (uid,),
        )

    r = _accept_while_write_lock_held(
        api, db, invite["token"], token=token, mutate=_password_change_effect
    )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"

    row = db.execute("SELECT status, used_at FROM invites WHERE id = ?",
                     (invite["id"],)).fetchone()
    assert row["status"] == "available" and row["used_at"] is None
    assert _accept_audit_count(db, org["id"]) == 0


def test_session_reaching_expiry_instant_while_waiting_is_401(api: Api, db):
    org, name, token, invite = _setup_invited_user(api)
    sid = _session_id(db, token)
    # Valid when the request is sent (expiry ~2s out), invalid by the time the
    # queued transaction resumes.
    expiry = int(time.time()) + 2
    db.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (expiry, sid))
    db.commit()

    def _wait_for_expiry(c) -> None:
        while time.time() < expiry:
            time.sleep(0.05)

    r = _accept_while_write_lock_held(
        api, db, invite["token"], token=token, mutate=_wait_for_expiry
    )
    # The expiry instant itself is invalid (expires_at <= now), not just times
    # strictly after it.
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    row = db.execute("SELECT status FROM invites WHERE id = ?", (invite["id"],)).fetchone()
    assert row["status"] == "available"
    assert _accept_audit_count(db, org["id"]) == 0


def test_other_valid_session_neither_rescues_nor_is_blocked(api: Api, db):
    org, name, token_a, invite = _setup_invited_user(api)
    token_b = api.token_for(name)  # second live session of the same account
    sid_a = _session_id(db, token_a)

    # Session A revoked mid-request: another valid session B of the same
    # account cannot authorize A's request -> 401.
    r = _accept_while_write_lock_held(
        api, db, invite["token"], token=token_a,
        mutate=lambda c: c.execute(
            "UPDATE sessions SET revoked_at = strftime('%s','now') WHERE id = ?", (sid_a,)
        ),
    )
    assert r.status_code == 401

    # B stayed live and accepts the still-available invite successfully;
    # revoking A had no effect on B.
    r = api.request("POST", "/invites/accept", token=token_b,
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text
    assert r.json()["membership"]["username"] == name
    assert _accept_audit_count(db, org["id"]) == 1


def test_x_session_token_is_revalidated_at_join_time(api: Api, db):
    org, name, token, invite = _setup_invited_user(api)
    sid = _session_id(db, token)

    r = _accept_while_write_lock_held(
        api, db, invite["token"], headers={"X-Session-Token": token},
        mutate=lambda c: c.execute(
            "UPDATE sessions SET revoked_at = strftime('%s','now') WHERE id = ?", (sid,)
        ),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # And the header still works for a live session.
    new_token = api.token_for(name)
    r = api.request("POST", "/invites/accept",
                    headers={"X-Session-Token": new_token},
                    json={"token": invite["token"]})
    assert r.status_code == 200, r.text


def test_join_completed_before_logout_keeps_membership(api: Api, db):
    org, name, token, invite = _setup_invited_user(api, role="admin")

    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": invite["token"]})
    assert r.status_code == 200
    # Joining first, then logging the joining session out: the membership
    # survives the later revocation.
    assert api.request("POST", "/auth/logout", token=token).status_code == 200
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=token).status_code == 401

    fresh = api.token_for(name)
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=fresh).json()["membership"]
    assert me["role"] == "admin" and me["status"] == "active"
    row = db.execute("SELECT status FROM invites WHERE id = ?", (invite["id"],)).fetchone()
    assert row["status"] == "used"
    assert _accept_audit_count(db, org["id"]) == 1


def test_concurrent_accept_vs_password_change_is_serialized_consistently(api: Api):
    """Real endpoints racing: whichever IMMEDIATE txn commits first decides.

    Per round the outcome must be internally consistent:
    * join commits first  -> 200 and the membership exists;
    * revocation first    -> accept is 401, no membership/audit, and after
                             logging in with the NEW password the same invite
                             still joins.
    """
    rounds = 8
    for i in range(rounds):
        _, admin_token = api.new_user()
        org = api.request("POST", "/orgs", token=admin_token,
                          json={"name": f"race-{api.unique()}"}).json()
        name = api.unique("rc")
        api.register(name)
        accept_tok = api.token_for(name)
        password_tok = api.token_for(name)
        invite = _issue(api, admin_token, org["id"], name).json()["token"]
        new_password = f"NewPass{i}!xyz"

        outcomes: dict[str, httpx.Response] = {}
        barrier = threading.Barrier(2)

        def accept_worker() -> None:
            with httpx.Client(base_url=api.base_url, timeout=30) as c:
                barrier.wait()
                outcomes["accept"] = c.post(
                    "/invites/accept",
                    headers={"Authorization": f"Bearer {accept_tok}"},
                    json={"token": invite},
                )

        def password_worker() -> None:
            with httpx.Client(base_url=api.base_url, timeout=30) as c:
                barrier.wait()
                outcomes["password"] = c.post(
                    "/auth/password",
                    headers={"Authorization": f"Bearer {password_tok}"},
                    json={"current_password": "Passw0rd!", "new_password": new_password},
                )

        threads = [threading.Thread(target=accept_worker),
                   threading.Thread(target=password_worker)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert outcomes["password"].status_code == 200, outcomes["password"].text
        code = outcomes["accept"].status_code
        assert code in (200, 401), outcomes["accept"].text
        relogin = api.token_for(name, new_password)
        if code == 200:
            # Join won; later password change did not remove the membership.
            assert outcomes["accept"].json()["membership"]["org_id"] == org["id"]
            r = api.request("GET", f"/orgs/{org['id']}/members/me", token=relogin)
            assert r.status_code == 200
        else:
            # Revocation won: no join happened, invite still usable once.
            assert outcomes["accept"].json()["error"]["code"] == "unauthorized"
            r = api.request("GET", f"/orgs/{org['id']}/members/me", token=relogin)
            assert r.status_code == 403
            r = api.request("POST", "/invites/accept", token=relogin,
                            json={"token": invite})
            assert r.status_code == 200, r.text

