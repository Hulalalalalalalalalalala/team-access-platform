"""POST /auth/logout-others — keep this session, end every other session."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from tests.conftest import Api


def _logout_others(api: Api, token: str | None, current: object, **kw):
    headers = kw.pop("headers", {})
    return api.request(
        "POST", "/auth/logout-others", token=token,
        json={"current_password": current},
        headers=headers,
    )


def test_happy_path_revokes_only_other_sessions(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    t3 = api.token_for(u)

    r = _logout_others(api, t1, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 2}

    # The requesting session keeps working; the others are dead everywhere.
    assert api.request("GET", "/orgs", token=t1).status_code == 200
    for t in (t2, t3):
        r = api.request("GET", "/orgs", token=t)
        assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # The password is unchanged: the same password still logs in.
    assert api.login(u, "Passw0rd!").status_code == 200


def test_current_session_expiry_unchanged(api: Api, db):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    from app.security import hash_token
    before = db.execute(
        "SELECT expires_at FROM sessions WHERE token_hash = ?", (hash_token(t1),)
    ).fetchone()["expires_at"]
    assert _logout_others(api, t1, "Passw0rd!").status_code == 200
    after = db.execute(
        "SELECT expires_at, revoked_at FROM sessions WHERE token_hash = ?",
        (hash_token(t1),),
    ).fetchone()
    assert after["expires_at"] == before and after["revoked_at"] is None


def test_count_excludes_logged_out_and_expired_sessions(api: Api, db):
    u = api.unique()
    api.register(u)
    t_keep = api.token_for(u)
    t_live = api.token_for(u)
    t_out = api.token_for(u)
    t_expired = api.token_for(u)
    # One already logged out, one already expired: neither counts.
    assert api.request("POST", "/auth/logout", token=t_out).status_code == 200
    from app.security import hash_token
    db.execute(
        "UPDATE sessions SET expires_at = 0 WHERE token_hash = ?",
        (hash_token(t_expired),),
    )
    db.commit()

    r = _logout_others(api, t_keep, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}
    assert api.request("GET", "/orgs", token=t_live).status_code == 401
    assert api.request("GET", "/orgs", token=t_keep).status_code == 200


def test_repeat_with_no_other_sessions_is_zero(api: Api):
    u, token = api.new_user()
    r = _logout_others(api, token, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 0}
    # The surviving session is still valid afterwards.
    assert api.request("GET", "/orgs", token=token).status_code == 200


def test_other_accounts_unaffected(api: Api):
    victim = api.unique("victim")
    bystander = api.unique("other")
    api.register(victim)
    api.register(bystander)
    t_victim = api.token_for(victim)
    t_other = api.token_for(bystander)

    r = _logout_others(api, t_victim, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 0}
    assert api.request("GET", "/orgs", token=t_other).status_code == 200
    assert api.login(bystander, "Passw0rd!").status_code == 200


def test_validation_errors(api: Api):
    u, token = api.new_user()
    other = api.token_for(u)
    bad_bodies = [
        {},                                  # missing
        {"current_password": ""},            # empty
        {"current_password": None},          # null
        {"current_password": 123},           # non-string
        {"current_password": True},
        {"current_password": ["Passw0rd!"]},
        {"current_password": "x" * 257},     # too long
    ]
    for body in bad_bodies:
        r = api.request("POST", "/auth/logout-others", token=token, json=body)
        assert r.status_code == 422, body
        assert r.json()["error"]["code"] == "validation_error"
    # Nothing was revoked; both sessions still work.
    assert api.request("GET", "/orgs", token=token).status_code == 200
    assert api.request("GET", "/orgs", token=other).status_code == 200


def test_password_spaces_and_case_significant(api: Api):
    u = api.unique()
    api.register(u, "  Mixed CASE pass  ")
    t1 = api.token_for(u, "  Mixed CASE pass  ")
    t2 = api.token_for(u, "  Mixed CASE pass  ")
    # Trimmed or case-folded variants are wrong passwords -> 403, no revoke.
    r = _logout_others(api, t1, "Mixed CASE pass")
    assert r.status_code == 403
    r = _logout_others(api, t1, "  mixed case pass  ")
    assert r.status_code == 403
    assert api.request("GET", "/orgs", token=t2).status_code == 200
    # The exact password works.
    r = _logout_others(api, t1, "  Mixed CASE pass  ")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}
    assert api.request("GET", "/orgs", token=t2).status_code == 401


def test_no_or_invalid_session_is_401(api: Api):
    u = api.unique()
    api.register(u)
    # No token at all.
    r = _logout_others(api, None, "Passw0rd!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # Unknown token.
    r = _logout_others(api, "a" * 64, "Passw0rd!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # X-Session-Token header is accepted like the Bearer scheme.
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    r = api.request(
        "POST", "/auth/logout-others",
        json={"current_password": "Passw0rd!"},
        headers={"X-Session-Token": t1},
    )
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}
    assert api.request("GET", "/orgs", token=t2).status_code == 401
    # A logged-out session cannot use the endpoint.
    t3 = api.token_for(u)
    assert api.request("POST", "/auth/logout", token=t3).status_code == 200
    r = _logout_others(api, t3, "Passw0rd!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"


def test_expired_session_is_401(api: Api, db):
    u = api.unique()
    api.register(u)
    token = api.token_for(u)
    other = api.token_for(u)
    from app.security import hash_token, now_ts
    # Expiry exactly at "now" already counts as invalid.
    db.execute(
        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
        (now_ts(), hash_token(token)),
    )
    db.commit()
    r = _logout_others(api, token, "Passw0rd!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # Nothing was revoked.
    assert api.request("GET", "/orgs", token=other).status_code == 200


def test_wrong_current_password_is_403_and_revokes_nothing(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    r = _logout_others(api, t1, "not-the-password")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "invalid_current_password"
    # Both sessions survive; the password is untouched.
    assert api.request("GET", "/orgs", token=t1).status_code == 200
    assert api.request("GET", "/orgs", token=t2).status_code == 200
    assert api.login(u, "Passw0rd!").status_code == 200


def test_disabled_or_removed_member_can_logout_others(api: Api):
    admin_u, admin_t = api.new_user()
    member_u, member_t = api.new_user()
    member_t2 = api.token_for(member_u)
    r = api.request("POST", "/orgs", token=admin_t, json={"name": api.unique("org")})
    org_id = r.json()["id"]
    r = api.request("POST", f"/orgs/{org_id}/invites", token=admin_t,
                    json={"username": member_u, "role": "member"})
    invite_token = r.json()["token"]
    assert api.request("POST", "/invites/accept", token=member_t,
                       json={"token": invite_token}).status_code == 200
    # Look the id up via the admin's roster so no extra member session is
    # created (a member login would itself be a live session to count).
    r = api.request("GET", f"/orgs/{org_id}/members", token=admin_t)
    member_id = [m for m in r.json()["members"] if m["username"] == member_u][0]["user_id"]

    # Disabled member: the endpoint still works on a valid account session.
    r = api.request("PATCH", f"/orgs/{org_id}/members/batch", token=admin_t,
                    json={"changes": [{"user_id": member_id, "status": "disabled"}]})
    assert r.status_code == 200
    r = _logout_others(api, member_t, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}
    assert api.request("GET", "/orgs", token=member_t2).status_code == 401
    assert api.request("GET", "/orgs", token=member_t).status_code == 200
    # Membership state itself is untouched (still disabled).
    r = api.request("GET", f"/orgs/{org_id}/members", token=admin_t)
    member = [m for m in r.json()["members"] if m["username"] == member_u][0]
    assert member["status"] == "disabled" and member["role"] == "member"

    # Removed member: same behaviour with a fresh second session.
    member_t3 = api.token_for(member_u)
    r = api.request("DELETE", f"/orgs/{org_id}/members/{member_id}", token=admin_t)
    assert r.status_code == 200
    r = _logout_others(api, member_t, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}
    assert api.request("GET", "/orgs", token=member_t3).status_code == 401
    assert api.request("GET", "/orgs", token=member_t).status_code == 200


def test_user_without_org_can_logout_others(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    r = _logout_others(api, t1, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}


def test_concurrent_logout_others_exactly_one_wins(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_logout_others, api, t1, "Passw0rd!")
        f2 = pool.submit(_logout_others, api, t2, "Passw0rd!")
        results = sorted([f1.result().status_code, f2.result().status_code])
    # One revoked the other's session; the loser fails closed with 401.
    assert results == [200, 401]

    # Exactly one session survives; using it again finds nothing to revoke.
    survivors = [t for t in (t1, t2)
                 if api.request("GET", "/orgs", token=t).status_code == 200]
    assert len(survivors) == 1
    r = _logout_others(api, survivors[0], "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 0}


def test_session_revoked_by_password_change_cannot_logout_others(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    # Password change revokes every session; a dead session must not be able
    # to go on revoking anything.
    r = api.request("POST", "/auth/password", token=t1,
                    json={"current_password": "Passw0rd!", "new_password": "N3wPass!"})
    assert r.status_code == 200
    r = api.request("POST", "/auth/logout-others", token=t2,
                    json={"current_password": "N3wPass!"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"


def test_revocation_survives_restart(make_server):
    srv = make_server("logoutothers")
    api = Api(srv.base_url)
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    r = _logout_others(api, t1, "Passw0rd!")
    assert r.status_code == 200 and r.json() == {"revoked_sessions": 1}

    srv.restart()
    api = Api(srv.base_url)
    # The revocation persisted; the kept session is still valid, and the
    # same password establishes a fresh session.
    assert api.request("GET", "/orgs", token=t2).status_code == 401
    assert api.request("GET", "/orgs", token=t1).status_code == 200
    r = api.login(u, "Passw0rd!")
    assert r.status_code == 200 and r.json()["token"]


def test_secrets_not_leaked(api: Api, server, db):
    u = api.unique("loleak")
    pw = "S3cret!value"
    api.register(u, pw)
    t1 = api.token_for(u, pw)
    t2 = api.token_for(u, pw)
    r = _logout_others(api, t1, pw)
    assert r.status_code == 200
    assert pw not in r.text and t1 not in r.text and t2 not in r.text
    assert "pbkdf2_sha256$" not in r.text
    # Wrong-password failure does not echo the attempted password either.
    r = _logout_others(api, t1, "wr0ng-attempt-value")
    assert r.status_code == 403 and "wr0ng-attempt-value" not in r.text
    # Neither password nor token nor hash appears in the server log.
    log_text = server.log_path.read_text()
    assert pw not in log_text and t1 not in log_text and t2 not in log_text
    assert "pbkdf2_sha256$" not in log_text
