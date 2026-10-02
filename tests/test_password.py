"""POST /auth/password — change own password, revoke all sessions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from tests.conftest import Api


def _change(api: Api, token: str | None, current: object, new: object, **kw):
    headers = kw.pop("headers", {})
    return api.request(
        "POST", "/auth/password", token=token,
        json={"current_password": current, "new_password": new},
        headers=headers,
    )


def test_change_password_happy_path(api: Api):
    u = api.unique()
    api.register(u, "OldPass 1")
    token = api.token_for(u, "OldPass 1")

    r = _change(api, token, "OldPass 1", "NewPass 2")
    assert r.status_code == 200 and r.json() == {"password_changed": True}
    assert "password" not in r.text.replace("password_changed", "")

    # The requesting session is revoked too; no replacement token is issued.
    assert "token" not in r.json()
    r = api.request("GET", "/orgs", token=token)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Old password no longer logs in; the new one does.
    r = api.login(u, "OldPass 1")
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_credentials"
    r = api.login(u, "NewPass 2")
    assert r.status_code == 200 and r.json()["token"]
    # A session established with the new password is not revoked.
    assert api.request("GET", "/orgs", token=r.json()["token"]).status_code == 200


def test_all_sessions_on_all_devices_are_revoked(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    t3 = api.token_for(u)

    r = _change(api, t1, "Passw0rd!", "Br4ndNew!")
    assert r.status_code == 200
    for t in (t1, t2, t3):
        r = api.request("GET", "/orgs", token=t)
        assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"


def test_other_accounts_unaffected(api: Api):
    victim = api.unique("victim")
    bystander = api.unique("other")
    api.register(victim)
    api.register(bystander)
    t_victim = api.token_for(victim)
    t_other = api.token_for(bystander)

    assert _change(api, t_victim, "Passw0rd!", "N3wPass!").status_code == 200
    # The bystander's session and password still work.
    assert api.request("GET", "/orgs", token=t_other).status_code == 200
    assert api.login(bystander, "Passw0rd!").status_code == 200


def test_validation_errors(api: Api):
    u, token = api.new_user()
    bad_bodies = [
        {},                                            # both missing
        {"current_password": "Passw0rd!"},             # new missing
        {"new_password": "Xy1!"},                      # current missing
        {"current_password": "", "new_password": "Xy1!"},     # empty
        {"current_password": "Passw0rd!", "new_password": ""},
        {"current_password": None, "new_password": "Xy1!"},   # null
        {"current_password": 123, "new_password": "Xy1!"},    # non-string
        {"current_password": "Passw0rd!", "new_password": True},
        {"current_password": "Passw0rd!", "new_password": "x" * 257},  # too long
        {"current_password": "x" * 257, "new_password": "Xy1!"},
    ]
    for body in bad_bodies:
        r = api.request("POST", "/auth/password", token=token, json=body)
        assert r.status_code == 422, body
        assert r.json()["error"]["code"] == "validation_error"
    # Password untouched, session still valid.
    assert api.login(u, "Passw0rd!").status_code == 200
    assert api.request("GET", "/orgs", token=token).status_code == 200


def test_password_spaces_and_case_preserved(api: Api):
    u = api.unique()
    api.register(u, "  Mixed CASE pass  ")
    token = api.token_for(u, "  Mixed CASE pass  ")
    r = _change(api, token, "  Mixed CASE pass  ", "  New CASE pass  ")
    assert r.status_code == 200
    # Trailing/leading whitespace and case are significant on login.
    assert api.login(u, "New CASE pass").status_code == 401
    assert api.login(u, "  new case pass  ").status_code == 401
    assert api.login(u, "  New CASE pass  ").status_code == 200


def test_no_or_invalid_session_is_401(api: Api):
    u = api.unique()
    api.register(u)
    # No token at all.
    r = _change(api, None, "Passw0rd!", "N3wPass!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # Unknown token.
    r = _change(api, "a" * 64, "Passw0rd!", "N3wPass!")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    # X-Session-Token header is accepted like the Bearer scheme.
    token = api.token_for(u)
    r = api.request(
        "POST", "/auth/password",
        json={"current_password": "Passw0rd!", "new_password": "N3wPass!"},
        headers={"X-Session-Token": token},
    )
    assert r.status_code == 200
    # Logged-out session can no longer change the password.
    token2 = api.token_for(u, "N3wPass!")
    assert api.request("POST", "/auth/logout", token=token2).status_code == 200
    r = _change(api, token2, "N3wPass!", "An0ther!")
    assert r.status_code == 401


def test_wrong_current_password_is_403_and_changes_nothing(api: Api):
    u, token = api.new_user()
    r = _change(api, token, "not-the-password", "N3wPass!")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "invalid_current_password"
    # Password and session are both untouched.
    assert api.login(u, "Passw0rd!").status_code == 200
    assert api.request("GET", "/orgs", token=token).status_code == 200


def test_same_password_is_409_and_changes_nothing(api: Api):
    u, token = api.new_user()
    r = _change(api, token, "Passw0rd!", "Passw0rd!")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "password_unchanged"
    assert api.request("GET", "/orgs", token=token).status_code == 200
    assert api.login(u, "Passw0rd!").status_code == 200


def test_disabled_member_can_change_password(api: Api):
    admin_u, admin_t = api.new_user()
    member_u, member_t = api.new_user()
    r = api.request("POST", "/orgs", token=admin_t, json={"name": api.unique("org")})
    org_id = r.json()["id"]
    r = api.request("POST", f"/orgs/{org_id}/invites", token=admin_t,
                    json={"username": member_u, "role": "member"})
    invite_token = r.json()["token"]
    assert api.request("POST", "/invites/accept", token=member_t,
                       json={"token": invite_token}).status_code == 200
    # Disable the member, then the disabled member changes their password.
    r = api.request("PATCH", f"/orgs/{org_id}/members/batch", token=admin_t,
                    json={"changes": [{"user_id": _user_id(api, member_u), "status": "disabled"}]})
    assert r.status_code == 200
    r = _change(api, member_t, "Passw0rd!", "N3wPass!")
    assert r.status_code == 200
    # Re-login works and membership state is unchanged (still disabled).
    new_token = api.token_for(member_u, "N3wPass!")
    r = api.request("GET", f"/orgs/{org_id}/members/me", token=new_token)
    assert r.status_code == 403  # disabled members get the uniform 403
    r = api.request("GET", f"/orgs/{org_id}/members", token=admin_t)
    member = [m for m in r.json()["members"] if m["username"] == member_u][0]
    assert member["status"] == "disabled" and member["role"] == "member"


def _user_id(api: Api, username: str) -> int:
    # Helper: look up a user's id via their login response.
    r = api.login(username, "Passw0rd!")
    assert r.status_code == 200
    return r.json()["user"]["id"]


def test_concurrent_changes_exactly_one_wins(api: Api):
    u = api.unique()
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)

    def change(token, new):
        return _change(api, token, "Passw0rd!", new)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(change, t1, "WinnerOne!1")
        f2 = pool.submit(change, t2, "WinnerTwo!2")
        results = sorted([f1.result().status_code, f2.result().status_code])
    assert results == [200, 401]

    # Exactly one new password works; the old one does not.
    ok = [p for p in ("WinnerOne!1", "WinnerTwo!2") if api.login(u, p).status_code == 200]
    assert len(ok) == 1
    assert api.login(u, "Passw0rd!").status_code == 401
    # Both pre-change sessions are dead.
    assert api.request("GET", "/orgs", token=t1).status_code == 401
    assert api.request("GET", "/orgs", token=t2).status_code == 401


def test_change_survives_restart(make_server):
    srv = make_server("pwrestart")
    api = Api(srv.base_url)
    u = api.unique()
    api.register(u, "OldPass 1")
    token = api.token_for(u, "OldPass 1")
    assert _change(api, token, "OldPass 1", "NewPass 2").status_code == 200

    srv.restart()
    api = Api(srv.base_url)
    # Revocation and the new password both persisted.
    assert api.request("GET", "/orgs", token=token).status_code == 401
    r = api.login(u, "OldPass 1")
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_credentials"
    assert api.login(u, "NewPass 2").status_code == 200


def test_password_and_hash_not_leaked(api: Api, server, db):
    u = api.unique("pwleak")
    old_pw = "OldS3cret!value"
    new_pw = "N3wS3cret!value"
    api.register(u, old_pw)
    token = api.token_for(u, old_pw)
    r = _change(api, token, old_pw, new_pw)
    assert r.status_code == 200
    assert old_pw not in r.text and new_pw not in r.text
    # Neither password nor its hash appears in the server log.
    log_text = server.log_path.read_text()
    assert old_pw not in log_text and new_pw not in log_text
    assert "pbkdf2_sha256$" not in log_text
    # On disk: salted hash, no plaintext.
    stored = db.execute(
        "SELECT password_hash FROM users WHERE username = ?", (u,)
    ).fetchone()["password_hash"]
    assert stored.startswith("pbkdf2_sha256$")
    assert new_pw not in stored and old_pw not in stored
