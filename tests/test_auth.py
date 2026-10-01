"""Registration / login / logout and secret hygiene."""
from __future__ import annotations

from tests.conftest import Api


def test_register_login_logout(api: Api):
    u = api.unique()
    r = api.register(u)
    assert r.status_code == 201
    assert r.json()["user"]["username"] == u
    assert "password" not in r.text and "password_hash" not in r.text

    r = api.login(u)
    assert r.status_code == 200
    token = r.json()["token"]
    assert "password" not in r.text

    # Token works.
    r = api.request("GET", "/orgs", token=token)
    assert r.status_code == 200

    # Logout invalidates exactly this session immediately.
    r = api.request("POST", "/auth/logout", token=token)
    assert r.status_code == 200 and r.json() == {"logged_out": True}
    r = api.request("GET", "/orgs", token=token)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"

    # Logout without a session is 401.
    r = api.request("POST", "/auth/logout")
    assert r.status_code == 401


def test_duplicate_username_is_409(api: Api):
    u = api.unique()
    assert api.register(u).status_code == 201
    r = api.register(u)
    assert r.status_code == 409
    body = r.json()
    assert body["error"]["code"] == "username_taken"


def test_logout_is_scoped_to_current_session(api: Api):
    _, _ = api.new_user()
    u = api.unique("multi")
    api.register(u)
    t1 = api.token_for(u)
    t2 = api.token_for(u)
    assert api.request("GET", "/orgs", token=t1).status_code == 200
    assert api.request("GET", "/orgs", token=t2).status_code == 200

    assert api.request("POST", "/auth/logout", token=t1).status_code == 200
    assert api.request("GET", "/orgs", token=t1).status_code == 401
    # The other session of the same user is unaffected.
    assert api.request("GET", "/orgs", token=t2).status_code == 200


def test_bad_credentials_and_missing_session(api: Api):
    u = api.unique()
    api.register(u)
    r = api.login(u, "wrong-password")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"

    r = api.login("no-such-user-xyz", "whatever")
    assert r.status_code == 401

    r = api.request("GET", "/orgs", token="a" * 64)
    assert r.status_code == 401
    r = api.request("GET", "/orgs")
    assert r.status_code == 401


def test_passwords_are_hashed_on_disk(api: Api, db):
    u = api.unique("secret")
    password = "Sup3rSecret!v@lue"
    api.register(u, password)
    row = db.execute("SELECT password_hash FROM users WHERE username = ?", (u,)).fetchone()
    stored = row["password_hash"]
    assert stored.startswith("pbkdf2_sha256$")
    assert password not in stored
    # Plaintext must not appear anywhere in the database file either.
    blob = db.execute("PRAGMA database_list").fetchone()[2]
    with open(blob, "rb") as f:
        assert password.encode() not in f.read()


def test_session_token_never_logged(api: Api, server):
    _, token = api.new_user()
    api.request("GET", "/orgs", token=token)
    log_text = server.log_path.read_text()
    assert token not in log_text
