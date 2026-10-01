"""Single-use invitations: issue / accept / revoke / expire / concurrency."""
from __future__ import annotations

import threading

import httpx

from tests.conftest import Api


def _issue(api: Api, admin_token: str, org_id: int, username: str, role: str = "member",
           key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                       json={"username": username, "role": role}, headers=headers)


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
