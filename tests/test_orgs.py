"""Organization lifecycle and the 401/403 isolation rules."""
from __future__ import annotations

from tests.conftest import Api


def _invite(api: Api, token: str, org_id: int, username: str, role: str = "member") -> str:
    r = api.request("POST", f"/orgs/{org_id}/invites", token=token,
                    json={"username": username, "role": role})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def _accept(api: Api, token: str, invite_token: str):
    return api.request("POST", "/invites/accept", token=token, json={"token": invite_token})


def test_create_org_makes_creator_admin(api: Api):
    _, token = api.new_user()
    r = api.request("POST", "/orgs", token=token, json={"name": f"org-{api.unique()}"})
    assert r.status_code == 201, r.text
    org = r.json()
    assert org["role"] == "admin" and org["id"] > 0

    r = api.request("GET", "/orgs", token=token)
    assert r.status_code == 200
    assert any(o["id"] == org["id"] and o["role"] == "admin" for o in r.json()["organizations"])


def test_duplicate_org_name_409(api: Api):
    _, token = api.new_user()
    name = f"dup-{api.unique()}"
    assert api.request("POST", "/orgs", token=token, json={"name": name}).status_code == 201
    r = api.request("POST", "/orgs", token=token, json={"name": name})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "org_name_taken"


def test_user_can_belong_to_several_orgs(api: Api):
    _, token = api.new_user()
    ids = []
    for _ in range(3):
        r = api.request("POST", "/orgs", token=token, json={"name": f"multi-{api.unique()}"})
        assert r.status_code == 201
        ids.append(r.json()["id"])
    listed = {o["id"] for o in api.request("GET", "/orgs", token=token).json()["organizations"]}
    assert set(ids) <= listed


def test_non_member_gets_uniform_403_for_unknown_and_known_org(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"iso-{api.unique()}"}).json()

    _, outsider = api.new_user()
    for org_id in (org["id"], 9_999_999):
        for path in (f"/orgs/{org_id}/members", f"/orgs/{org_id}/audit",
                     f"/orgs/{org_id}/members/me"):
            r = api.request("GET", path, token=outsider)
            assert r.status_code == 403, (path, r.status_code)
            assert r.json()["error"]["code"] == "forbidden"
            assert org["name"] not in r.text


def test_member_role_isolation(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"role-{api.unique()}"}).json()
    member_name, member_token = api.new_user()

    # Before joining: even the roster is 403.
    assert api.request("GET", f"/orgs/{org['id']}/members",
                       token=member_token).status_code == 403

    _accept(api, member_token, _invite(api, admin_token, org["id"], member_name))

    # Plain member CAN read the roster and own state...
    r = api.request("GET", f"/orgs/{org['id']}/members", token=member_token)
    assert r.status_code == 200
    assert r.json()["members"][0]["status"] == "active"
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=member_token).status_code == 200

    # ...but cannot issue invites, revoke them, read audit or change members.
    r = api.request("POST", f"/orgs/{org['id']}/invites", token=member_token,
                    json={"username": "valid_name", "role": "member"})
    assert r.status_code == 403
    assert api.request("GET", f"/orgs/{org['id']}/audit",
                       token=member_token).status_code == 403
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{1}", token=member_token,
                    json={"role": "admin"})
    assert r.status_code == 403
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": "a" * 40})
    assert r.status_code == 403


def test_disabled_member_loses_org_access_but_keeps_other_orgs(api: Api):
    _, admin_token = api.new_user()
    org1 = api.request("POST", "/orgs", token=admin_token,
                       json={"name": f"d1-{api.unique()}"}).json()
    org2 = api.request("POST", "/orgs", token=admin_token,
                       json={"name": f"d2-{api.unique()}"}).json()
    member_name, member_token = api.new_user()

    # Admin invites a second admin into org1 so disabling the creator's
    # target below is legal; here the member joins both orgs.
    _accept(api, member_token, _invite(api, admin_token, org1["id"], member_name))
    _accept(api, member_token, _invite(api, admin_token, org2["id"], member_name))

    member_id = api.request("GET", f"/orgs/{org1['id']}/members/me",
                            token=member_token).json()["membership"]["user_id"]

    # Disable in org1 only.
    r = api.request("PATCH", f"/orgs/{org1['id']}/members/{member_id}",
                    token=admin_token, json={"status": "disabled"})
    assert r.status_code == 200, r.text

    # Immediate effect on the NEXT request, including the member's own query.
    for path in (f"/orgs/{org1['id']}/members", f"/orgs/{org1['id']}/members/me"):
        r = api.request("GET", path, token=member_token)
        assert r.status_code == 403, (path, r.status_code)

    # Other organization is unaffected; session itself stays valid.
    assert api.request("GET", f"/orgs/{org2['id']}/members",
                       token=member_token).status_code == 200
    assert api.request("GET", "/orgs", token=member_token).status_code == 200

    # Restore brings access back.
    r = api.request("PATCH", f"/orgs/{org1['id']}/members/{member_id}",
                    token=admin_token, json={"status": "active"})
    assert r.status_code == 200
    assert api.request("GET", f"/orgs/{org1['id']}/members",
                       token=member_token).status_code == 200


def test_disabling_revokes_org_access_on_all_sessions(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"ds-{api.unique()}"}).json()
    member_name, _ = api.new_user()
    invite = api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                         json={"username": member_name, "role": "member"}).json()
    t1 = api.token_for(member_name)
    t2 = api.token_for(member_name)
    for t in (t1, t2):
        assert api.request("POST", "/invites/accept", token=t,
                           json={"token": invite["token"]}).status_code in (200, 409)
    # One of the sessions holds the membership now; both sessions could read.
    members = api.request("GET", f"/orgs/{org['id']}/members", token=admin_token).json()["members"]
    member_id = next(m["user_id"] for m in members if m["username"] == member_name)

    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}",
                token=admin_token, json={"status": "disabled"})

    # EVERY session loses access to THIS org on its next request.
    for t in (t1, t2):
        assert api.request("GET", f"/orgs/{org['id']}/members", token=t).status_code == 403
        # But the sessions themselves remain valid.
        assert api.request("GET", "/orgs", token=t).status_code == 200


def test_role_change_takes_effect_on_next_request(api: Api):
    admin_name, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"rc-{api.unique()}"}).json()
    member_name, member_token = api.new_user()
    _accept(api, member_token, _invite(api, admin_token, org["id"], member_name))
    member_id = api.request("GET", f"/orgs/{org['id']}/members/me",
                            token=member_token).json()["membership"]["user_id"]

    # Promote: audit becomes readable on the next request.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}",
                    token=admin_token, json={"role": "admin"})
    assert r.status_code == 200
    assert api.request("GET", f"/orgs/{org['id']}/audit",
                       token=member_token).status_code == 200

    # Demote: next request is forbidden again. (Two active admins exist.)
    admin_id = None
    for m in api.request("GET", f"/orgs/{org['id']}/members",
                         token=admin_token).json()["members"]:
        if m["username"] == admin_name:
            admin_id = m["user_id"]
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}",
                    token=admin_token, json={"role": "member"})
    assert r.status_code == 200
    assert api.request("GET", f"/orgs/{org['id']}/audit",
                       token=member_token).status_code == 403
    assert admin_id is not None
