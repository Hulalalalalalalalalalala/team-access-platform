"""Audit trail: content, pagination, admin-only access, immutability."""
from __future__ import annotations

from tests.conftest import Api


def _invite_member(api: Api, admin_token, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    return name, token


def test_audit_records_all_mutations_with_states(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"au-{api.unique()}"}).json()
    member_name, member_token = _invite_member(api, admin_token, org["id"])

    member_id = api.request("GET", f"/orgs/{org['id']}/members/me",
                            token=member_token).json()["membership"]["user_id"]
    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}",
                token=admin_token, json={"role": "admin"})

    r = api.request("GET", f"/orgs/{org['id']}/audit", token=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 4
    actions = [i["action"] for i in data["items"]]
    assert "org.created" in actions
    assert "invite.created" in actions
    assert "invite.accepted" in actions
    assert "member.updated" in actions

    updated = next(i for i in data["items"] if i["action"] == "member.updated")
    assert updated["org_id"] == org["id"]
    assert updated["before"] == {"role": "member", "status": "active"}
    assert updated["after"] == {"role": "admin", "status": "active"}
    assert updated["actor_username"]
    assert isinstance(updated["created_at"], int)


def test_audit_is_org_scoped_and_paginated(api: Api):
    _, admin_token = api.new_user()
    o1 = api.request("POST", "/orgs", token=admin_token,
                     json={"name": f"p1-{api.unique()}"}).json()
    o2 = api.request("POST", "/orgs", token=admin_token,
                     json={"name": f"p2-{api.unique()}"}).json()
    _invite_member(api, admin_token, o1["id"])

    r1 = api.request("GET", f"/orgs/{o1['id']}/audit", token=admin_token).json()
    r2 = api.request("GET", f"/orgs/{o2['id']}/audit", token=admin_token).json()
    assert all(i["action"] != "invite.created" or i["org_id"] == o2["id"]
               for i in r2["items"])
    assert {i["org_id"] for i in r2["items"]} == {o2["id"]}
    assert r1["total"] > r2["total"]

    # Pagination is stable and complete across pages.
    page1 = api.request("GET", f"/orgs/{o1['id']}/audit?page=1&page_size=1",
                        token=admin_token).json()
    page2 = api.request("GET", f"/orgs/{o1['id']}/audit?page=2&page_size=1",
                        token=admin_token).json()
    assert page1["total"] >= 3
    assert page1["page_size"] == 1 and page2["page_size"] == 1
    assert page1["items"][0]["id"] != page2["items"][0]["id"]
    assert page1["items"][0]["id"] < page2["items"][0]["id"]


def test_audit_admin_only_and_read_only(api: Api):
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"ar-{api.unique()}"}).json()
    _, member_token = _invite_member(api, admin_token, org["id"])
    _, outsider_token = api.new_user()

    assert api.request("GET", f"/orgs/{org['id']}/audit",
                       token=member_token).status_code == 403
    assert api.request("GET", f"/orgs/{org['id']}/audit",
                       token=outsider_token).status_code == 403

    # No mutation endpoints exist for the audit log.
    for method, path in (("PATCH", f"/orgs/{org['id']}/audit/1"),
                         ("DELETE", f"/orgs/{org['id']}/audit/1"),
                         ("POST", f"/orgs/{org['id']}/audit")):
        r = api.request(method, path, token=admin_token, json={})
        assert r.status_code in (404, 405)
        assert r.json()["error"]["code"]
