"""Member administration: role/status changes and the last-admin invariant."""
from __future__ import annotations

import threading

import httpx

from tests.conftest import Api


def _setup_org_with_two_admins(api: Api):
    a_name, a_token = api.new_user()
    org = api.request("POST", "/orgs", token=a_token,
                      json={"name": f"la-{api.unique()}"}).json()
    b_name, b_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=a_token,
                      json={"username": b_name, "role": "admin"})
    api.request("POST", "/invites/accept", token=b_token, json={"token": inv.json()["token"]})
    members = api.request("GET", f"/orgs/{org['id']}/members", token=a_token).json()["members"]
    ids = {m["username"]: m["user_id"] for m in members}
    return org, a_name, a_token, ids[a_name], b_name, b_token, ids[b_name]


def test_last_admin_cannot_demote_or_disable_self(api: Api):
    name, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"one-{api.unique()}"}).json()
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=token).json()["membership"]["user_id"]

    for payload in ({"role": "member"}, {"status": "disabled"},
                    {"role": "member", "status": "disabled"}):
        r = api.request("PATCH", f"/orgs/{org['id']}/members/{me}",
                        token=token, json=payload)
        assert r.status_code == 409, payload
        assert r.json()["error"]["code"] == "last_admin_required"

    me_state = api.request("GET", f"/orgs/{org['id']}/members/me",
                           token=token).json()["membership"]
    assert me_state["role"] == "admin" and me_state["status"] == "active"


def test_demote_and_disable_with_two_admins(api: Api):
    org, _, a_token, a_id, b_name, b_token, b_id = _setup_org_with_two_admins(api)

    r = api.request("PATCH", f"/orgs/{org['id']}/members/{b_id}",
                    token=a_token, json={"role": "member"})
    assert r.status_code == 200 and r.json()["membership"]["role"] == "member"

    # Now B is the only admin again (A demoted B... A is still admin, B member)
    # so A must not be demotable either.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{a_id}",
                    token=a_token, json={"role": "member"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"

    # Promote B back, then disabling A is still forbidden (B admin, but the
    # target A being disabled leaves B as the sole admin -> allowed).
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{b_id}",
                    token=a_token, json={"role": "admin"})
    assert r.status_code == 200
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{a_id}",
                    token=a_token, json={"status": "disabled"})
    assert r.status_code == 200 and r.json()["membership"]["status"] == "disabled"


def test_concurrent_demotions_keep_one_admin(api: Api):
    org, _, a_token, a_id, _, b_token, b_id = _setup_org_with_two_admins(api)
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker(token: str, target: int) -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.patch(
                f"/orgs/{org['id']}/members/{target}",
                headers={"Authorization": f"Bearer {token}"},
                json={"role": "member"},
            ))

    threads = [
        threading.Thread(target=worker, args=(a_token, b_id)),
        threading.Thread(target=worker, args=(b_token, a_id)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = sorted(r.status_code for r in results)
    # Exactly one demotion lands. The loser either trips the last-admin
    # invariant (409) or has already lost admin rights by the time it takes
    # the write lock, in which case its next request is simply 403 — both
    # demonstrate that concurrent changes cannot leave zero active admins.
    assert statuses == [200, 403] or statuses == [200, 409], statuses
    if any(r.status_code == 409 for r in results):
        failed = next(r for r in results if r.status_code == 409)
        assert failed.json()["error"]["code"] == "last_admin_required"

    members = api.request("GET", f"/orgs/{org['id']}/members", token=a_token).json()["members"]
    active_admins = [m for m in members if m["role"] == "admin" and m["status"] == "active"]
    assert len(active_admins) == 1


def test_disabled_admin_blocks_sole_admin_invariant_by_role_state(api: Api):
    # Disabled member (former admin) must NOT count toward the admin quota.
    org, _, a_token, a_id, _, b_token, b_id = _setup_org_with_two_admins(api)
    # Disable B (allowed, A stays active admin).
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{b_id}",
                    token=a_token, json={"status": "disabled"})
    assert r.status_code == 200
    # Now A cannot leave the active-admin role: B is disabled.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{a_id}",
                    token=a_token, json={"status": "disabled"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"


def test_update_unknown_member_404_and_noop_body_422(api: Api):
    _, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"u4-{api.unique()}"}).json()
    r = api.request("PATCH", f"/orgs/{org['id']}/members/999999",
                    token=token, json={"role": "member"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"
    r = api.request("PATCH", f"/orgs/{org['id']}/members/999999",
                    token=token, json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
