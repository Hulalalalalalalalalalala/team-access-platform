"""Idempotency-Key semantics for org creation, invites and member updates."""
from __future__ import annotations

import threading
import uuid

import httpx

from tests.conftest import Api


def _key() -> str:
    return uuid.uuid4().hex


def test_create_org_idempotent_replay(api: Api):
    _, token = api.new_user()
    key = _key()
    body = {"name": f"idem-{api.unique()}"}
    h = {"Idempotency-Key": key}

    r1 = api.request("POST", "/orgs", token=token, json=body, headers=h)
    r2 = api.request("POST", "/orgs", token=token, json=body, headers=h)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json() == r2.json()
    assert len(api.request("GET", "/orgs", token=token).json()["organizations"]) == 1


def test_same_key_different_body_is_conflict(api: Api):
    _, token = api.new_user()
    key = _key()
    h = {"Idempotency-Key": key}
    api.request("POST", "/orgs", token=token, json={"name": f"c1-{api.unique()}"}, headers=h)
    r = api.request("POST", "/orgs", token=token, json={"name": f"c2-{api.unique()}"}, headers=h)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency_conflict"


def test_invite_idempotency_scoped_per_org_and_returns_same_token(api: Api):
    _, token = api.new_user()
    o1 = api.request("POST", "/orgs", token=token, json={"name": f"io1-{api.unique()}"}).json()
    o2 = api.request("POST", "/orgs", token=token, json={"name": f"io2-{api.unique()}"}).json()
    member, _ = api.new_user()
    key = "shared-key-1"

    r1 = api.request("POST", f"/orgs/{o1['id']}/invites", token=token,
                     json={"username": member, "role": "member"},
                     headers={"Idempotency-Key": key})
    # Same key is independently usable for a different target org.
    r2 = api.request("POST", f"/orgs/{o2['id']}/invites", token=token,
                     json={"username": member, "role": "member"},
                     headers={"Idempotency-Key": key})
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["token"] != r2.json()["token"]

    # Same org + key + same body replays the FIRST invite token.
    r1b = api.request("POST", f"/orgs/{o1['id']}/invites", token=token,
                      json={"username": member, "role": "member"},
                      headers={"Idempotency-Key": key})
    assert r1b.status_code == 201
    assert r1b.json()["token"] == r1.json()["token"]

    # Different body with the same key in the same org conflicts.
    r = api.request("POST", f"/orgs/{o1['id']}/invites", token=token,
                    json={"username": member, "role": "admin"},
                    headers={"Idempotency-Key": key})
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"


def test_member_update_idempotency_one_audit_row(api: Api):
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin, json={"name": f"im-{api.unique()}"}).json()
    name, member = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                      json={"username": name, "role": "admin"}).json()
    api.request("POST", "/invites/accept", token=member, json={"token": inv["token"]})
    members = api.request("GET", f"/orgs/{org['id']}/members", token=admin).json()["members"]
    target = next(m["user_id"] for m in members if m["username"] == name)

    key = _key()
    body = {"role": "member"}
    r1 = api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=admin,
                     json=body, headers={"Idempotency-Key": key})
    r2 = api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=admin,
                     json=body, headers={"Idempotency-Key": key})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()

    audit = api.request("GET", f"/orgs/{org['id']}/audit", token=admin).json()
    assert sum(1 for i in audit["items"] if i["action"] == "member.updated") == 1


def test_replay_rechecks_permissions(api: Api):
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin, json={"name": f"rp-{api.unique()}"}).json()
    name, member = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                      json={"username": name, "role": "admin"}).json()
    api.request("POST", "/invites/accept", token=member, json={"token": inv["token"]})
    members = api.request("GET", f"/orgs/{org['id']}/members", token=admin).json()["members"]
    target = next(m["user_id"] for m in members if m["username"] == name)

    key = _key()
    body = {"role": "member"}
    # Admin performs it once.
    assert api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=admin,
                       json=body, headers={"Idempotency-Key": key}).status_code == 200
    # The now-demoted user replays the same key: permission is re-checked.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=member,
                    json=body, headers={"Idempotency-Key": key})
    assert r.status_code == 403


def test_concurrent_idempotent_retry_single_change(api: Api):
    _, token = api.new_user()
    key = _key()
    body = {"name": f"cc-{api.unique()}"}
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.post(
                "/orgs",
                headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key},
                json=body,
            ))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r.status_code for r in results) == [201, 201]
    ids = {r.json()["id"] for r in results}
    assert len(ids) == 1
    orgs = api.request("GET", "/orgs", token=token).json()["organizations"]
    assert len(orgs) == 1


def test_idempotency_does_not_cache_failures(api: Api):
    _, token = api.new_user()
    key = _key()
    # First attempt conflicts at the business layer (duplicate name).
    name = f"fail-{api.unique()}"
    api.request("POST", "/orgs", token=token, json={"name": name})
    r1 = api.request("POST", "/orgs", token=token, json={"name": name},
                     headers={"Idempotency-Key": key})
    assert r1.status_code == 409 and r1.json()["error"]["code"] == "org_name_taken"
    # The key is still usable for a genuinely different, valid request.
    r2 = api.request("POST", "/orgs", token=token, json={"name": f"ok-{api.unique()}"},
                     headers={"Idempotency-Key": key})
    assert r2.status_code == 201
