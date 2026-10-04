"""Idempotency-Key semantics for org creation, invites and member updates."""
from __future__ import annotations

import threading
import uuid

import httpx

from tests.conftest import Api


def _key() -> str:
    return uuid.uuid4().hex


def _org(api: Api, prefix: str) -> tuple[dict, str]:
    _, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    return org, token


def _add_member(api: Api, admin: str, org_id: int, role: str = "member") -> tuple[str, str, int]:
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    return name, token, r.json()["membership"]["user_id"]


def _member(api: Api, admin: str, org_id: int, user_id: int) -> dict:
    rows = api.request("GET", f"/orgs/{org_id}/members", token=admin).json()["members"]
    return next(m for m in rows if m["user_id"] == user_id)


def _patch(api: Api, admin: str, org_id: int, target: int, body: dict, key: str):
    return api.request("PATCH", f"/orgs/{org_id}/members/{target}", token=admin,
                       json=body, headers={"Idempotency-Key": key})


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


# ---------------- single-member adjustment keys bind to the first target ----

def test_member_update_same_key_different_target_is_conflict(api: Api):
    org, admin = _org(api, "mk-dt")
    # A joins as a second admin (so it can be demoted); B is a plain member.
    _, _, a_id = _add_member(api, admin, org["id"], "admin")
    _, _, b_id = _add_member(api, admin, org["id"], "member")
    key = _key()
    body = {"role": "member"}

    r1 = _patch(api, admin, org["id"], a_id, body, key)
    assert r1.status_code == 200
    first = r1.json()["membership"]
    assert first["user_id"] == a_id and first["role"] == "member"

    # Same key, identical body, but a DIFFERENT target: conflict, and member
    # A's stored info must not leak into the error response.
    r2 = _patch(api, admin, org["id"], b_id, body, key)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "idempotency_conflict"
    assert set(r2.json()) == {"error"}

    # Nothing about member B changed (role/status/updated_at), and no second
    # member-change audit was written.
    mb = _member(api, admin, org["id"], b_id)
    assert mb["role"] == "member" and mb["status"] == "active"
    audit = api.request("GET", f"/orgs/{org['id']}/audit?page=1&page_size=100",
                        token=admin).json()
    updates = [i for i in audit["items"] if i["action"] == "member.updated"]
    assert len(updates) == 1
    assert updates[0]["after"] is not None
    assert updates[0]["after"]["role"] == "member"

    # Original key + original target + original body still replays the first
    # result exactly.
    r3 = _patch(api, admin, org["id"], a_id, body, key)
    assert r3.status_code == 200 and r3.json()["membership"] == first
    # The replay neither changed B nor added an audit row.
    assert _member(api, admin, org["id"], b_id) == mb


def test_member_update_conflict_target_not_in_org(api: Api):
    org, admin = _org(api, "mk-nm")
    _, _, a_id = _add_member(api, admin, org["id"], "admin")
    # A user who never belongs to the target organization.
    outsider_name, outsider = api.new_user()
    outsider_org = api.request("POST", "/orgs", token=outsider,
                               json={"name": f"mk-out-{api.unique()}"}).json()
    outsider_id = api.request("GET", f"/orgs/{outsider_org['id']}/members/me",
                              token=outsider).json()["membership"]["user_id"]

    key = _key()
    body = {"role": "member"}
    assert _patch(api, admin, org["id"], a_id, body, key).status_code == 200

    # The key is already bound to A: aiming it at a non-member is rejected as
    # a target conflict — never success, never the plain 404 a fresh
    # adjustment would give, and never A's stored member info.
    r2 = _patch(api, admin, org["id"], outsider_id, body, key)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "idempotency_conflict"
    assert set(r2.json()) == {"error"}

    # A keyless adjustment of the same non-member is still the plain 404,
    # showing the 409 came from key binding rather than target existence.
    r3 = api.request("PATCH", f"/orgs/{org['id']}/members/{outsider_id}",
                     token=admin, json=body)
    assert r3.status_code == 404 and r3.json()["error"]["code"] == "member_not_found"

    # The stored success is intact and replays for A.
    r4 = _patch(api, admin, org["id"], a_id, body, key)
    assert r4.status_code == 200 and r4.json()["membership"]["user_id"] == a_id


def test_member_update_replay_returns_first_result_despite_later_change(api: Api):
    org, admin = _org(api, "mk-rc")
    _, _, a_id = _add_member(api, admin, org["id"], "admin")
    # Second admin so A's demotion is allowed and A can later be repromoted.
    _add_member(api, admin, org["id"], "admin")
    key = _key()
    body = {"role": "member"}

    r1 = _patch(api, admin, org["id"], a_id, body, key)
    assert r1.status_code == 200
    first = r1.json()["membership"]

    # Member A is later changed through a normal (keyless) request.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{a_id}", token=admin,
                    json={"role": "admin"})
    assert r.status_code == 200 and r.json()["membership"]["role"] == "admin"

    # Replaying the original key/body returns the FIRST snapshot without
    # re-executing: the later change survives.
    r2 = _patch(api, admin, org["id"], a_id, body, key)
    assert r2.status_code == 200
    assert r2.json()["membership"] == first
    assert _member(api, admin, org["id"], a_id)["role"] == "admin"

    # Same bound target, same key, but a DIFFERENT body stays a body
    # conflict (target match does not relax the body rule).
    r3 = _patch(api, admin, org["id"], a_id, {"status": "disabled"}, key)
    assert r3.status_code == 409
    assert r3.json()["error"]["code"] == "idempotency_conflict"
    assert _member(api, admin, org["id"], a_id)["status"] == "active"


def test_member_update_noop_success_binds_key_to_target(api: Api):
    org, admin = _org(api, "mk-no")
    _, _, a_id = _add_member(api, admin, org["id"], "member")
    _, _, b_id = _add_member(api, admin, org["id"], "member")
    key = _key()
    body = {"role": "member"}  # A is already a member: a successful no-op

    r1 = _patch(api, admin, org["id"], a_id, body, key)
    assert r1.status_code == 200 and r1.json()["membership"]["user_id"] == a_id

    # Nothing actually changed, yet the key was successfully used for A and
    # cannot be reused against B.
    r2 = _patch(api, admin, org["id"], b_id, body, key)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "idempotency_conflict"

    # Replaying against A still returns the first result.
    r3 = _patch(api, admin, org["id"], a_id, body, key)
    assert r3.status_code == 200 and r3.json() == r1.json()


def test_member_update_target_conflict_is_a_noop(api: Api):
    org, admin = _org(api, "mk-nop")
    _, _, a_id = _add_member(api, admin, org["id"], "member")
    b_name, _, b_id = _add_member(api, admin, org["id"], "member")

    # Active delegation in which B is trustee; the conflict must leave it
    # active and usable.
    d = api.request("POST", f"/orgs/{org['id']}/delegations", token=admin,
                    json={"user_id": b_id, "duration_seconds": 3600})
    assert d.status_code == 201, d.text
    deleg_id = d.json()["id"]

    key = _key()
    body = {"role": "member"}
    assert _patch(api, admin, org["id"], a_id, body, key).status_code == 200
    before_b = _member(api, admin, org["id"], b_id)
    rc = _patch(api, admin, org["id"], b_id, body, key)
    assert rc.status_code == 409 and rc.json()["error"]["code"] == "idempotency_conflict"

    # No member change, no new audit of any kind, delegation still active.
    assert _member(api, admin, org["id"], b_id) == before_b
    audit1 = api.request("GET", f"/orgs/{org['id']}/audit?page=1&page_size=100",
                         token=admin).json()["total"]
    rc2 = _patch(api, admin, org["id"], b_id, body, key)
    assert rc2.status_code == 409
    audit2 = api.request("GET", f"/orgs/{org['id']}/audit?page=1&page_size=100",
                         token=admin).json()["total"]
    assert audit1 == audit2
    delegs = api.request("GET", f"/orgs/{org['id']}/delegations", token=admin).json()
    mine = [x for x in delegs["delegations"] if x["id"] == deleg_id]
    assert len(mine) == 1 and mine[0]["status"] == "active"

    # B can still exercise the delegation (issue a member invite).
    b_tok = api.token_for(b_name)
    invitee, _ = api.new_user()
    r = api.request("POST", f"/orgs/{org['id']}/invites", token=b_tok,
                    json={"username": invitee, "role": "member"})
    assert r.status_code == 201, r.text


def test_member_update_key_scoped_per_org_and_entry_point(api: Api):
    org, admin = _org(api, "mk-sc")
    _, _, a_id = _add_member(api, admin, org["id"], "member")
    # A second org owned by the SAME operator, so the key can be compared
    # across orgs without changing the operator scope.
    org2 = api.request("POST", "/orgs", token=admin,
                       json={"name": f"mk-sc2-{api.unique()}"}).json()
    _, _, o2_id = _add_member(api, admin, org2["id"], "member")
    key = "shared-member-key"

    # A successful use against A in org 1 ...
    r1 = _patch(api, admin, org["id"], a_id, {"role": "member"}, key)
    assert r1.status_code == 200
    # ... does not bind the key in org 2 (org isolation kept) ...
    r2 = _patch(api, admin, org2["id"], o2_id, {"role": "member"}, key)
    assert r2.status_code == 200
    # ... nor in the batch entry point (single/batch scopes stay separate).
    r3 = api.request("PATCH", f"/orgs/{org['id']}/members/batch", token=admin,
                     headers={"Idempotency-Key": key},
                     json={"changes": [{"user_id": a_id, "role": "member"}]})
    assert r3.status_code == 200, r3.text

