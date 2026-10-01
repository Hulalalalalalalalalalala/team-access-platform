"""Batch member role/status adjustment: PATCH /orgs/{org_id}/members/batch.

Covers validation, authorization (admins only; delegates excluded),
whole-batch 404 atomicity, the order-independent last-admin invariant,
permanent delegation invalidation (one row even when both parties lose
eligibility in the same batch), audit batch ids, idempotency, concurrency,
fault rollback and restart persistence.
"""
from __future__ import annotations

import threading
import uuid

import httpx

from tests.conftest import Api, Server


def _key() -> str:
    return uuid.uuid4().hex


def _setup_org(api: Api, *, n_admins: int = 1, n_members: int = 0):
    """Create an org with the creator as admin plus extra admins/members.

    Returns (org_id, admin_token, list[(username, token, user_id, role)]).
    """
    admin_name, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"batch-{api.unique()}"}).json()
    people: list[tuple[str, str, int, str]] = []

    def add(role: str):
        name, token = api.new_user()
        inv = api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                          json={"username": name, "role": role}).json()
        r = api.request("POST", "/invites/accept", token=token,
                        json={"token": inv["token"]})
        assert r.status_code == 200, r.text
        uid = api.request("GET", f"/orgs/{org['id']}/members/me",
                          token=token).json()["membership"]["user_id"]
        people.append((name, token, uid, role))
        return name, token, uid

    for _ in range(n_admins - 1):
        add("admin")
    for _ in range(n_members):
        add("member")
    return org["id"], admin_token, people


def _batch(api: Api, token: str, org_id: int, changes: list[dict], key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("PATCH", f"/orgs/{org_id}/members/batch", token=token,
                       json={"changes": changes}, headers=headers)


# ================================================================ basic shape

def test_batch_success_returns_members_in_submission_order(api: Api):
    org, admin, people = _setup_org(api, n_members=3)
    ids = [p[2] for p in people]
    changes = [
        {"user_id": ids[2], "role": "admin"},
        {"user_id": ids[0], "status": "disabled"},
        {"user_id": ids[1], "role": "admin", "status": "disabled"},
    ]
    r = _batch(api, admin, org, changes)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data["batch_id"], str) and data["batch_id"]
    returned = data["members"]
    assert [m["user_id"] for m in returned] == [ids[2], ids[0], ids[1]]
    assert returned[0]["role"] == "admin" and returned[0]["status"] == "active"
    assert returned[1]["role"] == "member" and returned[1]["status"] == "disabled"
    assert returned[2]["role"] == "admin" and returned[2]["status"] == "disabled"
    for m in returned:
        assert {"org_id", "user_id", "username", "role", "status",
                "created_at", "updated_at"} <= set(m)


def test_batch_unspecified_fields_keep_original_values(api: Api):
    org, admin, people = _setup_org(api, n_admins=2)
    target = people[0][2]
    r = _batch(api, admin, org, [{"user_id": target, "role": "member"}])
    assert r.status_code == 200
    m = r.json()["members"][0]
    assert m["role"] == "member" and m["status"] == "active"


def test_batch_unchanged_member_returned_without_timestamp_or_audit(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    noop_id, change_id = people[0][2], people[1][2]
    before = {m["user_id"]: m for m in
              api.request("GET", f"/orgs/{org}/members", token=admin).json()["members"]}

    r = _batch(api, admin, org, [
        {"user_id": noop_id, "role": "member", "status": "active"},  # no-op
        {"user_id": change_id, "role": "admin"},
    ])
    assert r.status_code == 200
    after = {m["user_id"]: m for m in r.json()["members"]}
    assert after[noop_id]["updated_at"] == before[noop_id]["updated_at"]
    assert after[change_id]["updated_at"] >= before[change_id]["updated_at"]

    batch_id = r.json()["batch_id"]
    items = api.request("GET", f"/orgs/{org}/audit", token=admin).json()["items"]
    rows = [i for i in items if i.get("batch_id") == batch_id]
    # Exactly one member change; the no-op produced no audit row.
    member_rows = [i for i in rows if i["action"] == "member.updated"]
    assert len(member_rows) == 1
    assert member_rows[0]["before"] == {"role": "member", "status": "active"}
    assert member_rows[0]["after"] == {"role": "admin", "status": "active"}


# ================================================================ validation

def test_batch_validation_errors(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    ids = [p[2] for p in people]

    bad_bodies = [
        {"changes": []},                                   # too few
        {"changes": [{"user_id": i, "role": "member"} for i in range(1, 102)]},  # too many
        {"changes": [{"user_id": ids[0]}, {"user_id": ids[0], "role": "admin"}]},  # dup
        {"changes": [{"user_id": ids[0]}]},               # no role/status
        {"changes": [{"user_id": ids[0], "role": "wizard"}]},  # bad enum
        {"changes": [{"user_id": ids[0], "status": "banned"}]},
        {"changes": [{"user_id": 0, "role": "member"}]},   # non-positive
        {"changes": [{"user_id": -1, "role": "member"}]},
        {"changes": [{"user_id": "1", "role": "member"}]},  # strict int
        {"changes": [{"user_id": 1.0, "role": "member"}]},
        {"changes": [{"user_id": True, "role": "member"}]},
        {},                                               # changes missing
    ]
    for body in bad_bodies:
        r = api.request("PATCH", f"/orgs/{org}/members/batch", token=admin, json=body)
        assert r.status_code == 422, body
        assert r.json()["error"]["code"] == "validation_error"


# ================================================================ authorization

def test_batch_requires_active_admin_and_forbids_delegate(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    _, member_token, member_id, _ = people[0]
    _, delegate_token, delegate_id, _ = people[1]
    outsider_name, outsider_token = api.new_user()

    # A plain member cannot batch.
    r = _batch(api, member_token, org, [{"user_id": delegate_id, "role": "admin"}])
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # An invitation delegate cannot batch even though they can issue invites.
    g = api.request("POST", f"/orgs/{org}/delegations", token=admin,
                    json={"user_id": delegate_id, "duration_seconds": 3600})
    assert g.status_code == 201
    r = _batch(api, delegate_token, org, [{"user_id": member_id, "status": "disabled"}])
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Outsider and a nonexistent org get the same uniform 403.
    r = _batch(api, outsider_token, org, [{"user_id": member_id, "role": "admin"}])
    assert r.status_code == 403
    r = _batch(api, outsider_token, 99999999, [{"user_id": member_id, "role": "admin"}])
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Unauthenticated -> 401.
    r = api.request("PATCH", f"/orgs/{org}/members/batch",
                    json={"changes": [{"user_id": member_id, "role": "admin"}]})
    assert r.status_code == 401


# ================================================================ 404 / atomicity

def test_batch_target_outside_org_is_404_and_changes_nothing(api: Api):
    org1, admin1, people1 = _setup_org(api, n_members=2)
    org2, admin2, people2 = _setup_org(api, n_members=1)
    member_id = people1[0][2]
    foreign_id = people2[0][2]  # belongs to org2

    # Mix a valid local target with a foreign-org target.
    r = _batch(api, admin1, org1, [
        {"user_id": member_id, "role": "admin"},
        {"user_id": foreign_id, "role": "admin"},
    ])
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "member_not_found"

    # Nothing in org1 changed and no batch audit landed.
    members = api.request("GET", f"/orgs/{org1}/members", token=admin1).json()["members"]
    local = next(m for m in members if m["user_id"] == member_id)
    assert local["role"] == "member"
    audit = api.request("GET", f"/orgs/{org1}/audit", token=admin1).json()["items"]
    assert not any(i["action"] == "member.updated" for i in audit)

    # A completely unknown user id fails identically.
    r = _batch(api, admin1, org1, [{"user_id": 99999999, "role": "member"}])
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"


# ================================================================ last admin

def test_batch_last_admin_invariant(api: Api):
    # Sole admin disabling/demoting self alone -> 409.
    org, admin, people = _setup_org(api, n_members=1)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    member_id = people[0][2]
    for changes in ([{"user_id": admin_uid, "role": "member"}],
                    [{"user_id": admin_uid, "status": "disabled"}],
                    [{"user_id": admin_uid, "role": "member", "status": "disabled"}]):
        r = _batch(api, admin, org, changes)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "last_admin_required"

    # Two active admins, batch demotes one and disables the other -> 409.
    org2, admin2, people2 = _setup_org(api, n_admins=2)
    a2_uid = api.request("GET", f"/orgs/{org2}/members/me",
                         token=admin2).json()["membership"]["user_id"]
    b2_id = people2[0][2]
    r = _batch(api, admin2, org2, [
        {"user_id": a2_uid, "role": "member"},
        {"user_id": b2_id, "status": "disabled"},
    ])
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"
    # Failure left no partial changes.
    members = api.request("GET", f"/orgs/{org2}/members", token=admin2).json()["members"]
    assert all(m["role"] == "admin" and m["status"] == "active" for m in members
               if m["user_id"] in (a2_uid, b2_id))


def test_batch_promote_and_demote_in_one_batch_order_independent(api: Api):
    # The same swap succeeds in BOTH list orderings.
    for order in ("promote_first", "demote_first"):
        org, admin, people = _setup_org(api, n_members=1)
        admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                                token=admin).json()["membership"]["user_id"]
        new_admin_id = people[0][2]
        promote = {"user_id": new_admin_id, "role": "admin"}
        demote = {"user_id": admin_uid, "role": "member", "status": "disabled"}
        changes = [promote, demote] if order == "promote_first" else [demote, promote]
        r = _batch(api, admin, org, changes)
        assert r.status_code == 200, (order, r.text)
        members = api.request("GET", f"/orgs/{org}/members",
                              token=people[0][1]).json()["members"]
        by_id = {m["user_id"]: m for m in members}
        assert by_id[new_admin_id]["role"] == "admin"
        assert by_id[new_admin_id]["status"] == "active"
        assert by_id[admin_uid]["role"] == "member"
        assert by_id[admin_uid]["status"] == "disabled"


def test_batch_allows_self_demotion_and_disabling(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    _, other_token, _, _ = people[0]
    other_id = people[0][2]
    # Promote the other member and demote self in one batch.
    r = _batch(api, admin, org, [
        {"user_id": other_id, "role": "admin"},
        {"user_id": admin_uid, "role": "member"},
    ])
    assert r.status_code == 200
    # New identity is effective immediately: member roster visible, audit not.
    assert api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).status_code == 200
    assert api.request("GET", f"/orgs/{org}/audit", token=admin).status_code == 403
    assert _batch(api, admin, org, [{"user_id": other_id, "status": "disabled"}]
                  ).status_code == 403

    # The remaining admin can now disable the former admin; access is cut off.
    r = _batch(api, other_token, org, [{"user_id": admin_uid, "status": "disabled"}])
    assert r.status_code == 200
    assert api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).status_code == 403


# ================================================================ delegations

def _grant(api: Api, admin: str, org_id: int, user_id: int):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin,
                       json={"user_id": user_id, "duration_seconds": 3600})


def test_batch_invalidates_delegations_with_combined_reasons_once(api: Api):
    # Admin A grants a delegation to member D; member X is also present.
    # A second admin B exists so A can be demoted/disabled in a batch.
    org, admin_a, people = _setup_org(api, n_admins=2, n_members=2)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin_a).json()["membership"]["user_id"]
    _, b_token, b_id, _ = people[0]
    _, d_token, d_id, _ = people[1]
    _, _, x_id, _ = people[2]

    g = _grant(api, admin_a, org, d_id)
    assert g.status_code == 201
    delegation_id = g.json()["id"]

    # One batch: grantor A demoted AND delegate D disabled -> ONE invalidation
    # row carrying both reasons. B stays an active admin.
    r = _batch(api, b_token, org, [
        {"user_id": a_id, "role": "member"},
        {"user_id": d_id, "status": "disabled"},
        {"user_id": x_id, "role": "admin"},
    ])
    assert r.status_code == 200, r.text
    batch_id = r.json()["batch_id"]

    items = api.request("GET", f"/orgs/{org}/audit", token=b_token).json()["items"]
    inv_rows = [i for i in items
                if i["action"] == "delegation.invalidated"
                and i["target_id"] == str(delegation_id)]
    assert len(inv_rows) == 1
    reason = inv_rows[0]["after"]["reason"]
    assert "grantor_not_admin" in reason and "delegate_ineligible" in reason
    assert inv_rows[0]["batch_id"] == batch_id
    assert inv_rows[0]["actor_id"] == b_id

    # Delegate lost invite powers immediately.
    invitee, _ = api.new_user()
    r = api.request("POST", f"/orgs/{org}/invites", token=d_token,
                    json={"username": invitee, "role": "member"})
    assert r.status_code == 403

    # Re-enabling/restoring BOTH parties in a later batch never revives it.
    r = _batch(api, b_token, org, [
        {"user_id": a_id, "role": "admin", "status": "active"},
        {"user_id": d_id, "status": "active"},
    ])
    assert r.status_code == 200
    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=b_token).json()["delegations"]
    target = next(x for x in lst if x["id"] == delegation_id)
    assert target["status"] == "invalidated"
    assert "grantor_not_admin" in target["reason"]


def test_batch_invalidation_keeps_already_issued_invites_usable(api: Api):
    org, admin, people = _setup_org(api, n_admins=2, n_members=1)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).json()["membership"]["user_id"]
    _, b_token, _, _ = people[0]
    _, d_token, d_id, _ = people[1]
    _grant(api, admin, org, d_id)

    invitee, invitee_tok = api.new_user()
    inv = api.request("POST", f"/orgs/{org}/invites", token=d_token,
                      json={"username": invitee, "role": "member"})
    assert inv.status_code == 201

    # Invalidate the delegation by demoting its grantor in a batch.
    r = _batch(api, b_token, org, [{"user_id": a_id, "role": "member"}])
    assert r.status_code == 200

    # The previously issued invite still follows the normal accept rules.
    r = api.request("POST", "/invites/accept", token=invitee_tok,
                    json={"token": inv.json()["token"]})
    assert r.status_code == 200


def test_batch_audit_rows_share_batch_id(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    ids = [p[2] for p in people]
    r = _batch(api, admin, org, [
        {"user_id": ids[0], "role": "admin"},
        {"user_id": ids[1], "status": "disabled"},
    ])
    batch_id = r.json()["batch_id"]
    items = api.request("GET", f"/orgs/{org}/audit", token=admin).json()["items"]
    rows = [i for i in items if i.get("batch_id") == batch_id]
    assert len([i for i in rows if i["action"] == "member.updated"]) == 2
    for i in rows:
        assert i["org_id"] == org and i["actor_id"]
        assert isinstance(i["created_at"], int)
        assert i["before"] and i["after"]
    # Unrelated rows do not carry a batch id.
    assert all(i["batch_id"] is not None or i["action"] != "member.updated"
               for i in items)


# ================================================================ idempotency

def test_batch_idempotent_replay_single_change_set(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    ids = [p[2] for p in people]
    changes = [{"user_id": i, "role": "admin"} for i in ids]
    key = _key()
    r1 = _batch(api, admin, org, changes, key=key)
    r2 = _batch(api, admin, org, changes, key=key)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()

    items = api.request("GET", f"/orgs/{org}/audit", token=admin).json()["items"]
    assert sum(1 for i in items if i["action"] == "member.updated") == 2


def test_batch_same_key_different_body_conflict(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    ids = [p[2] for p in people]
    key = _key()
    assert _batch(api, admin, org, [{"user_id": ids[0], "role": "admin"}],
                  key=key).status_code == 200
    r = _batch(api, admin, org, [{"user_id": ids[1], "role": "admin"}], key=key)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency_conflict"


def test_batch_idempotency_isolated_from_single_entry(api: Api):
    org, admin, people = _setup_org(api, n_admins=2, n_members=1)
    target = people[1][2]
    key = "shared-entry-point-key"
    r1 = api.request("PATCH", f"/orgs/{org}/members/{target}", token=admin,
                     json={"role": "admin"}, headers={"Idempotency-Key": key})
    assert r1.status_code == 200
    # Same key on the batch scope is independent (no conflict, no replay).
    r2 = _batch(api, admin, org, [
        {"user_id": target, "role": "member"}
    ], key=key)
    assert r2.status_code == 200
    assert r2.json()["members"][0]["role"] == "member"
    # And the single-entry key still replays its own first result.
    r3 = api.request("PATCH", f"/orgs/{org}/members/{target}", token=admin,
                     json={"role": "admin"}, headers={"Idempotency-Key": key})
    assert r3.status_code == 200 and r3.json() == r1.json()


def test_batch_failure_does_not_consume_key(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target = people[0][2]
    key = _key()
    r = _batch(api, admin, org, [{"user_id": 99999999, "role": "admin"}], key=key)
    assert r.status_code == 404
    r = _batch(api, admin, org, [{"user_id": target, "role": "admin"}], key=key)
    assert r.status_code == 200


def test_batch_replay_rechecks_admin_after_self_demotion(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    other_id = people[0][2]
    key = _key()
    changes = [{"user_id": other_id, "role": "admin"},
               {"user_id": admin_uid, "role": "member"}]
    assert _batch(api, admin, org, changes, key=key).status_code == 200
    # Same key replay: the caller is no longer an admin -> 403.
    r = _batch(api, admin, org, changes, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"


def test_batch_concurrent_retry_single_change(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    ids = [p[2] for p in people]
    changes = [{"user_id": i, "role": "admin"} for i in ids]
    key = _key()
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.patch(
                f"/orgs/{org}/members/batch",
                headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": key},
                json={"changes": changes},
            ))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r.status_code for r in results) == [200, 200]
    assert results[0].json()["batch_id"] == results[1].json()["batch_id"]
    items = api.request("GET", f"/orgs/{org}/audit", token=admin).json()["items"]
    assert sum(1 for i in items if i["action"] == "member.updated") == 2


# ================================================================ concurrency

def test_concurrent_batch_single_and_delegate_invite_keep_invariants(api: Api):
    # Two active admins A (batch actor) and B (single-PATCH actor); A has
    # granted a delegation to member D; C is a plain member.
    org, token_a, people = _setup_org(api, n_admins=2, n_members=2)
    _, token_b, _, _ = people[0]
    _, token_d, d_id, _ = people[1]
    _, token_c, c_id, _ = people[2]
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=token_a).json()["membership"]["user_id"]

    g = _grant(api, token_a, org, d_id)
    delegation_id = g.json()["id"]
    invitee, invitee_tok = api.new_user()

    barrier = threading.Barrier(3)
    outcomes: dict[str, httpx.Response] = {}

    def batch_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            outcomes["batch"] = c.patch(
                f"/orgs/{org}/members/batch",
                headers={"Authorization": f"Bearer {token_a}"},
                json={"changes": [
                    {"user_id": a_id, "role": "member"},
                    {"user_id": c_id, "role": "admin"},
                ]},
            )

    def single_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            outcomes["single"] = c.patch(
                f"/orgs/{org}/members/{c_id}",
                headers={"Authorization": f"Bearer {token_b}"},
                json={"status": "disabled"},
            )

    def invite_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            outcomes["invite"] = c.post(
                f"/orgs/{org}/invites",
                headers={"Authorization": f"Bearer {token_d}"},
                json={"username": invitee, "role": "member"},
            )

    threads = [threading.Thread(target=batch_worker),
               threading.Thread(target=single_worker),
               threading.Thread(target=invite_worker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Never zero active administrators.
    members = api.request("GET", f"/orgs/{org}/members",
                          token=token_b).json()["members"]
    active_admins = [m for m in members if m["role"] == "admin" and m["status"] == "active"]
    assert len(active_admins) >= 1

    # The batch must have committed and invalidated A's delegation.
    assert outcomes["batch"].status_code == 200, outcomes["batch"].text
    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=token_b).json()["delegations"]
    assert next(x for x in lst if x["id"] == delegation_id)["status"] == "invalidated"

    # Delegate invite: either it committed strictly BEFORE invalidation
    # (201 and the invite remains usable) or it was rejected (403). It can
    # never succeed against an already-invalidated delegation.
    ir = outcomes["invite"]
    if ir.status_code == 201:
        assert ir.json()["delegation_id"] == delegation_id
        r = api.request("POST", "/invites/accept", token=invitee_tok,
                        json={"token": ir.json()["token"]})
        assert r.status_code == 200
    else:
        assert ir.status_code == 403


# ================================================================ atomic rollback

def test_batch_failed_audit_rolls_back_everything(api: Api, db):
    org, admin, people = _setup_org(api, n_members=1)
    _, d_token, d_id, _ = people[0]
    _grant(api, admin, org, d_id)

    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)",
               ("delegation.invalidated",))
    db.commit()
    key = _key()
    try:
        r = _batch(api, admin, org, [{"user_id": d_id, "status": "disabled"}], key=key)
        assert r.status_code == 500
        assert r.json()["error"]["code"] == "internal_error"
    finally:
        db.execute("DELETE FROM _fail_next_actions WHERE action = ?",
                   ("delegation.invalidated",))
        db.commit()

    # Members, delegation and audit all stayed as they were.
    row = db.execute("SELECT status FROM memberships WHERE user_id = ?",
                     (d_id,)).fetchone()
    assert row["status"] == "active"
    row = db.execute("SELECT status FROM delegations WHERE delegate_id = ?",
                     (d_id,)).fetchone()
    assert row["status"] == "active"
    n_audit = db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ? AND action IN "
        "('member.updated','delegation.invalidated')",
        (org,),
    ).fetchone()["n"]
    assert n_audit == 0
    # The failure did not consume the idempotency key.
    n_keys = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys WHERE scope = ?",
        (f"org:{org}:member.batch_update",),
    ).fetchone()["n"]
    assert n_keys == 0

    # Delegate powers are intact and a retry with the same key now succeeds.
    invitee, _ = api.new_user()
    assert api.request("POST", f"/orgs/{org}/invites", token=d_token,
                       json={"username": invitee, "role": "member"}).status_code == 201
    assert _batch(api, admin, org, [{"user_id": d_id, "status": "disabled"}], key=key
                  ).status_code == 200


# ================================================================ restart

def test_batch_result_and_idempotency_survive_restart(make_server):
    srv: Server = make_server(f"batch-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        admin_name = api.unique("ba")
        c.post("/auth/register", json={"username": admin_name, "password": "Passw0rd!"})
        admin = c.post("/auth/login", json={"username": admin_name,
                                            "password": "Passw0rd!"}).json()["token"]
        org = c.post("/orgs", headers={"Authorization": f"Bearer {admin}"},
                     json={"name": f"persist-b-{api.unique()}"}).json()
        member_name = api.unique("bm")
        c.post("/auth/register", json={"username": member_name, "password": "Passw0rd!"})
        member = c.post("/auth/login", json={"username": member_name,
                                             "password": "Passw0rd!"}).json()["token"]
        inv = c.post(f"/orgs/{org['id']}/invites",
                     headers={"Authorization": f"Bearer {admin}"},
                     json={"username": member_name, "role": "member"}).json()
        c.post("/invites/accept", headers={"Authorization": f"Bearer {member}"},
               json={"token": inv["token"]})
        roster = c.get(f"/orgs/{org['id']}/members",
                       headers={"Authorization": f"Bearer {admin}"}).json()["members"]
        target = next(m["user_id"] for m in roster if m["username"] == member_name)

        r1 = c.patch(
            f"/orgs/{org['id']}/members/batch",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "batch-persist"},
            json={"changes": [{"user_id": target, "role": "admin"}]},
        )
        assert r1.status_code == 200
        first = r1.json()

    srv.restart()
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        r2 = c.patch(
            f"/orgs/{org['id']}/members/batch",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "batch-persist"},
            json={"changes": [{"user_id": target, "role": "admin"}]},
        )
        assert r2.status_code == 200
        assert r2.json() == first
        # No duplicate audit after replay.
        audit = c.get(f"/orgs/{org['id']}/audit",
                      headers={"Authorization": f"Bearer {admin}"}).json()["items"]
        rows = [i for i in audit if i.get("batch_id") == first["batch_id"]]
        assert len([i for i in rows if i["action"] == "member.updated"]) == 1
        # Different body still conflicts after restart.
        r3 = c.patch(
            f"/orgs/{org['id']}/members/batch",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "batch-persist"},
            json={"changes": [{"user_id": target, "status": "disabled"}]},
        )
        assert r3.status_code == 409
        assert r3.json()["error"]["code"] == "idempotency_conflict"
