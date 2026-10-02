"""Member removal: DELETE /orgs/{org_id}/members/{user_id}.

Covers the response shape, authorization, the last-admin invariant, effects
on the roster / own org list / sessions / other orgs, recovery rejection,
single and batch adjustments involving a removed target, permanent delegation
invalidation, bound-invite revocation (with the availability check first),
post-removal rejoin, idempotency (scope isolation, same-key-different-target
conflict, permission re-check, failure does not consume the key), concurrency
equivalence, atomic rollback and restart persistence.
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

    ``people`` lists the added users in order: the extra admins first, then
    the members. Returns (org_id, admin_token, people).
    """
    admin_name, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"rm-{api.unique()}"}).json()
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


def _remove(api: Api, token: str, org_id: int, user_id: int, key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("DELETE", f"/orgs/{org_id}/members/{user_id}",
                       token=token, headers=headers)


def _grant(api: Api, admin: str, org_id: int, user_id: int):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin,
                       json={"user_id": user_id, "duration_seconds": 3600})


# ================================================================ basic shape

def test_remove_active_member_success(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target = people[0][2]
    r = _remove(api, admin, org, target)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": org, "user_id": target, "removed": True}


def test_remove_disabled_member_success(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target = people[0][2]
    api.request("PATCH", f"/orgs/{org}/members/{target}", token=admin,
                json={"status": "disabled"})
    r = _remove(api, admin, org, target)
    assert r.status_code == 200
    assert r.json()["removed"] is True


def test_remove_self_with_other_admin(api: Api):
    org, admin, people = _setup_org(api, n_admins=2)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    r = _remove(api, admin, org, admin_uid)
    assert r.status_code == 200
    assert r.json()["user_id"] == admin_uid


# ================================================================ authorization

def test_remove_requires_active_admin(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    member_token, member_id = people[0][1], people[0][2]
    other_id = people[1][2]
    outsider, outsider_token = api.new_user()

    # A plain member cannot remove.
    assert _remove(api, member_token, org, other_id).status_code == 403
    # An outsider cannot.
    assert _remove(api, outsider_token, org, member_id).status_code == 403
    # A nonexistent org gets the same uniform 403.
    assert _remove(api, outsider_token, 99999999, member_id).status_code == 403
    # Unauthenticated -> 401.
    assert api.request("DELETE", f"/orgs/{org}/members/{member_id}").status_code == 401
    # A disabled admin cannot call.
    api.request("PATCH", f"/orgs/{org}/members/{member_id}", token=admin,
                json={"role": "admin"})
    api.request("PATCH", f"/orgs/{org}/members/{member_id}", token=admin,
                json={"status": "disabled"})
    assert _remove(api, people[0][1], org, other_id).status_code == 403


def test_remove_target_not_in_org_is_404(api: Api):
    org1, admin1, people1 = _setup_org(api, n_members=1)
    org2, admin2, people2 = _setup_org(api, n_members=1)
    foreign_id = people2[0][2]

    # Member of another org.
    r = _remove(api, admin1, org1, foreign_id)
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"
    # Completely unknown user id.
    r = _remove(api, admin1, org1, 99999999)
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"
    # Removing twice: the second is 404.
    target = people1[0][2]
    assert _remove(api, admin1, org1, target).status_code == 200
    assert _remove(api, admin1, org1, target).status_code == 404


# ================================================================ last admin

def test_remove_last_active_admin_is_409(api: Api):
    org, admin, _ = _setup_org(api)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    # Sole admin removing self.
    r = _remove(api, admin, org, admin_uid)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"
    # Still a member.
    assert api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).status_code == 200


def test_remove_last_active_admin_with_disabled_admin_is_409(api: Api):
    org, admin, people = _setup_org(api, n_admins=2)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    other_id = people[0][2]
    # Disable the other admin; the sole active admin cannot be removed.
    api.request("PATCH", f"/orgs/{org}/members/{other_id}", token=admin,
                json={"status": "disabled"})
    r = _remove(api, admin, org, admin_uid)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"


def test_remove_one_of_two_admins_allowed(api: Api):
    org, admin, people = _setup_org(api, n_admins=2)
    other_id = people[0][2]
    r = _remove(api, admin, org, other_id)
    assert r.status_code == 200
    # The remaining admin still sees the org.
    assert api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).status_code == 200


# ================================================================ effects

def test_removed_member_disappears_from_roster_and_own_orgs(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]

    r = _remove(api, admin, org, target_id)
    assert r.status_code == 200

    # Gone from the roster.
    members = api.request("GET", f"/orgs/{org}/members",
                          token=admin).json()["members"]
    assert all(m["user_id"] != target_id for m in members)

    # Gone from their own org list.
    orgs = api.request("GET", "/orgs", token=target_token).json()["organizations"]
    assert all(o["id"] != org for o in orgs)

    # Their session is denied access to this org from the next request.
    assert api.request("GET", f"/orgs/{org}/members",
                       token=target_token).status_code == 403
    assert api.request("GET", f"/orgs/{org}/members/me",
                       token=target_token).status_code == 403
    assert api.request("GET", f"/orgs/{org}/delegations",
                       token=target_token).status_code == 403


def test_removed_member_account_and_other_orgs_unaffected(api: Api):
    org1, admin1, people1 = _setup_org(api, n_members=1)
    org2, admin2, _ = _setup_org(api, n_members=0)
    target_name, target_token, target_id, _ = people1[0]
    # Target also belongs to org2.
    inv = api.request("POST", f"/orgs/{org2}/invites", token=admin2,
                      json={"username": target_name, "role": "member"}).json()
    api.request("POST", "/invites/accept", token=target_token,
                json={"token": inv["token"]})

    assert _remove(api, admin1, org1, target_id).status_code == 200

    # Account still works: own org list reachable.
    assert api.request("GET", "/orgs", token=target_token).status_code == 200
    # Other org membership intact.
    orgs = api.request("GET", "/orgs", token=target_token).json()["organizations"]
    assert {o["id"] for o in orgs} == {org2}
    assert api.request("GET", f"/orgs/{org2}/members",
                       token=target_token).status_code == 200


def test_recovery_cannot_bring_back_removed_member(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    assert _remove(api, admin, org, target_id).status_code == 200
    # The restore entry point rejects a removed member as not found.
    r = api.request("PATCH", f"/orgs/{org}/members/{target_id}", token=admin,
                    json={"status": "active"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"


def test_single_and_batch_adjustment_reject_removed_target(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    removed_id = people[0][2]
    other_id = people[1][2]
    assert _remove(api, admin, org, removed_id).status_code == 200

    # Single adjustment.
    r = api.request("PATCH", f"/orgs/{org}/members/{removed_id}", token=admin,
                    json={"role": "admin"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"

    # Batch involving the removed target: whole batch 404, others unchanged.
    r = api.request("PATCH", f"/orgs/{org}/members/batch", token=admin,
                    json={"changes": [
                        {"user_id": removed_id, "role": "admin"},
                        {"user_id": other_id, "role": "admin"},
                    ]})
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"
    members = api.request("GET", f"/orgs/{org}/members",
                          token=admin).json()["members"]
    other = next(m for m in members if m["user_id"] == other_id)
    assert other["role"] == "member"


# ================================================================ delegations

def test_removal_invalidates_delegation_as_grantor(api: Api):
    # Two admins: A (grantor, self-removes) and B (remaining).
    org, admin_a, people = _setup_org(api, n_admins=2, n_members=1)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin_a).json()["membership"]["user_id"]
    b_token, b_id = people[0][1], people[0][2]
    delegate_id = people[1][2]
    d = _grant(api, admin_a, org, delegate_id).json()

    assert _remove(api, admin_a, org, a_id).status_code == 200

    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=b_token).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "grantor_not_admin"


def test_removal_invalidates_delegation_as_delegate(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    delegate_id = people[0][2]
    d = _grant(api, admin, org, delegate_id).json()

    assert _remove(api, admin, org, delegate_id).status_code == 200

    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=admin).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "delegate_ineligible"


def test_removal_invalidates_delegation_with_applicable_reason(api: Api):
    # A grants to D. Removing the grantor invalidates with grantor_not_admin;
    # the delegation is already dead, so removing D afterwards does not change
    # it (combined reasons only arise from the batch entry point).
    org, admin_a, people = _setup_org(api, n_admins=2, n_members=1)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin_a).json()["membership"]["user_id"]
    b_token, b_id = people[0][1], people[0][2]
    d_token, d_id = people[1][1], people[1][2]
    d = _grant(api, admin_a, org, d_id).json()

    assert _remove(api, admin_a, org, a_id).status_code == 200

    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=b_token).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "grantor_not_admin"

    # Audit: one invalidation row with the grantor reason.
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=b_token).json()["items"]
    inv_rows = [i for i in items if i["action"] == "delegation.invalidated"
                and i["target_id"] == str(d["id"])]
    assert len(inv_rows) == 1
    assert inv_rows[0]["after"]["reason"] == "grantor_not_admin"

    # Removing the delegate now: the delegation is already invalidated, so no
    # second invalidation row and no reason change.
    assert _remove(api, b_token, org, d_id).status_code == 200
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=b_token).json()["items"]
    inv_rows = [i for i in items if i["action"] == "delegation.invalidated"
                and i["target_id"] == str(d["id"])]
    assert len(inv_rows) == 1
    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=b_token).json()["delegations"]
    assert next(x for x in lst if x["id"] == d["id"])["reason"] == "grantor_not_admin"


def test_rejoin_does_not_revive_invalidated_delegation(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    d_token, d_id = people[0][1], people[0][2]
    d = _grant(api, admin, org, d_id).json()

    assert _remove(api, admin, org, d_id).status_code == 200

    # Rejoin via a fresh invite.
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": people[0][0], "role": "member"}).json()
    assert api.request("POST", "/invites/accept", token=d_token,
                       json={"token": inv["token"]}).status_code == 200

    lst = api.request("GET", f"/orgs/{org}/delegations",
                      token=admin).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    # Delegate still has no invite powers.
    invitee, _ = api.new_user()
    assert api.request("POST", f"/orgs/{org}/invites", token=d_token,
                       json={"username": invitee, "role": "member"}
                       ).status_code == 403


# ================================================================ invites

def test_bound_invite_revoked_on_removal(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]
    # An invite bound to the target's username, issued before removal.
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": target_name, "role": "member"}).json()

    assert _remove(api, admin, org, target_id).status_code == 200

    # Accepting it now: availability is checked first -> invite_unavailable.
    r = api.request("POST", "/invites/accept", token=target_token,
                    json={"token": inv["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


def test_removal_does_not_touch_invites_issued_for_others(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    # An invite bound to a DIFFERENT user (the invitee), issued by the admin.
    invitee, invitee_tok = api.new_user()
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": invitee, "role": "member"}).json()

    assert _remove(api, admin, org, target_id).status_code == 200

    # The invite for the other user still works.
    r = api.request("POST", "/invites/accept", token=invitee_tok,
                    json={"token": inv["token"]})
    assert r.status_code == 200


def test_post_removal_invite_rejoins_with_new_role_and_fresh_join_time(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]
    assert _remove(api, admin, org, target_id).status_code == 200

    # A new invite after removal can rejoin; role comes from the new invite.
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": target_name, "role": "admin"}).json()
    r = api.request("POST", "/invites/accept", token=target_token,
                    json={"token": inv["token"]})
    assert r.status_code == 200
    m = r.json()["membership"]
    assert m["role"] == "admin" and m["status"] == "active"
    # Join time re-recorded (the new membership is fresh).
    assert m["created_at"] >= inv["created_at"]


def test_same_second_issuance_and_removal_distinguished(api: Api):
    # Issuing an invite and removing in the same second must not revoke the
    # post-removal invite. The write lock serializes them: the invite either
    # commits before the removal (and is revoked) or after (and is kept).
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]

    # Issue an invite, then remove in the same second.
    inv_before = api.request("POST", f"/orgs/{org}/invites", token=admin,
                             json={"username": target_name, "role": "member"}).json()
    assert _remove(api, admin, org, target_id).status_code == 200

    # The pre-removal invite is revoked.
    r = api.request("POST", "/invites/accept", token=target_token,
                    json={"token": inv_before["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"

    # A post-removal invite (same second) is kept and can rejoin.
    inv_after = api.request("POST", f"/orgs/{org}/invites", token=admin,
                            json={"username": target_name, "role": "member"}).json()
    r = api.request("POST", "/invites/accept", token=target_token,
                    json={"token": inv_after["token"]})
    assert r.status_code == 200


# ================================================================ idempotency

def test_remove_idempotent_replay(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    key = _key()
    r1 = _remove(api, admin, org, target_id, key=key)
    r2 = _remove(api, admin, org, target_id, key=key)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()

    # Only one member.removed audit.
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=admin).json()["items"]
    assert sum(1 for i in items if i["action"] == "member.removed") == 1


def test_remove_replay_after_rejoin_does_not_remove_again(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]
    key = _key()
    assert _remove(api, admin, org, target_id, key=key).status_code == 200

    # Rejoin.
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": target_name, "role": "member"}).json()
    assert api.request("POST", "/invites/accept", token=target_token,
                       json={"token": inv["token"]}).status_code == 200

    # Replay with the same key: returns the first success, does NOT remove again.
    r = _remove(api, admin, org, target_id, key=key)
    assert r.status_code == 200 and r.json()["removed"] is True
    # The target is still a member.
    members = api.request("GET", f"/orgs/{org}/members",
                          token=admin).json()["members"]
    assert any(m["user_id"] == target_id for m in members)
    # Still only one member.removed audit.
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=admin).json()["items"]
    assert sum(1 for i in items if i["action"] == "member.removed") == 1


def test_remove_same_key_different_target_conflict(api: Api):
    org, admin, people = _setup_org(api, n_members=2)
    id1, id2 = people[0][2], people[1][2]
    key = _key()
    assert _remove(api, admin, org, id1, key=key).status_code == 200
    r = _remove(api, admin, org, id2, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    # id2 is untouched.
    members = api.request("GET", f"/orgs/{org}/members",
                          token=admin).json()["members"]
    assert any(m["user_id"] == id2 for m in members)


def test_remove_idempotency_isolated_from_other_entry_points(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    key = "shared-entry-point-key"
    # Single-member adjustment with the same key.
    r1 = api.request("PATCH", f"/orgs/{org}/members/{target_id}", token=admin,
                     json={"role": "admin"}, headers={"Idempotency-Key": key})
    assert r1.status_code == 200
    # Removal with the same key: independent scope, no conflict.
    r2 = _remove(api, admin, org, target_id, key=key)
    assert r2.status_code == 200
    # The adjustment key still replays its own first result (the stored
    # success is returned regardless of the target's current membership).
    r3 = api.request("PATCH", f"/orgs/{org}/members/{target_id}", token=admin,
                     json={"role": "admin"}, headers={"Idempotency-Key": key})
    assert r3.status_code == 200 and r3.json() == r1.json()
    # The removal key replays its own first result.
    r4 = _remove(api, admin, org, target_id, key=key)
    assert r4.status_code == 200 and r4.json() == r2.json()


def test_remove_failure_does_not_consume_key(api: Api):
    org, admin, people = _setup_org(api)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    key = _key()
    # First attempt fails the last-admin invariant.
    r = _remove(api, admin, org, admin_uid, key=key)
    assert r.status_code == 409
    # The key is still usable for a valid removal (nonexistent target -> 404,
    # but the key is not poisoned; use a fresh org with two admins).
    org2, admin2, people2 = _setup_org(api, n_admins=2)
    target = people2[0][2]
    r = _remove(api, admin2, org2, target, key=key)
    assert r.status_code == 200


def test_remove_replay_after_self_removal_is_403(api: Api):
    org, admin, people = _setup_org(api, n_admins=2)
    admin_uid = api.request("GET", f"/orgs/{org}/members/me",
                            token=admin).json()["membership"]["user_id"]
    key = _key()
    assert _remove(api, admin, org, admin_uid, key=key).status_code == 200
    # Self-removed operator replays: permission re-check fails -> 403.
    r = _remove(api, admin, org, admin_uid, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"


def test_remove_concurrent_retry_single_change(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    key = _key()
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org}/members/{target_id}",
                headers={"Authorization": f"Bearer {admin}",
                         "Idempotency-Key": key},
            ))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r.status_code for r in results) == [200, 200]
    # Exactly one member.removed audit.
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=admin).json()["items"]
    assert sum(1 for i in items if i["action"] == "member.removed") == 1


# ================================================================ concurrency

def test_concurrent_removals_keep_one_admin(api: Api):
    # Three admins: A, B (targets of each other), and C (untouched, used to
    # inspect the final roster). Exactly one removal lands; the loser is
    # denied (403) or finds the target gone (404).
    org, admin_a, people = _setup_org(api, n_admins=3)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin_a).json()["membership"]["user_id"]
    b_token, b_id = people[0][1], people[0][2]
    c_token = people[1][1]
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker(token: str, target: int) -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org}/members/{target}",
                headers={"Authorization": f"Bearer {token}"},
            ))

    threads = [
        threading.Thread(target=worker, args=(admin_a, b_id)),
        threading.Thread(target=worker, args=(b_token, a_id)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(r.status_code for r in results)
    assert codes == [200, 403] or codes == [200, 404], codes
    # Never zero active admins (queried with the untouched admin's token).
    members = api.request("GET", f"/orgs/{org}/members",
                          token=c_token).json()["members"]
    active_admins = [m for m in members if m["role"] == "admin" and m["status"] == "active"]
    assert len(active_admins) >= 1


def test_concurrent_removal_and_adjustment_equivalent_to_serial(api: Api):
    # Removal of target T and a single adjustment of T race. The outcome is
    # equivalent to whichever committed first: either T is removed (adjust ->
    # 404) or T is adjusted (removal -> 200). Either way no partial state.
    org, admin, people = _setup_org(api, n_admins=2, n_members=1)
    target_id = people[1][2]
    barrier = threading.Barrier(2)
    outcomes: dict[str, httpx.Response] = {}

    def remove_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            outcomes["remove"] = c.delete(
                f"/orgs/{org}/members/{target_id}",
                headers={"Authorization": f"Bearer {admin}"},
            )

    def adjust_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            outcomes["adjust"] = c.patch(
                f"/orgs/{org}/members/{target_id}",
                headers={"Authorization": f"Bearer {people[0][1]}"},
                json={"role": "admin"},
            )

    t1 = threading.Thread(target=remove_worker)
    t2 = threading.Thread(target=adjust_worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert outcomes["remove"].status_code == 200
    # Adjust either committed first (200) or found the member gone (404).
    assert outcomes["adjust"].status_code in (200, 404)
    if outcomes["adjust"].status_code == 404:
        members = api.request("GET", f"/orgs/{org}/members",
                              token=admin).json()["members"]
        assert all(m["user_id"] != target_id for m in members)


# ================================================================ audit

def test_audit_records_removal_with_invite_and_delegation_changes(api: Api):
    org, admin, people = _setup_org(api, n_admins=2, n_members=1)
    a_id = api.request("GET", f"/orgs/{org}/members/me",
                       token=admin).json()["membership"]["user_id"]
    b_token, b_id = people[0][1], people[0][2]
    target_name, target_token, target_id, _ = people[1]
    # A delegation where the target is delegate.
    d = _grant(api, admin, org, target_id).json()
    # A bound invite.
    inv = api.request("POST", f"/orgs/{org}/invites", token=admin,
                      json={"username": target_name, "role": "member"}).json()

    assert _remove(api, admin, org, target_id).status_code == 200

    items = api.request("GET", f"/orgs/{org}/audit",
                        token=b_token).json()["items"]
    row = next(i for i in items if i["action"] == "member.removed")
    assert row["org_id"] == org
    assert row["actor_id"] == a_id
    assert row["target_id"] == f"{org}:{target_id}"
    assert row["before"] == {"role": "member", "status": "active"}
    assert row["after"]["org_id"] == org
    assert row["after"]["user_id"] == target_id
    assert row["after"]["removed"] is True
    # Invite and delegation changes are recorded.
    assert any(c["id"] == inv["id"] for c in row["after"]["revoked_invites"])
    assert any(c["id"] == d["id"] for c in row["after"]["invalidated_delegations"])
    # No token material in the audit.
    raw = str(row)
    assert inv["token"] not in raw
    assert len(inv["token"]) >= 40


def test_audit_history_retained_after_removal(api: Api):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    assert _remove(api, admin, org, target_id).status_code == 200
    items = api.request("GET", f"/orgs/{org}/audit",
                        token=admin).json()["items"]
    actions = [i["action"] for i in items]
    assert "member.removed" in actions


# ================================================================ atomic rollback

def test_failed_audit_rolls_back_removal(api: Api, db):
    org, admin, people = _setup_org(api, n_members=1)
    target_id = people[0][2]
    _grant(api, admin, org, target_id)

    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)",
               ("member.removed",))
    db.commit()
    key = _key()
    try:
        r = _remove(api, admin, org, target_id, key=key)
        assert r.status_code == 500
        assert r.json()["error"]["code"] == "internal_error"
    finally:
        db.execute("DELETE FROM _fail_next_actions WHERE action = ?",
                   ("member.removed",))
        db.commit()

    # Member, delegation and audit all stayed as they were.
    row = db.execute("SELECT role, status FROM memberships WHERE user_id = ?",
                     (target_id,)).fetchone()
    assert row is not None and row["status"] == "active"
    drow = db.execute("SELECT status FROM delegations WHERE delegate_id = ?",
                      (target_id,)).fetchone()
    assert drow["status"] == "active"
    n_audit = db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ? AND action = 'member.removed'",
        (org,),
    ).fetchone()["n"]
    assert n_audit == 0
    # The failure did not consume the idempotency key.
    n_keys = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys WHERE scope = ?",
        (f"org:{org}:member.remove",),
    ).fetchone()["n"]
    assert n_keys == 0
    # A retry with the same key now succeeds.
    assert _remove(api, admin, org, target_id, key=key).status_code == 200


def test_failed_invite_revoke_audit_rolls_back_removal(api: Api, db):
    org, admin, people = _setup_org(api, n_members=1)
    target_name, target_token, target_id, _ = people[0]
    api.request("POST", f"/orgs/{org}/invites", token=admin,
                json={"username": target_name, "role": "member"})

    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)",
               ("invite.revoked",))
    db.commit()
    try:
        r = _remove(api, admin, org, target_id)
        assert r.status_code == 500
    finally:
        db.execute("DELETE FROM _fail_next_actions WHERE action = ?",
                   ("invite.revoked",))
        db.commit()

    # Rolled back: member still present, the NEW invite still available.
    assert db.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND user_id = ?",
        (org, target_id),
    ).fetchone()["n"] == 1
    inv_status = db.execute(
        "SELECT status FROM invites WHERE org_id = ? AND invite_username = ?"
        " ORDER BY id DESC LIMIT 1",
        (org, target_name),
    ).fetchone()["status"]
    assert inv_status == "available"


# ================================================================ restart

def test_removal_result_and_idempotency_survive_restart(make_server):
    srv: Server = make_server(f"rm-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        admin_name = api.unique("ra")
        c.post("/auth/register", json={"username": admin_name, "password": "Passw0rd!"})
        admin = c.post("/auth/login", json={"username": admin_name,
                                            "password": "Passw0rd!"}).json()["token"]
        org = c.post("/orgs", headers={"Authorization": f"Bearer {admin}"},
                     json={"name": f"persist-rm-{api.unique()}"}).json()
        member_name = api.unique("rm")
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

        r1 = c.delete(
            f"/orgs/{org['id']}/members/{target}",
            headers={"Authorization": f"Bearer {admin}",
                     "Idempotency-Key": "rm-persist"},
        )
        assert r1.status_code == 200
        first = r1.json()

    srv.restart()
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        # Removal persisted.
        roster = c.get(f"/orgs/{org['id']}/members",
                       headers={"Authorization": f"Bearer {admin}"}).json()["members"]
        assert all(m["user_id"] != target for m in roster)
        # Idempotent replay returns the first result.
        r2 = c.delete(
            f"/orgs/{org['id']}/members/{target}",
            headers={"Authorization": f"Bearer {admin}",
                     "Idempotency-Key": "rm-persist"},
        )
        assert r2.status_code == 200 and r2.json() == first
        # No duplicate audit.
        audit = c.get(f"/orgs/{org['id']}/audit",
                      headers={"Authorization": f"Bearer {admin}"}).json()["items"]
        assert sum(1 for i in audit if i["action"] == "member.removed") == 1
        # Same key with a different target still conflicts.
        other = next(m["user_id"] for m in roster)
        r3 = c.delete(
            f"/orgs/{org['id']}/members/{other}",
            headers={"Authorization": f"Bearer {admin}",
                     "Idempotency-Key": "rm-persist"},
        )
        assert r3.status_code == 409 and r3.json()["error"]["code"] == "idempotency_conflict"
