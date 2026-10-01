"""Temporary delegation of invite management.

Covers: grant validation (422/409), one-active-delegation rule, delegate
invite issue/revoke scope, uniform 403 for out-of-scope actions, expiry and
membership-change invalidation (permanent), admin list/revoke semantics,
idempotency (including replay bound to the original delegation), audit
content, and persistence across restart.
"""
from __future__ import annotations

import threading

from tests.conftest import Api


def _org_with_member(api: Api):
    """Return (admin_token, org_id, member_name, member_token, member_id)."""
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"dlg-{api.unique()}"}).json()
    member_name, member_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                      json={"username": member_name, "role": "member"}).json()
    api.request("POST", "/invites/accept", token=member_token,
                json={"token": inv["token"]})
    member_id = api.request("GET", f"/orgs/{org['id']}/members/me",
                            token=member_token).json()["membership"]["user_id"]
    return admin_token, org["id"], member_name, member_token, member_id


def _grant(api: Api, admin_token, org_id, member_id, ttl=3600, key=None):
    headers = {"Idempotency-Key": key} if key else None
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": member_id, "ttl_seconds": ttl},
                       headers=headers)


def _audit(api: Api, admin_token, org_id):
    return api.request("GET", f"/orgs/{org_id}/audit?page_size=100",
                       token=admin_token).json()["items"]


# ------------------------------------------------------------------- granting

def test_grant_delegation_happy_path(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    r = _grant(api, admin_token, org_id, member_id, ttl=600)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["org_id"] == org_id
    assert d["grantor_id"] != d["delegate_id"] == member_id
    assert d["expires_at"] - d["created_at"] == 600
    assert d["status"] == "active"
    # The delegate's membership role is untouched.
    m = api.request("GET", f"/orgs/{org_id}/members/me",
                    token=member_token).json()["membership"]
    assert m["role"] == "member"


def test_grant_ttl_validation(api: Api):
    admin_token, org_id, _, _, member_id = _org_with_member(api)
    for bad in (59, 86401, 0, -1, 60.5, "3600", True, None):
        r = _grant(api, admin_token, org_id, member_id, ttl=bad)
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["error"]["code"] == "validation_error"
    for ok in (60, 86400):
        # use a fresh org per ok-value to avoid delegation_exists
        a2, o2, _, _, mid2 = _org_with_member(api)
        assert _grant(api, a2, o2, mid2, ttl=ok).status_code == 201


def test_grant_ineligible_member_uniform_409(api: Api):
    admin_token, org_id, _, _, member_id = _org_with_member(api)
    # Unknown user
    r = _grant(api, admin_token, org_id, 999999)
    assert r.status_code == 409 and r.json()["error"]["code"] == "ineligible_member"
    # Admin target (the grantor themselves is an admin)
    admin_id = api.request("GET", f"/orgs/{org_id}/members/me",
                           token=admin_token).json()["membership"]["user_id"]
    r = _grant(api, admin_token, org_id, admin_id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "ineligible_member"
    # Disabled member
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                token=admin_token, json={"status": "disabled"})
    r = _grant(api, admin_token, org_id, member_id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "ineligible_member"


def test_grant_requires_admin_and_org_scope(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    # Plain member cannot grant
    r = _grant(api, member_token, org_id, member_id)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    # Non-member gets the same uniform 403 (also for unknown orgs)
    _, outsider = api.new_user()
    assert _grant(api, outsider, org_id, member_id).status_code == 403
    assert _grant(api, outsider, 999999, member_id).status_code == 403
    # No session -> 401
    assert _grant(api, None, org_id, member_id).status_code == 401


def test_one_active_delegation_per_member(api: Api):
    admin_token, org_id, _, _, member_id = _org_with_member(api)
    assert _grant(api, admin_token, org_id, member_id).status_code == 201
    r = _grant(api, admin_token, org_id, member_id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "delegation_exists"


def test_concurrent_grants_create_only_one(api: Api):
    admin_token, org_id, _, _, member_id = _org_with_member(api)
    results = []

    def grant():
        results.append(_grant(api, admin_token, org_id, member_id).status_code)

    threads = [threading.Thread(target=grant) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [201] + [409] * 7
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert len(ds) == 1


# ------------------------------------------------------------- delegate power

def test_delegate_issues_and_revokes_member_invites(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    assert _grant(api, admin_token, org_id, member_id).status_code == 201

    invitee_name, invitee_token = api.new_user()
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": invitee_name, "role": "member"})
    assert r.status_code == 201, r.text
    token = r.json()["token"]

    # Delegate revokes the invite they issued under this delegation.
    r = api.request("POST", f"/orgs/{org_id}/invites/revoke", token=member_token,
                    json={"token": token})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # Revoked invite can no longer be accepted.
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": token})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"

    # A fresh delegated invite can be accepted normally.
    invitee2, invitee2_token = api.new_user()
    inv2 = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                       json={"username": invitee2, "role": "member"}).json()
    r = api.request("POST", "/invites/accept", token=invitee2_token,
                    json={"token": inv2["token"]})
    assert r.status_code == 200
    assert r.json()["membership"]["role"] == "member"


def test_delegate_out_of_scope_is_uniform_403(api: Api):
    admin_token, org_id, other_name, member_token, member_id = _org_with_member(api)
    assert _grant(api, admin_token, org_id, member_id).status_code == 201

    # Cannot issue admin invites
    target, _ = api.new_user()
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": target, "role": "admin"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Cannot revoke an invite issued by the admin
    adm_inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                          json={"username": target, "role": "member"}).json()
    r = api.request("POST", f"/orgs/{org_id}/invites/revoke", token=member_token,
                    json={"token": adm_inv["token"]})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Cannot manage members, read audit, or re-delegate
    assert api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                       token=member_token, json={"role": "admin"}).status_code == 403
    assert api.request("GET", f"/orgs/{org_id}/audit",
                       token=member_token).status_code == 403
    assert _grant(api, member_token, org_id, member_id).status_code == 403


def test_delegate_cannot_revoke_invite_of_other_delegation(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d1 = _grant(api, admin_token, org_id, member_id).json()
    target, _ = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                      json={"username": target, "role": "member"}).json()
    # Rotate: revoke d1, grant a new delegation d2 to the same member.
    api.request("POST", f"/orgs/{org_id}/delegations/{d1['id']}/revoke",
                token=admin_token)
    assert _grant(api, admin_token, org_id, member_id).status_code == 201
    # The invite was issued under d1; d2 does not authorize revoking it.
    r = api.request("POST", f"/orgs/{org_id}/invites/revoke", token=member_token,
                    json={"token": inv["token"]})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    # The admin still can.
    assert api.request("POST", f"/orgs/{org_id}/invites/revoke", token=admin_token,
                       json={"token": inv["token"]}).status_code == 200


# --------------------------------------------------------------------- expiry

def test_expiry_ends_authorization_but_keeps_invites(api: Api, db):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id, ttl=60).json()
    invitee, invitee_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                      json={"username": invitee, "role": "member"}).json()
    invitee2, _ = api.new_user()
    inv2 = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                       json={"username": invitee2, "role": "member"}).json()

    # Force the delegation to expire.
    db.execute("UPDATE delegations SET expires_at = ? WHERE id = ?",
               (d["created_at"] - 1, d["id"]))
    db.commit()

    # No longer authorized.
    other, _ = api.new_user()
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": other, "role": "member"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    # Status reads as expired.
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert ds[0]["status"] == "expired" and ds[0]["reason"] == "expired"
    # Previously issued invites are unaffected: one is still accepted, and
    # the admin can still revoke the other.
    r = api.request("POST", "/invites/accept", token=invitee_token,
                    json={"token": inv["token"]})
    assert r.status_code == 200
    r = api.request("POST", f"/orgs/{org_id}/invites/revoke", token=admin_token,
                    json={"token": inv2["token"]})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    # A new delegation can be granted after expiry.
    assert _grant(api, admin_token, org_id, member_id).status_code == 201


# ------------------------------------------------- membership-change invalidation

def test_delegate_membership_change_invalidates_permanently(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id).json()

    # Disable the delegate -> delegation invalidated.
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                token=admin_token, json={"status": "disabled"})
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert ds[0]["status"] == "invalidated"
    assert ds[0]["reason"] == "delegate_not_active_member"

    # Restoring the member does NOT revive the delegation.
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                token=admin_token, json={"status": "active"})
    target, _ = api.new_user()
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": target, "role": "member"})
    assert r.status_code == 403
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert ds[0]["status"] == "invalidated"
    # Only a fresh grant authorizes again.
    assert _grant(api, admin_token, org_id, member_id).status_code == 201
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": target, "role": "member"})
    assert r.status_code == 201


def test_promoting_delegate_to_admin_invalidates(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    _grant(api, admin_token, org_id, member_id)
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                token=admin_token, json={"role": "admin"})
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert ds[0]["status"] == "invalidated"
    assert ds[0]["reason"] == "delegate_not_active_member"


def test_grantor_losing_admin_invalidates(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    # A second admin grants the delegation.
    grantor_name, grantor_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": grantor_name, "role": "admin"}).json()
    api.request("POST", "/invites/accept", token=grantor_token,
                json={"token": inv["token"]})
    grantor_id = api.request("GET", f"/orgs/{org_id}/members/me",
                             token=grantor_token).json()["membership"]["user_id"]
    d = _grant(api, grantor_token, org_id, member_id).json()
    assert d["grantor_id"] == grantor_id

    # Demote the grantor -> delegation invalidated.
    api.request("PATCH", f"/orgs/{org_id}/members/{grantor_id}",
                token=admin_token, json={"role": "member"})
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    dead = next(x for x in ds if x["id"] == d["id"])
    assert dead["status"] == "invalidated"
    assert dead["reason"] == "grantor_not_active_admin"
    # Delegate can no longer issue.
    target, _ = api.new_user()
    assert api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                       json={"username": target, "role": "member"}).status_code == 403


def test_delegation_does_not_relax_last_admin_rule(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    _grant(api, admin_token, org_id, member_id)
    admin_id = api.request("GET", f"/orgs/{org_id}/members/me",
                           token=admin_token).json()["membership"]["user_id"]
    r = api.request("PATCH", f"/orgs/{org_id}/members/{admin_id}",
                    token=admin_token, json={"role": "member"})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "last_admin_required"


# ------------------------------------------------------------- query & revoke

def test_list_delegations_scoping(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    _grant(api, admin_token, org_id, member_id)
    # Admin sees all; delegate sees only their own; stranger member of the
    # org sees an empty list; non-member gets 403.
    all_ds = api.request("GET", f"/orgs/{org_id}/delegations",
                         token=admin_token).json()["delegations"]
    assert len(all_ds) == 1
    own = api.request("GET", f"/orgs/{org_id}/delegations",
                      token=member_token).json()["delegations"]
    assert [d["id"] for d in own] == [all_ds[0]["id"]]

    other_name, other_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": other_name, "role": "member"}).json()
    api.request("POST", "/invites/accept", token=other_token,
                json={"token": inv["token"]})
    r = api.request("GET", f"/orgs/{org_id}/delegations", token=other_token)
    assert r.status_code == 200 and r.json()["delegations"] == []

    _, outsider = api.new_user()
    assert api.request("GET", f"/orgs/{org_id}/delegations",
                       token=outsider).status_code == 403
    assert api.request("GET", "/orgs/999999/delegations",
                       token=outsider).status_code == 403


def test_admin_revokes_delegation_idempotent_noop(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id).json()

    r = api.request("POST", f"/orgs/{org_id}/delegations/{d['id']}/revoke",
                    token=admin_token)
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert r.json()["reason"] == "revoked"

    # Delegate immediately loses authorization.
    target, _ = api.new_user()
    assert api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                       json={"username": target, "role": "member"}).status_code == 403

    # Repeat revoke: success, no duplicate audit row.
    r = api.request("POST", f"/orgs/{org_id}/delegations/{d['id']}/revoke",
                    token=admin_token)
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    revoked = [i for i in _audit(api, admin_token, org_id)
               if i["action"] == "delegation.revoked"]
    assert len(revoked) == 1

    # Unknown id and another org's delegation: uniform 404 for the admin.
    r = api.request("POST", f"/orgs/{org_id}/delegations/999999/revoke",
                    token=admin_token)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"

    admin2_token, org2, _, _, mid2 = _org_with_member(api)
    d2 = _grant(api, admin2_token, org2, mid2).json()
    r = api.request("POST", f"/orgs/{org_id}/delegations/{d2['id']}/revoke",
                    token=admin_token)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"

    # Non-admin cannot revoke at all (uniform 403).
    assert api.request("POST", f"/orgs/{org_id}/delegations/{d2['id']}/revoke",
                       token=member_token).status_code == 403


# ----------------------------------------------------------------- idempotency

def test_delegation_create_idempotent_replay(api: Api):
    admin_token, org_id, _, _, member_id = _org_with_member(api)
    r1 = _grant(api, admin_token, org_id, member_id, key="dlg-key-1")
    assert r1.status_code == 201
    r2 = _grant(api, admin_token, org_id, member_id, key="dlg-key-1")
    assert r2.status_code == 201 and r2.json() == r1.json()
    # Same key, different body -> conflict.
    r3 = _grant(api, admin_token, org_id, member_id, ttl=600, key="dlg-key-1")
    assert r3.status_code == 409
    assert r3.json()["error"]["code"] == "idempotency_conflict"
    # Only one delegation and one audit row exist.
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert len(ds) == 1
    created = [i for i in _audit(api, admin_token, org_id)
               if i["action"] == "delegation.created"]
    assert len(created) == 1


def test_delegated_invite_replay_bound_to_original_delegation(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d1 = _grant(api, admin_token, org_id, member_id).json()
    target, _ = api.new_user()
    body = {"username": target, "role": "member"}
    r1 = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                     json=body, headers={"Idempotency-Key": "inv-dlg-1"})
    assert r1.status_code == 201
    # Same-key replay while the delegation is valid returns the same invite.
    r2 = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                     json=body, headers={"Idempotency-Key": "inv-dlg-1"})
    assert r2.status_code == 201 and r2.json()["token"] == r1.json()["token"]

    # Revoke the delegation and grant a NEW one to the same member: the
    # replay must still be bound to the (now dead) original delegation.
    api.request("POST", f"/orgs/{org_id}/delegations/{d1['id']}/revoke",
                token=admin_token)
    assert _grant(api, admin_token, org_id, member_id).status_code == 201
    r3 = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                     json=body, headers={"Idempotency-Key": "inv-dlg-1"})
    assert r3.status_code == 403 and r3.json()["error"]["code"] == "forbidden"


# ----------------------------------------------------------------------- audit

def test_delegation_audit_trail(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id).json()

    target, _ = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                      json={"username": target, "role": "member"}).json()
    api.request("POST", f"/orgs/{org_id}/invites/revoke", token=member_token,
                json={"token": inv["token"]})
    api.request("POST", f"/orgs/{org_id}/delegations/{d['id']}/revoke",
                token=admin_token)

    items = _audit(api, admin_token, org_id)
    by_action = {}
    for i in items:
        by_action.setdefault(i["action"], []).append(i)

    created = by_action["delegation.created"][0]
    assert created["actor_id"] != member_id
    assert created["after"]["delegate_id"] == member_id
    assert created["after"]["status"] == "active"

    icreated = next(i for i in by_action["invite.created"]
                    if i["after"].get("delegation_id") == d["id"])
    assert icreated["actor_id"] == member_id  # actual operator recorded

    irevoked = next(i for i in by_action["invite.revoked"]
                    if i["after"].get("delegation_id") == d["id"])
    assert irevoked["actor_id"] == member_id
    assert irevoked["before"]["status"] == "available"
    assert irevoked["after"]["status"] == "revoked"

    revoked = by_action["delegation.revoked"][0]
    assert revoked["before"]["status"] == "active"
    assert revoked["after"]["status"] == "revoked"
    assert revoked["target_id"] == str(d["id"])


def test_membership_change_invalidation_audited(api: Api):
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id).json()
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}",
                token=admin_token, json={"status": "disabled"})
    inv = [i for i in _audit(api, admin_token, org_id)
           if i["action"] == "delegation.invalidated"]
    assert len(inv) == 1
    assert inv[0]["target_id"] == str(d["id"])
    assert inv[0]["before"]["status"] == "active"
    assert inv[0]["after"]["status"] == "invalidated"
    assert inv[0]["after"]["reason"] == "delegate_not_active_member"


# --------------------------------------------------------------------- restart

def test_delegations_survive_restart(make_server):
    srv = make_server("delegation")
    api = Api(srv.base_url)
    admin_token, org_id, _, member_token, member_id = _org_with_member(api)
    d = _grant(api, admin_token, org_id, member_id, key="restart-key").json()
    target, _ = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                      json={"username": target, "role": "member"},
                      headers={"Idempotency-Key": "restart-inv"}).json()

    srv.restart()

    # Delegation state and idempotency records persist.
    ds = api.request("GET", f"/orgs/{org_id}/delegations",
                     token=admin_token).json()["delegations"]
    assert [x["id"] for x in ds] == [d["id"]] and ds[0]["status"] == "active"
    r = _grant(api, admin_token, org_id, member_id, key="restart-key")
    assert r.status_code == 201 and r.json()["id"] == d["id"]
    r = api.request("POST", f"/orgs/{org_id}/invites", token=member_token,
                    json={"username": target, "role": "member"},
                    headers={"Idempotency-Key": "restart-inv"})
    assert r.status_code == 201 and r.json()["token"] == inv["token"]
