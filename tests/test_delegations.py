"""Temporary delegation of invite management.

An admin may grant one active ordinary member the right to issue member
invites and revoke their own invites for a bounded window (60..86400 s).
Delegation is permanent once invalidated (grantor/delegate eligibility
loss) and never revives on its own.
"""
from __future__ import annotations

import threading
import uuid

import httpx

from tests.conftest import Api, Server


def _key() -> str:
    return uuid.uuid4().hex


def _setup(api: Api):
    """Create an admin + their org. Returns (admin_token, org)."""
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin,
                      json={"name": f"del-{api.unique()}"}).json()
    return admin, org


def _add_member(api: Api, admin: str, org_id: int, role: str = "member"):
    """Register a user, invite them and accept. Returns (username, token, user_id)."""
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    me = api.request("GET", f"/orgs/{org_id}/members/me", token=token).json()["membership"]
    return name, token, me["user_id"]


def _grant(api: Api, admin: str, org_id: int, user_id: int,
           duration: int = 3600, key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin,
                       json={"user_id": user_id, "duration_seconds": duration},
                       headers=headers)


def _issue(api: Api, token: str, org_id: int, username: str, role: str = "member",
           key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("POST", f"/orgs/{org_id}/invites", token=token,
                       json={"username": username, "role": role}, headers=headers)


# ================================================================ grant basics

def test_grant_delegation_basic(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])

    r = _grant(api, admin, org["id"], member_id)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["org_id"] == org["id"]
    assert d["grantor_id"] > 0 and d["delegate_id"] == member_id
    assert d["status"] == "active"
    assert d["expires_at"] - d["starts_at"] == 3600
    assert d["starts_at"] == d["created_at"]

    # Delegate's role is still plain member.
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=member_token).json()["membership"]
    assert me["role"] == "member" and me["status"] == "active"

    # List shows it active.
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    assert any(x["id"] == d["id"] and x["status"] == "active" for x in lst)


def test_grant_duration_validation(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])

    for bad in (59, 86401):
        r = _grant(api, admin, org["id"], member_id, duration=bad)
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["error"]["code"] == "validation_error"

    # Strict int: floats and strings are 422, not silently coerced.
    for bad in (60.5, "60", True):
        r = api.request("POST", f"/orgs/{org['id']}/delegations", token=admin,
                        json={"user_id": member_id, "duration_seconds": bad})
        assert r.status_code == 422, (bad, r.text)

    # Boundaries are valid.
    for ok in (60, 86400):
        r = _grant(api, admin, org["id"], member_id, duration=ok)
        assert r.status_code == 201, (ok, r.text)
        # Clean up so the next boundary can grant.
        api.request("POST", f"/orgs/{org['id']}/delegations/{r.json()['id']}/revoke",
                    token=admin)


def test_grant_ineligible_member(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])

    # Nonexistent target.
    r = _grant(api, admin, org["id"], 999_999_999)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "ineligible_member"

    # Disabled member.
    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=admin,
                json={"status": "disabled"})
    r = _grant(api, admin, org["id"], member_id)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "ineligible_member"

    # Administrator (promote first).
    _, _, admin_id = _add_member(api, admin, org["id"])
    api.request("PATCH", f"/orgs/{org['id']}/members/{admin_id}", token=admin,
                json={"role": "admin"})
    r = _grant(api, admin, org["id"], admin_id)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "ineligible_member"


def test_grant_duplicate_delegation(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])

    r1 = _grant(api, admin, org["id"], member_id)
    assert r1.status_code == 201
    r2 = _grant(api, admin, org["id"], member_id)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "delegation_exists"

    # After revocation a fresh grant is allowed.
    api.request("POST", f"/orgs/{org['id']}/delegations/{r1.json()['id']}/revoke",
                token=admin)
    r3 = _grant(api, admin, org["id"], member_id)
    assert r3.status_code == 201

    # After expiry too: revoke the active one, then a fresh grant works.
    api.request("POST", f"/orgs/{org['id']}/delegations/{r3.json()['id']}/revoke", token=admin)
    assert _grant(api, admin, org["id"], member_id).status_code == 201


def test_grant_requires_admin(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    # A plain member cannot grant delegations.
    r = _grant(api, member_token, org["id"], member_id)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_grant_idempotent_replay(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])
    key = _key()

    r1 = _grant(api, admin, org["id"], member_id, duration=3600, key=key)
    r2 = _grant(api, admin, org["id"], member_id, duration=3600, key=key)
    assert r1.status_code == 201 and r2.status_code == 201
    # Same key + same body returns the ORIGINAL delegation, no extension.
    assert r1.json() == r2.json()

    # Different body with the same key conflicts.
    r3 = _grant(api, admin, org["id"], member_id, duration=7200, key=key)
    assert r3.status_code == 409
    assert r3.json()["error"]["code"] == "idempotency_conflict"

    # Only one delegation row exists.
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    assert len(lst) == 1


# ================================================================ delegate powers

def test_delegate_issues_member_invite(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    invitee, _ = api.new_user()
    r = _issue(api, member_token, org["id"], invitee)
    assert r.status_code == 201, r.text
    inv = r.json()
    assert inv["role"] == "member"
    assert inv["delegation_id"] == d["id"]

    # The invite works for the invitee.
    itok = api.token_for(invitee)
    r = api.request("POST", "/invites/accept", token=itok, json={"token": inv["token"]})
    assert r.status_code == 200

    # Audit records the delegate actor and the delegation link.
    audit = api.request("GET", f"/orgs/{org['id']}/audit", token=admin).json()["items"]
    created = [i for i in audit if i["action"] == "invite.created" and i["target_id"] == str(inv["id"])]
    assert len(created) == 1
    assert created[0]["actor_id"] == member_id
    assert created[0]["after"]["delegation_id"] == d["id"]


def test_delegate_cannot_issue_admin_invite(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    invitee, _ = api.new_user()
    r = _issue(api, member_token, org["id"], invitee, role="admin")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_delegate_revokes_own_invite(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    invitee, itok = api.new_user()
    inv = _issue(api, member_token, org["id"], invitee).json()
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": inv["token"]})
    assert r.status_code == 200 and r.json()["status"] == "revoked"

    # Invite is now unavailable.
    r = api.request("POST", "/invites/accept", token=itok, json={"token": inv["token"]})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "invite_unavailable"


def test_delegate_cannot_revoke_others_invites(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    # Admin's invite: delegate cannot revoke.
    invitee, _ = api.new_user()
    admin_inv = _issue(api, admin, org["id"], invitee).json()
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": admin_inv["token"]})
    assert r.status_code == 403

    # Another delegate's invite: cannot revoke.
    _, member2_token, member2_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member2_id)
    invitee2, _ = api.new_user()
    other_inv = _issue(api, member2_token, org["id"], invitee2).json()
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": other_inv["token"]})
    assert r.status_code == 403

    # Admin can still revoke both.
    assert api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin,
                       json={"token": admin_inv["token"]}).status_code == 200
    assert api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin,
                       json={"token": other_inv["token"]}).status_code == 200


def test_delegate_revoke_unavailable_invite(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    invitee, itok = api.new_user()
    inv = _issue(api, member_token, org["id"], invitee).json()
    # Use it first.
    assert api.request("POST", "/invites/accept", token=itok,
                       json={"token": inv["token"]}).status_code == 200
    # Delegate revoking an already-used invite -> existing 409 rule.
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": inv["token"]})
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "invite_unavailable"


def test_delegate_forbidden_ops(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    # Cannot adjust members.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=member_token,
                    json={"role": "admin"})
    assert r.status_code == 403
    # Cannot read audit.
    assert api.request("GET", f"/orgs/{org['id']}/audit", token=member_token).status_code == 403
    # Cannot grant delegations.
    assert _grant(api, member_token, org["id"], member_id).status_code == 403


# ================================================================ list visibility

def test_list_delegations_visibility(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    _, member2_token, member2_id = _add_member(api, admin, org["id"])
    d1 = _grant(api, admin, org["id"], member_id).json()
    d2 = _grant(api, admin, org["id"], member2_id).json()

    # Admin sees all.
    admin_lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                            token=admin).json()["delegations"]
    assert {x["id"] for x in admin_lst} == {d1["id"], d2["id"]}

    # Delegate sees only their own.
    m1_lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                         token=member_token).json()["delegations"]
    assert [x["id"] for x in m1_lst] == [d1["id"]]
    m2_lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                         token=member2_token).json()["delegations"]
    assert [x["id"] for x in m2_lst] == [d2["id"]]

    # Non-member / disabled / nonexistent org -> uniform 403.
    _, outsider = api.new_user()
    for token in (outsider,):
        assert api.request("GET", f"/orgs/{org['id']}/delegations",
                           token=token).status_code == 403
    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=admin,
                json={"status": "disabled"})
    assert api.request("GET", f"/orgs/{org['id']}/delegations",
                       token=member_token).status_code == 403
    assert api.request("GET", "/orgs/99999999/delegations",
                       token=outsider).status_code == 403


def test_list_delegations_statuses(api: Api, db):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])
    _, _, member2_id = _add_member(api, admin, org["id"])
    _, _, member3_id = _add_member(api, admin, org["id"])
    _, _, member4_id = _add_member(api, admin, org["id"])

    active = _grant(api, admin, org["id"], member_id).json()
    expired = _grant(api, admin, org["id"], member2_id).json()
    revoked = _grant(api, admin, org["id"], member3_id).json()
    invalidated = _grant(api, admin, org["id"], member4_id).json()

    # Expire one on disk.
    db.execute("UPDATE delegations SET expires_at = 0 WHERE id = ?", (expired["id"],))
    db.commit()
    # Revoke one.
    api.request("POST", f"/orgs/{org['id']}/delegations/{revoked['id']}/revoke", token=admin)
    # Invalidate one by disabling the delegate.
    api.request("PATCH", f"/orgs/{org['id']}/members/{member4_id}", token=admin,
                json={"status": "disabled"})

    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    by_id = {x["id"]: x for x in lst}
    assert by_id[active["id"]]["status"] == "active"
    assert by_id[expired["id"]]["status"] == "expired"
    assert by_id[revoked["id"]]["status"] == "revoked"
    inv = by_id[invalidated["id"]]
    assert inv["status"] == "invalidated"
    assert inv["reason"] == "delegate_ineligible"


# ================================================================ revoke delegation

def test_revoke_delegation(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    r = api.request("POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke", token=admin)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"
    assert r.json()["revoked_by"] > 0

    # Delegate can no longer issue invites.
    invitee, _ = api.new_user()
    assert _issue(api, member_token, org["id"], invitee).status_code == 403

    # Repeat revocation succeeds but writes no second audit.
    audit_before = api.request("GET", f"/orgs/{org['id']}/audit",
                               token=admin).json()["total"]
    r2 = api.request("POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke", token=admin)
    assert r2.status_code == 200
    assert r2.json()["status"] == "revoked"
    audit_after = api.request("GET", f"/orgs/{org['id']}/audit",
                              token=admin).json()["total"]
    assert audit_before == audit_after


def test_revoke_delegation_not_found(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])
    _grant(api, admin, org["id"], member_id)

    # Nonexistent delegation.
    r = api.request("POST", f"/orgs/{org['id']}/delegations/99999999/revoke", token=admin)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"

    # Delegation of another org.
    org2 = api.request("POST", "/orgs", token=admin,
                       json={"name": f"del2-{api.unique()}"}).json()
    _, _, member2_id = _add_member(api, admin, org2["id"])
    d2 = _grant(api, admin, org2["id"], member2_id).json()
    r = api.request("POST", f"/orgs/{org['id']}/delegations/{d2['id']}/revoke", token=admin)
    assert r.status_code == 404


def test_delegate_cannot_revoke_delegation(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()
    r = api.request("POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke",
                    token=member_token)
    assert r.status_code == 403


# ================================================================ invalidation

def test_invalidation_grantor_demoted(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    # Demote the grantor (the admin) to plain member. Need another admin.
    _, other_admin_token, other_admin_id = _add_member(api, admin, org["id"], role="admin")
    api.request("PATCH", f"/orgs/{org['id']}/members/{other_admin_id}", token=admin,
                json={"role": "admin"})
    # Now demote the original grantor.
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{me['user_id']}",
                    token=admin, json={"role": "member"})
    assert r.status_code == 200

    # Delegation is invalidated. Query with the remaining admin's token.
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=other_admin_token).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "grantor_not_admin"

    # Delegate can no longer issue invites.
    invitee, _ = api.new_user()
    assert _issue(api, member_token, org["id"], invitee).status_code == 403


def test_invalidation_delegate_disabled(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=admin,
                json={"status": "disabled"})

    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "delegate_ineligible"

    # Even after re-enabling, the delegation stays dead (permanent).
    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=admin,
                json={"status": "active"})
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"

    # A fresh grant is required and works.
    assert _grant(api, admin, org["id"], member_id).status_code == 201


def test_invalidation_delegate_demoted(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    # Promote to admin: delegate is no longer an ordinary member.
    api.request("PATCH", f"/orgs/{org['id']}/members/{member_id}", token=admin,
                json={"role": "admin"})
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    target = next(x for x in lst if x["id"] == d["id"])
    assert target["status"] == "invalidated"
    assert target["reason"] == "delegate_ineligible"


def test_idempotent_replay_requires_original_delegation(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    invitee, _ = api.new_user()
    key = _key()
    r1 = _issue(api, member_token, org["id"], invitee, key=key)
    assert r1.status_code == 201
    token1 = r1.json()["token"]

    # Invalidate the original delegation.
    api.request("POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke", token=admin)

    # Retry with the same key: original delegation is dead -> 403.
    r2 = _issue(api, member_token, org["id"], invitee, key=key)
    assert r2.status_code == 403

    # Even with a NEW delegation, the old key is still 403.
    _grant(api, admin, org["id"], member_id)
    r3 = _issue(api, member_token, org["id"], invitee, key=key)
    assert r3.status_code == 403

    # A brand-new key works.
    r4 = _issue(api, member_token, org["id"], invitee, key=_key())
    assert r4.status_code == 201
    assert r4.json()["token"] != token1


def test_expiry_boundary(api: Api, db):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id, duration=60).json()

    # Just before expiry the delegate can issue.
    invitee, _ = api.new_user()
    assert _issue(api, member_token, org["id"], invitee).status_code == 201

    # Force expiry to the current instant (and a bit beyond).
    db.execute("UPDATE delegations SET expires_at = ? WHERE id = ?", (0, d["id"]))
    db.commit()

    # From the expiry moment on, no authorization.
    invitee2, _ = api.new_user()
    r = _issue(api, member_token, org["id"], invitee2)
    assert r.status_code == 403

    # List shows expired.
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    assert next(x for x in lst if x["id"] == d["id"])["status"] == "expired"


def test_delegate_cannot_revoke_after_expiry(api: Api, db):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    invitee, _ = api.new_user()
    inv = _issue(api, member_token, org["id"], invitee).json()

    db.execute("UPDATE delegations SET expires_at = 0 WHERE id = ?", (d["id"],))
    db.commit()

    # Delegate can no longer revoke (past validity).
    r = api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=member_token,
                    json={"token": inv["token"]})
    assert r.status_code == 403

    # Admin still can.
    assert api.request("POST", f"/orgs/{org['id']}/invites/revoke", token=admin,
                       json={"token": inv["token"]}).status_code == 200


# ================================================================ concurrency

def test_concurrent_grant_one_active(api: Api):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])

    results: list[httpx.Response] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.post(
                f"/orgs/{org['id']}/delegations",
                headers={"Authorization": f"Bearer {admin}"},
                json={"user_id": member_id, "duration_seconds": 3600},
            ))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    codes = sorted(r.status_code for r in results)
    assert codes == [201, 409], codes
    for r in results:
        assert r.status_code == 201 or r.json()["error"]["code"] == "delegation_exists"
    # Exactly one active delegation.
    lst = api.request("GET", f"/orgs/{org['id']}/delegations",
                      token=admin).json()["delegations"]
    assert len([x for x in lst if x["status"] == "active"]) == 1


def test_concurrent_invite_and_revoke(api: Api):
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    invitee, _ = api.new_user()
    invite_result: list[httpx.Response] = []
    revoke_result: list[httpx.Response] = []
    barrier = threading.Barrier(2)

    def invite_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            invite_result.append(c.post(
                f"/orgs/{org['id']}/invites",
                headers={"Authorization": f"Bearer {member_token}"},
                json={"username": invitee, "role": "member"},
            ))

    def revoke_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            revoke_result.append(c.post(
                f"/orgs/{org['id']}/delegations/{d['id']}/revoke",
                headers={"Authorization": f"Bearer {admin}"},
            ))

    t1 = threading.Thread(target=invite_worker)
    t2 = threading.Thread(target=revoke_worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert revoke_result[0].status_code == 200
    inv_status = invite_result[0].status_code
    # Invite either completed before invalidation (201) or was rejected (403);
    # no partial write in either case.
    if inv_status == 201:
        inv = invite_result[0].json()
        assert inv["delegation_id"] == d["id"]
        # The invite still exists and is usable (delegation death does not
        # revoke issued invites).
        itok = api.token_for(invitee)
        assert api.request("POST", "/invites/accept", token=itok,
                           json={"token": inv["token"]}).status_code == 200
    else:
        assert inv_status == 403
        # No invite row was written.
        assert api.request("GET", f"/orgs/{org['id']}/delegations",
                           token=admin).status_code == 200


# ================================================================ restart

def test_delegation_survives_restart(make_server):
    srv: Server = make_server(f"deleg-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    admin, org = _setup(api)
    _, member_token, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id, duration=3600).json()

    invitee, _ = api.new_user()
    key = _key()
    inv = _issue(api, member_token, org["id"], invitee, key=key).json()

    srv.restart()

    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        # Delegation persisted and is still active.
        r = c.get(f"/orgs/{org['id']}/delegations",
                  headers={"Authorization": f"Bearer {admin}"})
        assert r.status_code == 200
        lst = r.json()["delegations"]
        assert any(x["id"] == d["id"] and x["status"] == "active" for x in lst)

        # Idempotent replay returns the original invite token.
        r = c.post(f"/orgs/{org['id']}/invites",
                   headers={"Authorization": f"Bearer {member_token}",
                            "Idempotency-Key": key},
                   json={"username": invitee, "role": "member"})
        assert r.status_code == 201
        assert r.json()["token"] == inv["token"]

        # Revocation persists.
        r = c.post(f"/orgs/{org['id']}/delegations/{d['id']}/revoke",
                   headers={"Authorization": f"Bearer {admin}"})
        assert r.status_code == 200
        r = c.get(f"/orgs/{org['id']}/delegations",
                  headers={"Authorization": f"Bearer {admin}"})
        assert next(x for x in r.json()["delegations"] if x["id"] == d["id"])["status"] == "revoked"


# ================================================================ atomic rollback

def test_failed_audit_rolls_back_delegation(api: Api, db):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])

    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)",
               ("delegation.created",))
    db.commit()
    try:
        r = _grant(api, admin, org["id"], member_id)
        assert r.status_code == 500
        assert r.json()["error"]["code"] == "internal_error"
    finally:
        db.execute("DELETE FROM _fail_next_actions WHERE action = ?",
                   ("delegation.created",))
        db.commit()

    # No delegation row was written.
    n = db.execute("SELECT COUNT(*) AS n FROM delegations WHERE org_id = ?",
                   (org["id"],)).fetchone()["n"]
    assert n == 0
    # The member is still eligible (no partial state).
    assert _grant(api, admin, org["id"], member_id).status_code == 201


def test_failed_audit_rolls_back_delegation_revoke(api: Api, db):
    admin, org = _setup(api)
    _, _, member_id = _add_member(api, admin, org["id"])
    d = _grant(api, admin, org["id"], member_id).json()

    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)",
               ("delegation.revoked",))
    db.commit()
    try:
        r = api.request("POST", f"/orgs/{org['id']}/delegations/{d['id']}/revoke",
                        token=admin)
        assert r.status_code == 500
    finally:
        db.execute("DELETE FROM _fail_next_actions WHERE action = ?",
                   ("delegation.revoked",))
        db.commit()

    # Delegation is still active (rollback).
    row = db.execute("SELECT status FROM delegations WHERE id = ?",
                     (d["id"],)).fetchone()["status"]
    assert row == "active"
