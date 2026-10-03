"""Member removal: DELETE /orgs/{org_id}/members/{user_id}.

Removal (unlike disable/enable) deletes the membership. These tests cover:

* authorization (active admins only; members/delegates/non-members -> 403,
  unknown org -> 403, anonymous -> 401), target lookup (404 member_not_found)
  and the last-active-administrator invariant (409 last_admin_required,
  self removal included);
* roster / own-org-list / all-sessions effects while the account, its
  sessions and other-organization memberships stay intact;
* usable username-bound invites are revoked (acceptance is 409), used/expired
  invites keep their rules, invites the target issued to others still work,
  and a fresh post-removal invite rejoins with the new role and join time;
* delegations touching the target as grantor/delegate are permanently
  invalidated with the existing reasons and never revive;
* the restore/single/batch adjustment entries cannot bring a removed member
  back (404, and a failed batch leaves every other member untouched);
* Idempotency-Key: replay returns the first result (no second removal even
  after rejoining), same key/different target is 409, the remove scope is
  independent of the adjustment scopes and of other orgs, self-removal
  retries are 403 and failures never occupy the key;
* audit detail without tokens, atomic rollback under audit fault injection,
* concurrency serialization (zero active admins and revoked-invite/
  invalidated-delegation authorization are impossible) and full restart
  persistence.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid

import httpx

from tests.conftest import Api, Server


# --------------------------------------------------------------- test helpers

def _key() -> str:
    return uuid.uuid4().hex


def _new_org(api: Api, prefix: str = "rm"):
    name, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    return name, token, org


def _org_with(api: Api, token: str, prefix: str = "rm"):
    """Create an organization owned by an already-authenticated admin."""
    return api.request("POST", "/orgs", token=token,
                       json={"name": f"{prefix}-{api.unique()}"}).json()


def _two_admins(api: Api):
    """Org with active admins A (creator) and B."""
    a_name, a_token = api.new_user()
    org = api.request("POST", "/orgs", token=a_token,
                      json={"name": f"rm2-{api.unique()}"}).json()
    b_name, b_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=a_token,
                      json={"username": b_name, "role": "admin"}).json()
    assert api.request("POST", "/invites/accept", token=b_token,
                       json={"token": inv["token"]}).status_code == 200
    ids = _member_ids(api, a_token, org["id"])
    return org, a_name, a_token, ids[a_name], b_name, b_token, ids[b_name]


def _add_member(api: Api, admin_token: str, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    return name, token, r.json()["membership"]["user_id"]


def _member_ids(api: Api, token: str, org_id: int) -> dict[str, int]:
    rows = api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]
    return {m["username"]: m["user_id"] for m in rows}


def _roster(api: Api, token: str, org_id: int) -> list[dict]:
    return api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]


def _issue(api: Api, token: str, org_id: int, username: str, role: str = "member",
           key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("POST", f"/orgs/{org_id}/invites", token=token,
                       json={"username": username, "role": role}, headers=headers)


def _remove(api: Api, token: str, org_id: int, user_id: int, key: str | None = None):
    headers = {"Idempotency-Key": key} if key else {}
    return api.request("DELETE", f"/orgs/{org_id}/members/{user_id}",
                       token=token, headers=headers)


def _grant(api: Api, admin_token: str, org_id: int, user_id: int, duration: int = 3600):
    return api.request("POST", f"/orgs/{org_id}/delegations", token=admin_token,
                       json={"user_id": user_id, "duration_seconds": duration})


def _audit_grouped(api: Api, token: str, org_id: int) -> dict[str, list[dict]]:
    items = api.request("GET", f"/orgs/{org_id}/audit?page=1&page_size=100",
                        token=token).json()["items"]
    grouped: dict[str, list[dict]] = {}
    for it in items:
        grouped.setdefault(it["action"], []).append(it)
    return grouped


def _arm(db, action: str) -> None:
    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)", (action,))
    db.commit()


def _disarm(db, action: str) -> None:
    db.execute("DELETE FROM _fail_next_actions WHERE action = ?", (action,))
    db.commit()


# ============================================================== basic results

def test_remove_returns_200_envelope_and_drops_member(api: Api):
    admin_name, admin, org = _new_org(api)
    tname, ttoken, tid = _add_member(api, admin, org["id"])

    r = _remove(api, admin, org["id"], tid)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": org["id"], "user_id": tid, "removed": True}

    # Gone from the roster (creator remains).
    members = _roster(api, admin, org["id"])
    assert [m["user_id"] for m in members] == [_member_ids(api, admin, org["id"])[admin_name]]

    # Gone from the target's own organization list.
    orgs = api.request("GET", "/orgs", token=ttoken).json()["organizations"]
    assert all(o["id"] != org["id"] for o in orgs)


def test_removed_member_all_sessions_denied_but_account_and_sessions_live(api: Api):
    _, admin, org = _new_org(api)
    tname, token1, tid = _add_member(api, admin, org["id"])
    token2 = api.token_for(tname)  # a second, independent session

    assert _remove(api, admin, org["id"], tid).status_code == 200

    for tok in (token1, token2):
        assert api.request("GET", f"/orgs/{org['id']}/members", token=tok).status_code == 403
        assert api.request("GET", f"/orgs/{org['id']}/members/me", token=tok).status_code == 403

    # The sessions still authenticate (account intact); a fresh login works.
    assert api.request("GET", "/orgs", token=token1).status_code == 200
    assert api.request("POST", "/auth/logout", token=token2).status_code == 200
    assert api.token_for(tname)


def test_other_organization_membership_unaffected(api: Api):
    _, admin1, o1 = _new_org(api, "rm-o1")
    _, admin2, o2 = _new_org(api, "rm-o2")
    tname, ttoken, tid1 = _add_member(api, admin1, o1["id"])
    inv2 = _issue(api, admin2, o2["id"], tname).json()
    assert api.request("POST", "/invites/accept", token=ttoken,
                       json={"token": inv2["token"]}).status_code == 200

    assert _remove(api, admin1, o1["id"], tid1).status_code == 200

    r = api.request("GET", f"/orgs/{o2['id']}/members/me", token=ttoken)
    assert r.status_code == 200 and r.json()["membership"]["status"] == "active"
    ids = {o["id"] for o in api.request("GET", "/orgs", token=ttoken).json()["organizations"]}
    assert o2["id"] in ids and o1["id"] not in ids


def test_remove_disabled_member_is_allowed(api: Api):
    _, admin, org = _new_org(api)
    tname, ttoken, tid = _add_member(api, admin, org["id"])
    assert api.request("PATCH", f"/orgs/{org['id']}/members/{tid}", token=admin,
                       json={"status": "disabled"}).status_code == 200

    r = _remove(api, admin, org["id"], tid)
    assert r.status_code == 200 and r.json()["removed"] is True
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=ttoken).status_code == 403


# ============================================================== authorization

def test_remove_authorization_rules(api: Api):
    org, _, a_token, _, b_name, _, b_id = _two_admins(api)
    m_name, m_token, m_id = _add_member(api, a_token, org["id"], "member")

    # Ordinary active member cannot remove.
    r = _remove(api, m_token, org["id"], b_id)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # A delegate (member with an active invitation delegation) cannot either.
    assert _grant(api, a_token, org["id"], m_id).status_code == 201
    r = _remove(api, m_token, org["id"], b_id)
    assert r.status_code == 403

    # Non-member and unknown organization: uniform 403.
    _, outsider = api.new_user()
    assert _remove(api, outsider, org["id"], b_id).status_code == 403
    assert _remove(api, a_token, 999999, b_id).status_code == 403

    # Anonymous: 401.
    r = api.request("DELETE", f"/orgs/{org['id']}/members/{b_id}")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Nothing was removed.
    usernames = {m["username"] for m in _roster(api, a_token, org["id"])}
    assert {b_name, m_name} <= usernames


def test_disabled_admin_cannot_remove_but_can_be_removed(api: Api):
    org, _, a_token, a_id, _, b_token, b_id = _two_admins(api)
    # A disables themselves (allowed: B stays active admin).
    assert api.request("PATCH", f"/orgs/{org['id']}/members/{a_id}", token=a_token,
                       json={"status": "disabled"}).status_code == 200
    # Disabled A is rejected even against the perfectly valid target B.
    assert _remove(api, a_token, org["id"], b_id).status_code == 403
    # B (still active admin) removes the disabled admin A.
    assert _remove(api, b_token, org["id"], a_id).status_code == 200


def test_remove_target_not_in_org_is_404(api: Api):
    _, admin, org = _new_org(api)
    r = _remove(api, admin, org["id"], 999999)
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"

    # An existing user from a organization of their own but not this one.
    other_name, other_token = api.new_user()
    other_org = _org_with(api, other_token, "rm-404")
    outsider_id = api.request("GET", f"/orgs/{other_org['id']}/members/me",
                              token=other_token).json()["membership"]["user_id"]
    r = _remove(api, admin, org["id"], outsider_id)
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"


def test_remove_last_active_admin_is_409(api: Api):
    # Sole admin removing themselves.
    _, admin, org = _new_org(api, "rm-la")
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]["user_id"]
    r = _remove(api, admin, org["id"], me)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"
    assert api.request("GET", f"/orgs/{org['id']}/members/me", token=admin).status_code == 200

    # The other admin exists but is DISABLED -> still the last active admin.
    org2, _, a2, a2_id, _, _, b2_id = _two_admins(api)
    assert api.request("PATCH", f"/orgs/{org2['id']}/members/{b2_id}", token=a2,
                       json={"status": "disabled"}).status_code == 200
    r = _remove(api, a2, org2["id"], a2_id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"
    # But the disabled admin may be removed, leaving A active.
    assert _remove(api, a2, org2["id"], b2_id).status_code == 200


def test_self_removal_allowed_with_second_admin(api: Api):
    org, _, a_token, a_id, _, b_token, b_id = _two_admins(api)
    r = _remove(api, a_token, org["id"], a_id)
    assert r.status_code == 200 and r.json()["removed"] is True
    # Immediate loss of access on the very same session.
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=a_token).status_code == 403
    active_admins = [m for m in _roster(api, b_token, org["id"])
                     if m["role"] == "admin" and m["status"] == "active"]
    assert [m["user_id"] for m in active_admins] == [b_id]


# ============================================================ restore / batch

def test_restore_and_adjustments_cannot_revive_removed_member(api: Api):
    _, admin, org = _new_org(api, "rm-rev")
    _, _, tid = _add_member(api, admin, org["id"])
    _, _, other_id = _add_member(api, admin, org["id"])
    assert _remove(api, admin, org["id"], tid).status_code == 200

    # The single-member adjustment/restore entry treats them as non-existent.
    for payload in ({"status": "active"}, {"role": "admin"},
                    {"role": "member", "status": "active"}):
        r = api.request("PATCH", f"/orgs/{org['id']}/members/{tid}", token=admin,
                        json=payload)
        assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"

    # A batch that mentions the removed member fails wholesale with 404 and
    # must not change any OTHER member.
    other_before = next(m for m in _roster(api, admin, org["id"])
                        if m["user_id"] == other_id)
    r = api.request("PATCH", f"/orgs/{org['id']}/members/batch", token=admin,
                    json={"changes": [
                        {"user_id": tid, "status": "active"},
                        {"user_id": other_id, "role": "admin"},
                    ]})
    assert r.status_code == 404 and r.json()["error"]["code"] == "member_not_found"
    other_after = next(m for m in _roster(api, admin, org["id"])
                       if m["user_id"] == other_id)
    assert other_after["role"] == other_before["role"]
    assert other_after["updated_at"] == other_before["updated_at"]


# ==================================================================== invites

def test_pending_invites_revoked_used_and_expired_keep_rules(api: Api, db):
    _, admin, org = _new_org(api, "rm-inv")
    tname, ttoken, tid = _add_member(api, admin, org["id"])
    used_id = db.execute(
        "SELECT id FROM invites WHERE org_id = ? AND invite_username = ? ORDER BY id",
        (org["id"], tname),
    ).fetchone()["id"]

    pending = _issue(api, admin, org["id"], tname, "admin").json()
    expired = _issue(api, admin, org["id"], tname).json()
    db.execute("UPDATE invites SET expires_at = 0 WHERE id = ?", (expired["id"],))
    db.commit()

    assert _remove(api, admin, org["id"], tid).status_code == 200

    # The still-usable invite was revoked; availability is checked first on
    # acceptance -> 409 invite_unavailable.
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (pending["id"],)).fetchone()["status"] == "revoked"
    r = api.request("POST", "/invites/accept", token=ttoken,
                    json={"token": pending["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"

    # Used stays used; the expired one is not re-stamped as revoked.
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (used_id,)).fetchone()["status"] == "used"
    erow = db.execute("SELECT status, expires_at FROM invites WHERE id = ?",
                      (expired["id"],)).fetchone()
    assert erow["status"] == "available" and erow["expires_at"] == 0
    r = api.request("POST", "/invites/accept", token=ttoken,
                    json={"token": expired["token"]})
    assert r.status_code == 409


def test_invite_issued_by_removed_admin_to_others_still_usable(api: Api):
    org, _, a_token, _, b_name, b_token, b_id = _two_admins(api)
    carol = api.unique("carol")
    inv = _issue(api, b_token, org["id"], carol, "member").json()
    assert _remove(api, a_token, org["id"], b_id).status_code == 200

    api.register(carol)
    r = api.request("POST", "/invites/accept", token=api.token_for(carol),
                    json={"token": inv["token"]})
    assert r.status_code == 200 and r.json()["membership"]["role"] == "member"


def test_fresh_invite_after_removal_rejoins_with_new_role_and_join_time(api: Api):
    _, admin, org = _new_org(api, "rm-rejoin")
    tname, ttoken, tid = _add_member(api, admin, org["id"], "admin")
    old = _issue(api, admin, org["id"], tname, "admin").json()
    ts_before = int(time.time())
    assert _remove(api, admin, org["id"], tid).status_code == 200

    # A fresh invite issued after the removal (same one-second window included)
    # rejoins with the NEW role and a freshly recorded join time.
    fresh = _issue(api, admin, org["id"], tname, "member").json()
    r = api.request("POST", "/invites/accept", token=ttoken,
                    json={"token": fresh["token"]})
    assert r.status_code == 200, r.text
    m = r.json()["membership"]
    assert m["user_id"] == tid and m["role"] == "member" and m["status"] == "active"
    assert m["created_at"] >= ts_before

    # The old invite is still revoked and cannot double-join.
    r = api.request("POST", "/invites/accept", token=ttoken,
                    json={"token": old["token"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invite_unavailable"


# ================================================================ delegations

def test_delegations_invalidated_for_delegate_and_grantor(api: Api):
    # Target as DELEGATE.
    _, admin, org = _new_org(api, "rm-d1")
    dname, dtoken, did = _add_member(api, admin, org["id"], "member")
    d = _grant(api, admin, org["id"], did).json()
    assert _remove(api, admin, org["id"], did).status_code == 200
    entry = next(x for x in api.request("GET", f"/orgs/{org['id']}/delegations",
                                        token=admin).json()["delegations"]
                 if x["id"] == d["id"])
    assert entry["status"] == "invalidated" and entry["reason"] == "delegate_ineligible"

    # Rejoin: the old delegation is not revived and the delegate cannot issue.
    fresh = _issue(api, admin, org["id"], dname, "member").json()
    assert api.request("POST", "/invites/accept", token=dtoken,
                       json={"token": fresh["token"]}).status_code == 200
    r = _issue(api, dtoken, org["id"], api.unique("x"))
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"

    # Target as GRANTOR: A grants on M, then B removes A.
    org2, _, a_token, a_id, _, b_token, _ = _two_admins(api)
    _, _, mid = _add_member(api, a_token, org2["id"], "member")
    d2 = _grant(api, a_token, org2["id"], mid).json()
    assert _remove(api, b_token, org2["id"], a_id).status_code == 200
    entry = next(x for x in api.request("GET", f"/orgs/{org2['id']}/delegations",
                                        token=b_token).json()["delegations"]
                 if x["id"] == d2["id"])
    assert entry["status"] == "invalidated" and entry["reason"] == "grantor_not_admin"


def test_invalidated_delegation_cannot_authorize_after_removal(api: Api):
    _, admin, org = _new_org(api, "rm-d2")
    dname, dtoken, did = _add_member(api, admin, org["id"])
    assert _grant(api, admin, org["id"], did).status_code == 201

    # The delegate issues an invite, then is removed (delegation invalidated).
    victim_name = api.unique("pre")
    issued = _issue(api, dtoken, org["id"], victim_name).json()
    assert _remove(api, admin, org["id"], did).status_code == 200

    # Rejoin and immediately try to issue again: no live delegation -> 403.
    fresh = _issue(api, admin, org["id"], dname).json()
    assert api.request("POST", "/invites/accept", token=dtoken,
                       json={"token": fresh["token"]}).status_code == 200
    assert _issue(api, dtoken, org["id"], api.unique("post")).status_code == 403

    # The invite issued BEFORE removal still follows the normal rules.
    api.register(victim_name)
    r = api.request("POST", "/invites/accept", token=api.token_for(victim_name),
                    json={"token": issued["token"]})
    assert r.status_code == 200


# ============================================================== idempotency

def test_remove_idempotent_replay_single_change_and_audit(api: Api):
    org, _, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    r1 = _remove(api, a_token, org["id"], b_id, key=key)
    r2 = _remove(api, a_token, org["id"], b_id, key=key)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json() == {
        "org_id": org["id"], "user_id": b_id, "removed": True}
    assert len(_audit_grouped(api, a_token, org["id"])["member.removed"]) == 1


def test_idempotent_replay_after_rejoin_does_not_remove_again(api: Api):
    _, admin, org = _new_org(api, "rm-ir")
    tname, ttoken, tid = _add_member(api, admin, org["id"])
    key = _key()
    assert _remove(api, admin, org["id"], tid, key=key).status_code == 200

    fresh = _issue(api, admin, org["id"], tname, "member").json()
    assert api.request("POST", "/invites/accept", token=ttoken,
                       json={"token": fresh["token"]}).status_code == 200

    # The stored success is returned but the rejoined membership survives.
    r = _remove(api, admin, org["id"], tid, key=key)
    assert r.status_code == 200 and r.json()["removed"] is True
    me = api.request("GET", f"/orgs/{org['id']}/members/me", token=ttoken)
    assert me.status_code == 200 and me.json()["membership"]["user_id"] == tid
    assert len(_audit_grouped(api, admin, org["id"])["member.removed"]) == 1


def test_same_key_different_target_is_conflict(api: Api):
    org, _, a_token, _, _, _, b_id = _two_admins(api)
    _, _, m_id = _add_member(api, a_token, org["id"], "member")
    key = _key()
    assert _remove(api, a_token, org["id"], m_id, key=key).status_code == 200
    r = _remove(api, a_token, org["id"], b_id, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    assert any(m["user_id"] == b_id for m in _roster(api, a_token, org["id"]))


def test_remove_key_independent_of_adjustments_and_other_orgs(api: Api):
    org, _, a_token, _, _, _, _ = _two_admins(api)
    _, _, m_id = _add_member(api, a_token, org["id"], "member")
    key = "shared-entry-key"

    # The single-member PATCH scope and the DELETE scope never collide.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{m_id}", token=a_token,
                    json={"role": "member"}, headers={"Idempotency-Key": key})
    assert r.status_code == 200
    patch_body = r.json()
    assert _remove(api, a_token, org["id"], m_id, key=key).status_code == 200
    # Replaying the PATCH key returns the PATCH's own stored result.
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{m_id}", token=a_token,
                    json={"role": "member"}, headers={"Idempotency-Key": key})
    assert r.status_code == 200 and r.json() == patch_body

    # Same key in a DIFFERENT organization (same operator) is independent.
    o2 = _org_with(api, a_token, "rm-iso")
    _, t2token, t2id = _add_member(api, a_token, o2["id"])
    assert _remove(api, a_token, o2["id"], t2id, key=key).status_code == 200
    assert api.request("GET", f"/orgs/{o2['id']}/members/me",
                       token=t2token).status_code == 403


def test_self_removal_idempotent_retry_is_403(api: Api):
    org, _, a_token, a_id, _, _, _ = _two_admins(api)
    key = _key()
    assert _remove(api, a_token, org["id"], a_id, key=key).status_code == 200
    r = _remove(api, a_token, org["id"], a_id, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"


def test_failed_removal_does_not_occupy_key(api: Api):
    # A 409 last-admin failure must not poison the key.
    _, admin, org = _new_org(api, "rm-fk")
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]["user_id"]
    key = _key()
    r = _remove(api, admin, org["id"], me, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin_required"

    org2 = _org_with(api, admin, "rm-fk2")
    _, _, tid = _add_member(api, admin, org2["id"])
    r = _remove(api, admin, org2["id"], tid, key=key)
    assert r.status_code == 200 and r.json()["removed"] is True

    # A 404 does not occupy the key either.
    key2 = _key()
    assert _remove(api, admin, org2["id"], 999999, key=key2).status_code == 404
    _, _, tid2 = _add_member(api, admin, org2["id"])
    assert _remove(api, admin, org2["id"], tid2, key=key2).status_code == 200


def test_concurrent_idempotent_removal_single_change(api: Api):
    org, _, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org['id']}/members/{b_id}",
                headers={"Authorization": f"Bearer {a_token}", "Idempotency-Key": key},
            ))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r.status_code for r in results) == [200, 200]
    assert len(_audit_grouped(api, a_token, org["id"])["member.removed"]) == 1


def test_concurrent_removal_same_target_without_keys(api: Api):
    org, _, a_token, _, _, b_token, b_id = _two_admins(api)
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker(token: str) -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org['id']}/members/{b_id}",
                headers={"Authorization": f"Bearer {token}"},
            ))

    threads = [threading.Thread(target=worker, args=(t,))
               for t in (a_token, b_token)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Serialized: exactly one 200. If B removes itself first, A later finds
    # the target gone (404); if A removes B first, B's own permission
    # re-check fails (403).
    codes = sorted(r.status_code for r in results)
    assert codes == [200, 403] or codes == [200, 404], codes
    loser = next(r for r in results if r.status_code != 200)
    assert loser.json()["error"]["code"] in ("forbidden", "member_not_found")


def test_concurrent_cross_removals_keep_one_active_admin(api: Api):
    org, _, a_token, a_id, _, b_token, b_id = _two_admins(api)
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def worker(token: str, target: int) -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org['id']}/members/{target}",
                headers={"Authorization": f"Bearer {token}"},
            ))

    threads = [
        threading.Thread(target=worker, args=(a_token, b_id)),
        threading.Thread(target=worker, args=(b_token, a_id)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Each removes the other: whoever commits first deletes the loser's
    # membership, so the loser's permission re-check is always 403 (the
    # target lookup is never reached). Never two 200s / zero admins.
    assert sorted(r.status_code for r in results) == [200, 403]
    for tok in (a_token, b_token):
        rr = api.request("GET", f"/orgs/{org['id']}/members", token=tok)
        if rr.status_code == 200:
            active_admins = [m for m in rr.json()["members"]
                             if m["role"] == "admin" and m["status"] == "active"]
            assert len(active_admins) == 1
            break
    else:  # pragma: no cover
        raise AssertionError("no surviving admin session")


def test_concurrent_remove_and_disable_batch_keep_one_active_admin(api: Api):
    org, _, a_token, a_id, _, b_token, b_id = _two_admins(api)
    barrier = threading.Barrier(2)
    results: list[httpx.Response] = []

    def remove_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.delete(
                f"/orgs/{org['id']}/members/{b_id}",
                headers={"Authorization": f"Bearer {a_token}"},
            ))

    def batch_worker() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results.append(c.request(
                "PATCH", f"/orgs/{org['id']}/members/batch",
                headers={"Authorization": f"Bearer {b_token}", "Content-Type": "application/json"},
                json={"changes": [{"user_id": a_id, "status": "disabled"}]},
            ))

    threads = [threading.Thread(target=remove_worker),
               threading.Thread(target=batch_worker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Whichever commits first, the serialized outcome keeps exactly one
    # active administrator: one 200 and one 403.
    assert sorted(r.status_code for r in results) == [200, 403]
    for tok in (a_token, b_token):
        rr = api.request("GET", f"/orgs/{org['id']}/members", token=tok)
        if rr.status_code == 200:
            active_admins = [m for m in rr.json()["members"]
                             if m["role"] == "admin" and m["status"] == "active"]
            assert len(active_admins) == 1
            break


def test_concurrent_remove_and_invite_accept_are_serialized(api: Api):
    _, admin, org = _new_org(api, "rm-race")
    tname, ttoken, tid = _add_member(api, admin, org["id"])
    pending = _issue(api, admin, org["id"], tname).json()
    barrier = threading.Barrier(2)
    results: dict[str, httpx.Response] = {}

    def remover() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results["remove"] = c.delete(
                f"/orgs/{org['id']}/members/{tid}",
                headers={"Authorization": f"Bearer {admin}"},
            )

    def accepter() -> None:
        with httpx.Client(base_url=api.base_url, timeout=30) as c:
            barrier.wait()
            results["accept"] = c.post(
                "/invites/accept",
                headers={"Authorization": f"Bearer {ttoken}", "Content-Type": "application/json"},
                json={"token": pending["token"]},
            )

    threads = [threading.Thread(target=remover), threading.Thread(target=accepter)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results["remove"].status_code == 200
    # accept-first -> already_member; remove-first -> invite unavailable.
    assert results["accept"].status_code == 409
    assert results["accept"].json()["error"]["code"] in (
        "already_member", "invite_unavailable")
    # The removed member is always gone in the end.
    assert all(m["user_id"] != tid for m in _roster(api, admin, org["id"]))


# ===================================================================== audit

def test_removal_audit_records_full_detail_without_tokens(api: Api):
    _, admin, org = _new_org(api, "rm-aud")
    tname, _, tid = _add_member(api, admin, org["id"], "member")
    pending = _issue(api, admin, org["id"], tname, "admin").json()
    d = _grant(api, admin, org["id"], tid).json()

    assert _remove(api, admin, org["id"], tid).status_code == 200

    grouped = _audit_grouped(api, admin, org["id"])
    row = grouped["member.removed"][0]
    assert row["target_type"] == "membership"
    assert row["target_id"] == f"{org['id']}:{tid}"
    assert row["before"]["username"] == tname
    assert row["before"] == {**row["before"], "role": "member", "status": "active"}
    assert row["after"]["user_id"] == tid
    assert pending["id"] in row["after"]["revoked_invite_ids"]
    assert [x["id"] for x in row["after"]["invalidated_delegations"]] == [d["id"]]

    deleg = grouped["delegation.invalidated"]
    assert len(deleg) == 1 and deleg[0]["after"]["reason"] == "delegate_ineligible"
    revocations = [x for x in grouped["invite.revoked"]
                   if x["after"].get("reason") == "member_removed"]
    assert len(revocations) == 1 and revocations[0]["target_id"] == str(pending["id"])

    assert pending["token"] not in str(grouped)


# ================================================================ atomicity

def test_failed_removal_audit_rolls_back_everything(api: Api, db):
    _, admin, org = _new_org(api, "rm-atom")
    tname, _, tid = _add_member(api, admin, org["id"])
    pending = _issue(api, admin, org["id"], tname).json()
    d = _grant(api, admin, org["id"], tid).json()

    _arm(db, "member.removed")
    try:
        r = _remove(api, admin, org["id"], tid, key="atomic-remove-key")
        assert r.status_code == 500
    finally:
        _disarm(db, "member.removed")

    mrow = db.execute("SELECT status FROM memberships WHERE org_id = ? AND user_id = ?",
                      (org["id"], tid)).fetchone()
    assert mrow is not None and mrow["status"] == "active"
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (pending["id"],)).fetchone()["status"] == "available"
    assert db.execute("SELECT status FROM delegations WHERE id = ?",
                      (d["id"],)).fetchone()["status"] == "active"
    # The failed operation's idempotency key was not stored (the shared
    # session database may hold keys from other tests, so scope the count).
    n = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE scope = ? AND idempotency_key = 'atomic-remove-key'",
        (f"org:{org['id']}:member.remove",),
    ).fetchone()["n"]
    assert n == 0

    # The exact same request now succeeds and performs the full removal.
    r = _remove(api, admin, org["id"], tid, key="atomic-remove-key")
    assert r.status_code == 200
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (pending["id"],)).fetchone()["status"] == "revoked"
    assert db.execute("SELECT status FROM delegations WHERE id = ?",
                      (d["id"],)).fetchone()["status"] == "invalidated"


def test_failed_delegation_audit_rolls_back_removal(api: Api, db):
    _, admin, org = _new_org(api, "rm-atom2")
    tname, _, tid = _add_member(api, admin, org["id"])
    pending = _issue(api, admin, org["id"], tname).json()
    assert _grant(api, admin, org["id"], tid).status_code == 201

    _arm(db, "delegation.invalidated")
    try:
        r = _remove(api, admin, org["id"], tid)
        assert r.status_code == 500
    finally:
        _disarm(db, "delegation.invalidated")

    # Membership deletion, invite revocation and the failure-triggered
    # invalidation all rolled back together.
    assert db.execute("SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?",
                      (org["id"], tid)).fetchone() is not None
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (pending["id"],)).fetchone()["status"] == "available"
    assert db.execute(
        "SELECT status FROM delegations WHERE org_id = ? AND delegate_id = ?",
        (org["id"], tid)).fetchone()["status"] == "active"

    assert _remove(api, admin, org["id"], tid).status_code == 200


# ============================================ session validity at commit time

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _revoke_session(db, token: str) -> None:
    db.execute("UPDATE sessions SET revoked_at = 1 WHERE token_hash = ?",
               (_token_hash(token),))


def _blocked_delete(api: Api, db, send, mutate) -> httpx.Response:
    """Run a DELETE ``send()`` while the database write lock is held.

    The request passes its arrival-time session check and then blocks on the
    write lock; ``mutate()`` runs under the lock and commits together with
    the lock release, so the DELETE's in-transaction session re-check
    observes the mutated state exactly as if the change had landed while the
    request was waiting for its turn to execute.
    """
    db.execute("BEGIN IMMEDIATE")
    out: dict[str, httpx.Response] = {}

    def worker() -> None:
        out["r"] = send()

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(1.0)  # let the request arrive and block on the write lock
    mutate()
    db.commit()
    t.join(timeout=30)
    return out["r"]


def test_session_revoked_while_waiting_is_401_and_removes_nothing(api: Api, db):
    aname, admin, org = _new_org(api, "rm-wait")
    tname, _, tid = _add_member(api, admin, org["id"])
    pending = _issue(api, admin, org["id"], tname).json()
    d = _grant(api, admin, org["id"], tid).json()
    key = _key()

    # The session is logged out while the DELETE waits for the write lock.
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, admin, org["id"], tid, key=key),
                        mutate=lambda: _revoke_session(db, admin))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Nothing happened: no removal, no invite revocation, no delegation
    # invalidation, no removal audit, and the key was not occupied.
    admin2 = api.token_for(aname)  # the account itself is fine; re-login works
    assert any(m["user_id"] == tid for m in _roster(api, admin2, org["id"]))
    assert db.execute("SELECT status FROM invites WHERE id = ?",
                      (pending["id"],)).fetchone()["status"] == "available"
    assert db.execute("SELECT status FROM delegations WHERE id = ?",
                      (d["id"],)).fetchone()["status"] == "active"
    assert "member.removed" not in _audit_grouped(api, admin2, org["id"])
    n = db.execute(
        "SELECT COUNT(*) AS n FROM idempotency_keys"
        " WHERE scope = ? AND idempotency_key = ?",
        (f"org:{org['id']}:member.remove", key),
    ).fetchone()["n"]
    assert n == 0

    # Re-logged-in and still an active admin: the same key now performs the
    # removal under the normal rules.
    r = _remove(api, admin2, org["id"], tid, key=key)
    assert r.status_code == 200 and r.json()["removed"] is True
    assert all(m["user_id"] != tid for m in _roster(api, admin2, org["id"]))


def test_session_expires_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api, "rm-exp")
    _, _, tid = _add_member(api, admin, org["id"])

    # The session is still valid when the request arrives, but its expiry
    # instant passes while the DELETE waits for the write lock.
    db.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
               (int(time.time()) + 2, _token_hash(admin)))
    db.commit()
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, admin, org["id"], tid),
                        mutate=lambda: time.sleep(3))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    admin2 = api.token_for(aname)
    assert any(m["user_id"] == tid for m in _roster(api, admin2, org["id"]))


def test_idempotent_replay_with_revoked_session_is_401(api: Api, db):
    org, aname, a_token, _, _, _, b_id = _two_admins(api)
    key = _key()
    assert _remove(api, a_token, org["id"], b_id, key=key).status_code == 200

    # A replay of the stored success whose carrying session was revoked
    # while waiting: 401, never the historical 200.
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, a_token, org["id"], b_id, key=key),
                        mutate=lambda: _revoke_session(db, a_token))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # The stored record is untouched: after a fresh login the same key
    # replays the original success and nothing is removed twice.
    a_token2 = api.token_for(aname)
    r = _remove(api, a_token2, org["id"], b_id, key=key)
    assert r.status_code == 200
    assert r.json() == {"org_id": org["id"], "user_id": b_id, "removed": True}
    assert len(_audit_grouped(api, a_token2, org["id"])["member.removed"]) == 1


def test_revoking_only_other_sessions_lets_removal_proceed(api: Api, db):
    aname, s1, org = _new_org(api, "rm-others")
    s2 = api.token_for(aname)  # a second, independent session of the same admin
    _, _, tid = _add_member(api, s1, org["id"])

    # Only the OTHER session is revoked while this request waits: this
    # session is still live, so the removal proceeds under the normal rules.
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, s1, org["id"], tid),
                        mutate=lambda: _revoke_session(db, s2))
    assert r.status_code == 200 and r.json()["removed"] is True
    assert all(m["user_id"] != tid for m in _roster(api, s1, org["id"]))


def test_invalid_session_is_401_regardless_of_target_or_org_state(api: Api, db):
    aname, admin, org = _new_org(api, "rm-prec")
    me = api.request("GET", f"/orgs/{org['id']}/members/me",
                     token=admin).json()["membership"]["user_id"]

    # Target not in the organization (a live session would get 404).
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, admin, org["id"], 999999),
                        mutate=lambda: _revoke_session(db, admin))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Unknown organization (a live session would get 403).
    admin2 = api.token_for(aname)
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, admin2, 999999, me),
                        mutate=lambda: _revoke_session(db, admin2))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # Last active administrator self-removal (a live session would get 409).
    admin3 = api.token_for(aname)
    r = _blocked_delete(api, db,
                        send=lambda: _remove(api, admin3, org["id"], me),
                        mutate=lambda: _revoke_session(db, admin3))
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    # The last admin is still in place and a fresh login works.
    admin4 = api.token_for(aname)
    assert api.request("GET", f"/orgs/{org['id']}/members/me",
                       token=admin4).status_code == 200


def test_x_session_token_header_revoked_while_waiting_is_401(api: Api, db):
    aname, admin, org = _new_org(api, "rm-xst")
    _, _, tid = _add_member(api, admin, org["id"])

    # Same rule when the session travels in X-Session-Token instead of
    # Authorization: Bearer.
    r = _blocked_delete(
        api, db,
        send=lambda: api.request("DELETE", f"/orgs/{org['id']}/members/{tid}",
                                 headers={"X-Session-Token": admin}),
        mutate=lambda: _revoke_session(db, admin),
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    admin2 = api.token_for(aname)
    assert any(m["user_id"] == tid for m in _roster(api, admin2, org["id"]))


# ================================================================ persistence

def test_removal_state_audit_and_idempotency_survive_restart(make_server):
    srv: Server = make_server(f"rm-restart-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        aname = api.unique("ra")
        c.post("/auth/register", json={"username": aname, "password": "Passw0rd!"})
        admin = c.post("/auth/login", json={"username": aname,
                                            "password": "Passw0rd!"}).json()["token"]
        org = c.post("/orgs", headers={"Authorization": f"Bearer {admin}"},
                     json={"name": f"persist-rm-{api.unique()}"}).json()
        tname = api.unique("rt")
        c.post("/auth/register", json={"username": tname, "password": "Passw0rd!"})
        ttoken = c.post("/auth/login", json={"username": tname,
                                             "password": "Passw0rd!"}).json()["token"]
        inv = c.post(f"/orgs/{org['id']}/invites",
                     headers={"Authorization": f"Bearer {admin}"},
                     json={"username": tname, "role": "member"}).json()
        c.post("/invites/accept", headers={"Authorization": f"Bearer {ttoken}"},
               json={"token": inv["token"]})
        tid = c.get(f"/orgs/{org['id']}/members/me",
                    headers={"Authorization": f"Bearer {ttoken}"}).json()["membership"]["user_id"]
        key = "restart-remove-key"
        r = c.delete(f"/orgs/{org['id']}/members/{tid}",
                     headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": key})
        assert r.status_code == 200 and r.json()["removed"] is True

    srv.restart()
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        # Removal persisted: the target is a non-member.
        assert c.get(f"/orgs/{org['id']}/members/me",
                     headers={"Authorization": f"Bearer {ttoken}"}).status_code == 403

        # Audit history persisted.
        actions = {i["action"] for i in c.get(
            f"/orgs/{org['id']}/audit?page=1&page_size=100",
            headers={"Authorization": f"Bearer {admin}"}).json()["items"]}
        assert "member.removed" in actions

        # Idempotency replay returns the stored result...
        r = c.delete(f"/orgs/{org['id']}/members/{tid}",
                     headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": key})
        assert r.status_code == 200 and r.json()["removed"] is True
        # ...and same key / different target still conflicts after restart.
        r = c.delete(f"/orgs/{org['id']}/members/999999",
                     headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": key})
        assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
