"""Target binding of Idempotency-Keys on the single-member PATCH endpoint.

A successfully used key belongs to the (operator, org, TARGET MEMBER, body)
combination. Reusing the key with the identical body against another member
must answer ``409 idempotency_conflict`` instead of replaying the first
member's response or performing a second adjustment — even when the new
target is not in the organization. The stored success stays replayable for
the original target, and authorization (401/403) is still re-checked first.
"""
from __future__ import annotations

import uuid

from tests.conftest import Api


def _key() -> str:
    return uuid.uuid4().hex


def _new_org(api: Api, prefix: str = "mk"):
    name, token = api.new_user()
    org = api.request("POST", "/orgs", token=token,
                      json={"name": f"{prefix}-{api.unique()}"}).json()
    return name, token, org


def _add_member(api: Api, admin_token: str, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    r = api.request("POST", "/invites/accept", token=token,
                    json={"token": inv["token"]})
    assert r.status_code == 200, r.text
    return name, token, r.json()["membership"]["user_id"]


def _member(api: Api, token: str, org_id: int, user_id: int) -> dict:
    rows = api.request("GET", f"/orgs/{org_id}/members", token=token).json()["members"]
    return next(m for m in rows if m["user_id"] == user_id)


def _audit_actions(api: Api, token: str, org_id: int) -> list[str]:
    items = api.request("GET", f"/orgs/{org_id}/audit?page=1&page_size=100",
                        token=token).json()["items"]
    return [i["action"] for i in items]


def _patch(api: Api, token: str, org_id: int, target_id: int, body: dict,
           *, key: str | None = None):
    headers = {"Idempotency-Key": key} if key is not None else {}
    return api.request("PATCH", f"/orgs/{org_id}/members/{target_id}",
                       token=token, json=body, headers=headers)


# ------------------------------------------------------------- the core bug

def test_key_reused_on_another_member_conflicts_and_changes_nothing(api: Api):
    _, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])
    _, _, b_id = _add_member(api, admin, org["id"])
    key, body = _key(), {"status": "disabled"}

    r1 = _patch(api, admin, org["id"], a_id, body, key=key)
    assert r1.status_code == 200, r1.text
    first = r1.json()
    assert first["membership"]["user_id"] == a_id
    assert first["membership"]["status"] == "disabled"

    b_before = _member(api, admin, org["id"], b_id)

    # Same key + byte-identical body, different target: 409, never A's data.
    r2 = _patch(api, admin, org["id"], b_id, body, key=key)
    assert r2.status_code == 409
    err = r2.json()["error"]
    assert err["code"] == "idempotency_conflict"
    assert "membership" not in r2.text
    assert str(a_id) not in r2.text

    # B was not adjusted at all (status and updated_at both untouched).
    b_after = _member(api, admin, org["id"], b_id)
    assert b_after["status"] == "active"
    assert b_after["updated_at"] == b_before["updated_at"]

    # Exactly one real adjustment, one audit row.
    assert _audit_actions(api, admin, org["id"]).count("member.updated") == 1

    # The stored success is intact: original key + body on A still replies
    # with the first result.
    r3 = _patch(api, admin, org["id"], a_id, body, key=key)
    assert r3.status_code == 200
    assert r3.json() == first


def test_conflict_works_even_when_new_target_is_not_in_the_org(api: Api):
    _, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])
    key, body = _key(), {"status": "disabled"}
    assert _patch(api, admin, org["id"], a_id, body, key=key).status_code == 200

    # Unknown user id in THIS org is rejected as a bound-key conflict, not a
    # fresh adjustment (200) and not a missing-member 404.
    r = _patch(api, admin, org["id"], 9_999_999, body, key=key)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency_conflict"
    assert "membership" not in r.text
    assert str(a_id) not in r.text

    # The original replay still works.
    assert _patch(api, admin, org["id"], a_id, body, key=key).status_code == 200


def test_conflict_does_not_invalidate_delegations(api: Api):
    _, admin, org = _new_org(api)
    _, _, delegate_id = _add_member(api, admin, org["id"])
    _, _, other_id = _add_member(api, admin, org["id"])
    g = api.request("POST", f"/orgs/{org['id']}/delegations", token=admin,
                    json={"user_id": delegate_id, "duration_seconds": 3600})
    assert g.status_code == 201, g.text

    key, body = _key(), {"status": "disabled"}
    assert _patch(api, admin, org["id"], other_id, body, key=key).status_code == 200

    # Replaying the key against the delegate is a pure conflict: the delegate
    # stays an active ordinary member and its delegation stays active.
    r = _patch(api, admin, org["id"], delegate_id, body, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    delegations = api.request("GET", f"/orgs/{org['id']}/delegations",
                              token=admin).json()["delegations"]
    assert len(delegations) == 1
    assert delegations[0]["delegate_id"] == delegate_id
    assert delegations[0]["status"] == "active"
    assert _member(api, admin, org["id"], delegate_id)["status"] == "active"
    assert "delegation.invalidated" not in _audit_actions(api, admin, org["id"])


# ---------------------------------------------------- same-target semantics

def test_same_target_replay_keeps_first_result_despite_later_change(api: Api):
    _, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])
    key, body = _key(), {"status": "disabled"}

    first = _patch(api, admin, org["id"], a_id, body, key=key)
    assert first.status_code == 200

    # A later, ordinary (keyless) change re-enables A.
    later = _patch(api, admin, org["id"], a_id, {"status": "active"})
    assert later.status_code == 200
    assert _member(api, admin, org["id"], a_id)["status"] == "active"

    # The replay returns the STORED result and must not roll A back.
    r = _patch(api, admin, org["id"], a_id, body, key=key)
    assert r.status_code == 200
    assert r.json() == first.json()
    assert r.json()["membership"]["status"] == "disabled"
    assert _member(api, admin, org["id"], a_id)["status"] == "active"
    assert _audit_actions(api, admin, org["id"]).count("member.updated") == 2


def test_same_target_different_body_remains_a_conflict(api: Api):
    _, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])
    key = _key()
    assert _patch(api, admin, org["id"], a_id, {"status": "disabled"},
                  key=key).status_code == 200
    r = _patch(api, admin, org["id"], a_id, {"role": "member"}, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
    # The first adjustment stands.
    assert _member(api, admin, org["id"], a_id)["status"] == "disabled"
    assert _audit_actions(api, admin, org["id"]).count("member.updated") == 1


def test_noop_success_still_binds_the_key_to_target(api: Api):
    _, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])  # already an ordinary member
    _, _, b_id = _add_member(api, admin, org["id"])
    a_before = _member(api, admin, org["id"], a_id)
    key, body = _key(), {"role": "member"}

    # Setting the member to their already-current state is still a successful
    # use of the key (no actual change, no audit row).
    r1 = _patch(api, admin, org["id"], a_id, body, key=key)
    assert r1.status_code == 200
    assert _member(api, admin, org["id"], a_id)["updated_at"] == a_before["updated_at"]
    assert "member.updated" not in _audit_actions(api, admin, org["id"])

    # ...so switching target with the same body must conflict.
    r2 = _patch(api, admin, org["id"], b_id, body, key=key)
    assert r2.status_code == 409 and r2.json()["error"]["code"] == "idempotency_conflict"
    assert _member(api, admin, org["id"], b_id)["role"] == "member"
    # The original no-op result is still replayable.
    r3 = _patch(api, admin, org["id"], a_id, body, key=key)
    assert r3.status_code == 200 and r3.json() == r1.json()


# ------------------------------------------------------- authorization first

def test_dead_session_on_target_switch_is_401_not_conflict(api: Api, db):
    from app.security import hash_token

    aname, admin, org = _new_org(api)
    _, _, a_id = _add_member(api, admin, org["id"])
    _, _, b_id = _add_member(api, admin, org["id"])
    key, body = _key(), {"status": "disabled"}
    assert _patch(api, admin, org["id"], a_id, body, key=key).status_code == 200

    # Kill the stored success's session directly.
    db.execute("UPDATE sessions SET revoked_at = 1 WHERE token_hash = ?",
               (hash_token(admin),))
    db.commit()

    r = _patch(api, admin, org["id"], b_id, body, key=key)
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    assert "membership" not in r.text
    # B untouched; with a fresh session the conflict is still enforced.
    new_token = api.token_for(aname)
    assert _member(api, new_token, org["id"], b_id)["status"] == "active"
    r = _patch(api, new_token, org["id"], b_id, body, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"


def test_non_admin_on_target_switch_is_403_not_conflict(api: Api):
    # Two admins: creator A and admin B. B performs the keyed adjustment...
    a_name, a_token = api.new_user()
    org = api.request("POST", "/orgs", token=a_token,
                      json={"name": f"m403-{api.unique()}"}).json()
    b_name, b_token = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=a_token,
                      json={"username": b_name, "role": "admin"})
    assert api.request("POST", "/invites/accept", token=b_token,
                       json={"token": inv.json()["token"]}).status_code == 200
    _, _, m_id = _add_member(api, a_token, org["id"])
    _, _, n_id = _add_member(api, a_token, org["id"])

    key, body = _key(), {"status": "disabled"}
    assert _patch(api, b_token, org["id"], m_id, body, key=key).status_code == 200

    # A demotes B to an ordinary member (keyless).
    members = api.request("GET", f"/orgs/{org['id']}/members",
                          token=a_token).json()["members"]
    b_id = next(m["user_id"] for m in members if m["username"] == b_name)
    assert _patch(api, a_token, org["id"], b_id, {"role": "member"}).status_code == 200

    # B replays the stored key against a DIFFERENT target: 403 (operator is
    # no longer an active admin), ahead of the target conflict.
    r = _patch(api, b_token, org["id"], n_id, body, key=key)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    assert "membership" not in r.text
    assert _member(api, a_token, org["id"], n_id)["status"] == "active"


# ------------------------------------------------------------- scope isolation

def test_key_stays_isolated_per_org_and_from_batch_endpoint(api: Api):
    _, admin = api.new_user()
    o1 = api.request("POST", "/orgs", token=admin,
                     json={"name": f"iso1-{api.unique()}"}).json()
    o2 = api.request("POST", "/orgs", token=admin,
                     json={"name": f"iso2-{api.unique()}"}).json()
    _, _, a_id = _add_member(api, admin, o1["id"])
    _, _, c_id = _add_member(api, admin, o2["id"])
    key, body = _key(), {"status": "disabled"}

    # Same operator, same key, same body, different org: independent success.
    assert _patch(api, admin, o1["id"], a_id, body, key=key).status_code == 200
    r = _patch(api, admin, o2["id"], c_id, body, key=key)
    assert r.status_code == 200 and r.json()["membership"]["user_id"] == c_id

    # The batch entry point owns a separate scope: the same key is free there.
    _, _, d_id = _add_member(api, admin, o1["id"])
    rb = api.request(
        "PATCH", f"/orgs/{o1['id']}/members/batch", token=admin,
        json={"changes": [{"user_id": d_id, "status": "disabled"}]},
        headers={"Idempotency-Key": key},
    )
    assert rb.status_code == 200, rb.text
    assert _member(api, admin, o1["id"], d_id)["status"] == "disabled"

    # Within org 1 the single-member key is still bound to A, not D.
    r = _patch(api, admin, o1["id"], d_id, body, key=key)
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"
