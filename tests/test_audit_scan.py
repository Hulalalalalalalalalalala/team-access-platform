"""Audit scan: stable-range cursor pagination, per-batch auth, cursor validation.

The scan endpoint (GET /orgs/{org_id}/audit/scan) fixes its range on the
FIRST request: only audit rows already committed at that instant are
visible. Later requests walk the range with an opaque cursor. These tests
cover range stability, id ordering, idempotent replay, per-batch
authorization, cursor forgery/cross-org rejection and the read-only
guarantee.
"""
from __future__ import annotations

from tests.conftest import Api


def _new_org(api: Api, token, name: str | None = None) -> int:
    org = api.request("POST", "/orgs", token=token,
                      json={"name": name or f"scan-{api.unique()}"}).json()
    return org["id"]


def _invite_member(api: Api, admin_token, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    return name, token


def _walk(api: Api, org_id: int, token, page_size: int = 20, cursor: str | None = None):
    """Yield (response_json, cursor) pages until next_cursor is null."""
    while True:
        r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=token,
                        params={"page_size": page_size, "cursor": cursor}
                        if cursor is not None else {"page_size": page_size})
        assert r.status_code == 200, r.text
        data = r.json()
        yield data
        cursor = data["next_cursor"]
        if cursor is None:
            break


# ------------------------------------------------------------- basic shape

def test_scan_first_page_fields_and_total(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)

    data = next(_walk(api, org_id, admin_token))
    assert data["total"] == 1
    assert data["next_cursor"] is None
    item = data["items"][0]
    # Every public field of the existing audit entry is present.
    assert set(item) == {
        "id", "org_id", "created_at", "actor_id", "actor_username", "action",
        "target_type", "target_id", "before", "after", "batch_id",
    }
    assert item["org_id"] == org_id
    assert item["action"] == "org.created"
    assert item["actor_username"]
    assert isinstance(item["created_at"], int)


def test_scan_matches_paged_endpoint_fields(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_id)

    paged = api.request("GET", f"/orgs/{org_id}/audit", token=admin_token).json()
    scanned = next(_walk(api, org_id, admin_token))
    assert scanned["total"] == paged["total"]
    assert [i["id"] for i in scanned["items"]] == [i["id"] for i in paged["items"]]
    for a, b in zip(scanned["items"], paged["items"]):
        assert a == b


def test_scan_default_page_size_is_20(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    # 3 audits: org.created, invite.created, invite.accepted
    _invite_member(api, admin_token, org_id)

    data = next(_walk(api, org_id, admin_token))
    assert len(data["items"]) == 3
    assert data["next_cursor"] is None


# ------------------------------------------------------------- pagination

def test_scan_walks_every_record_exactly_once_in_id_order(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    for _ in range(3):
        _invite_member(api, admin_token, org_id)

    pages = list(_walk(api, org_id, admin_token, page_size=1))
    assert all(p["total"] == 7 for p in pages)  # 1 org + 3*(invite+accept)
    ids = [i["id"] for p in pages for i in p["items"]]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids)) == 7
    assert pages[-1]["next_cursor"] is None


def test_scan_last_batch_exactly_page_size_ends(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_id)  # 3 audits

    pages = list(_walk(api, org_id, admin_token, page_size=3))
    assert len(pages) == 1
    assert len(pages[0]["items"]) == 3
    assert pages[0]["next_cursor"] is None


def test_scan_change_page_size_between_batches(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    for _ in range(3):
        _invite_member(api, admin_token, org_id)  # 7 audits

    r1 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2}).json()
    assert len(r1["items"]) == 2 and r1["next_cursor"]
    r2 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 4, "cursor": r1["next_cursor"]}).json()
    assert len(r2["items"]) == 4 and r2["next_cursor"]
    r3 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 4, "cursor": r2["next_cursor"]}).json()
    assert len(r3["items"]) == 1 and r3["next_cursor"] is None
    ids = [i["id"] for i in r1["items"] + r2["items"] + r3["items"]]
    assert ids == sorted(ids) and len(set(ids)) == 7


def test_scan_same_timestamp_still_ordered_by_id(api: Api):
    # Audit ordering is by id (commit order), never by timestamp: even rows
    # sharing the same second must walk in strict id order.
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    for _ in range(4):
        _invite_member(api, admin_token, org_id)

    pages = list(_walk(api, org_id, admin_token, page_size=2))
    ids = [i["id"] for p in pages for i in p["items"]]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids)) == 9


# ------------------------------------------------------------- range stability

def test_scan_excludes_audits_committed_after_start(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_id)  # 3 audits

    # Fix the range with page_size=2: 2 items, cursor for the 3rd.
    r1 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2}).json()
    assert r1["total"] == 3  # range fixed at all 3 committed rows
    assert len(r1["items"]) == 2 and r1["next_cursor"]

    # New audits commit AFTER the scan started.
    _invite_member(api, admin_token, org_id)
    _invite_member(api, admin_token, org_id)

    # Continuing reads only the fixed range: the remaining original row,
    # never the new ones.
    r2 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2, "cursor": r1["next_cursor"]}).json()
    assert r2["total"] == 3
    assert len(r2["items"]) == 1
    assert r2["items"][0]["id"] > r1["items"][-1]["id"]
    assert r2["next_cursor"] is None

    # A fresh scan (no cursor) starts a new range including later rows.
    r3 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 50}).json()
    assert r3["total"] == 7
    assert len(r3["items"]) == 7


def test_scan_unaffected_by_other_orgs(api: Api):
    _, admin_token = api.new_user()
    org_a = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_a)  # 3 audits in A

    r1 = api.request("GET", f"/orgs/{org_a}/audit/scan", token=admin_token,
                     params={"page_size": 2}).json()
    assert r1["total"] == 3 and r1["next_cursor"]

    # Lots of activity in another org while A's scan is in progress.
    org_b = _new_org(api, admin_token)
    for _ in range(5):
        _invite_member(api, admin_token, org_b)

    r2 = api.request("GET", f"/orgs/{org_a}/audit/scan", token=admin_token,
                     params={"page_size": 2, "cursor": r1["next_cursor"]}).json()
    assert r2["total"] == 3
    assert len(r2["items"]) == 1
    assert r2["next_cursor"] is None
    assert {i["org_id"] for i in r2["items"]} == {org_a}


def test_scan_replay_cursor_is_idempotent(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    for _ in range(2):
        _invite_member(api, admin_token, org_id)  # 5 audits

    # First page (no cursor).
    r1 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2}).json()
    assert len(r1["items"]) == 2 and r1["next_cursor"]

    # Second page with the cursor.
    r2 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2, "cursor": r1["next_cursor"]}).json()
    assert len(r2["items"]) == 2 and r2["next_cursor"]

    # Replaying the SAME cursor + page_size returns the SAME items and the
    # SAME next cursor: progress is not consumed.
    r2_again = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                           params={"page_size": 2, "cursor": r1["next_cursor"]}).json()
    assert r2_again == r2

    # Continue to the end; every record appears exactly once.
    r3 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 2, "cursor": r2["next_cursor"]}).json()
    assert len(r3["items"]) == 1 and r3["next_cursor"] is None
    ids = [i["id"] for i in r1["items"] + r2["items"] + r3["items"]]
    assert ids == sorted(ids) and len(set(ids)) == 5


def test_scan_empty_range(api: Api, db):
    # An organization that exists (with an admin membership) but has never
    # produced an audit row.
    name = api.unique()
    r = api.register(name)
    assert r.status_code == 201, r.text
    uid = r.json()["user"]["id"]
    token = api.token_for(name)
    cur = db.execute(
        "INSERT INTO organizations (name, created_by, created_at) VALUES (?, ?, ?)",
        (api.unique(), uid, 1000),
    )
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO memberships (org_id, user_id, role, status, created_at, updated_at)"
        " VALUES (?, ?, 'admin', 'active', 1000, 1000)",
        (org_id, uid),
    )
    db.commit()

    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=token)
    assert r.status_code == 200, r.text
    assert r.json() == {"items": [], "total": 0, "next_cursor": None}


def test_scan_creates_no_audit(api: Api, db):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_id)

    before = db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ?", (org_id,)
    ).fetchone()["n"]
    list(_walk(api, org_id, admin_token, page_size=1))
    after = db.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ?", (org_id,)
    ).fetchone()["n"]
    assert after == before


# ------------------------------------------------------------- authorization

def test_scan_requires_session(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    r = api.request("GET", f"/orgs/{org_id}/audit/scan")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_scan_forbidden_for_non_admin(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _, member_token = _invite_member(api, admin_token, org_id)
    _, outsider_token = api.new_user()

    for token in (member_token, outsider_token):
        r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=token)
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "forbidden"

    # Disabled member.
    member_id = api.request("GET", f"/orgs/{org_id}/members/me",
                            token=member_token).json()["membership"]["user_id"]
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}", token=admin_token,
                json={"status": "disabled"})
    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=member_token)
    assert r.status_code == 403

    # Removed member.
    api.request("DELETE", f"/orgs/{org_id}/members/{member_id}", token=admin_token)
    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=member_token)
    assert r.status_code == 403


def test_scan_forbidden_for_missing_org(api: Api):
    _, admin_token = api.new_user()
    r = api.request("GET", "/orgs/999999/audit/scan", token=admin_token)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"


def test_scan_demoted_admin_cannot_continue(api: Api):
    _, admin_a = api.new_user()
    org_id = _new_org(api, admin_a)
    # Promote B to admin so A can be demoted while the org keeps an admin.
    _, admin_b = _invite_member(api, admin_a, org_id)
    member_id = api.request("GET", f"/orgs/{org_id}/members/me",
                            token=admin_b).json()["membership"]["user_id"]
    api.request("PATCH", f"/orgs/{org_id}/members/{member_id}", token=admin_a,
                json={"role": "admin"})

    # A starts a scan and gets a cursor.
    r1 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_a,
                     params={"page_size": 1}).json()
    assert r1["next_cursor"]

    # B demotes A to member.
    a_id = api.request("GET", "/orgs", token=admin_a).json()  # noqa: F841
    me = api.request("GET", f"/orgs/{org_id}/members/me",
                     token=admin_a).json()["membership"]["user_id"]
    api.request("PATCH", f"/orgs/{org_id}/members/{me}", token=admin_b,
                json={"role": "member"})

    # A's cursor no longer works: permission is re-checked every batch.
    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_a,
                    params={"page_size": 1, "cursor": r1["next_cursor"]})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"

    # B, still an admin, continues the SAME range with A's cursor.
    r2 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_b,
                     params={"page_size": 1, "cursor": r1["next_cursor"]})
    assert r2.status_code == 200, r2.text
    assert r2.json()["total"] == r1["total"]


# ------------------------------------------------------------- cursor errors

def test_scan_garbage_cursor_rejected(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                    params={"cursor": "not-a-cursor"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_tampered_cursor_rejected(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_id)
    r1 = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                     params={"page_size": 1}).json()
    assert r1["next_cursor"]
    tampered = r1["next_cursor"][:-1] + ("A" if r1["next_cursor"][-1] != "A" else "B")
    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                    params={"page_size": 1, "cursor": tampered})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_cursor_from_other_org_rejected(api: Api):
    _, admin_token = api.new_user()
    org_a = _new_org(api, admin_token)
    _invite_member(api, admin_token, org_a)  # 3 audits -> cursor produced
    org_b = _new_org(api, admin_token)
    r1 = api.request("GET", f"/orgs/{org_a}/audit/scan", token=admin_token,
                     params={"page_size": 1}).json()
    assert r1["next_cursor"]
    # Cursor minted for org A is invalid on org B.
    r = api.request("GET", f"/orgs/{org_b}/audit/scan", token=admin_token,
                    params={"page_size": 1, "cursor": r1["next_cursor"]})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_invalid_page_size(api: Api):
    _, admin_token = api.new_user()
    org_id = _new_org(api, admin_token)
    for bad in ("0", "101", "abc", "-1"):
        r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=admin_token,
                        params={"page_size": bad})
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["error"]["code"] == "validation_error"
