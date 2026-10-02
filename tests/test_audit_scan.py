"""Audit scan: snapshot-consistent cursor iteration over the audit trail."""
from __future__ import annotations

import json

from tests.conftest import Api


def _invite_member(api: Api, admin_token, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    return name, token


def _invite_member_id(api: Api, admin_token, org_id: int, role: str = "member"):
    name, token = _invite_member(api, admin_token, org_id, role)
    uid = api.request("GET", f"/orgs/{org_id}/members/me",
                      token=token).json()["membership"]["user_id"]
    return name, token, uid


def _batch(api: Api, token: str, org_id: int, changes: list[dict]) -> str:
    r = api.request("PATCH", f"/orgs/{org_id}/members/batch", token=token,
                    json={"changes": changes})
    assert r.status_code == 200, r.text
    return r.json()["batch_id"]


def _org_with_two_batches(api: Api):
    """Org whose audit trail mixes batch and non-batch rows.

    Batch A disables two members, one of them an active delegate, so it
    contains 2 member.updated rows and 1 delegation.invalidated row.
    Batch B re-enables that member and disables another: 2 member.updated
    rows and no delegation rows (invalidation is permanent).
    """
    _, admin_token = api.new_user()
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"bscan-{api.unique()}"}).json()
    people = [_invite_member_id(api, admin_token, org["id"]) for _ in range(4)]
    m1, m2, m3, m4 = (p[2] for p in people)

    r = api.request("POST", f"/orgs/{org['id']}/delegations", token=admin_token,
                    json={"user_id": m1, "duration_seconds": 3600})
    assert r.status_code == 201, r.text

    batch_a = _batch(api, admin_token, org["id"], [
        {"user_id": m1, "status": "disabled"},
        {"user_id": m2, "status": "disabled"},
    ])
    batch_b = _batch(api, admin_token, org["id"], [
        {"user_id": m1, "status": "active"},
        {"user_id": m3, "status": "disabled"},
    ])
    return admin_token, org["id"], batch_a, batch_b, people



def _make_org_with_audit(api: Api, admin_token, actions: int):
    """Create an org and generate `actions` extra audit rows (invites)."""
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"scan-{api.unique()}"}).json()
    for _ in range(actions):
        api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                    json={"username": api.unique(), "role": "member"})
    return org


def _scan_all(api: Api, token, org_id: int, page_size: int = 2, batch_id=None):
    """Drive a full scan; return (batches, final_response)."""
    batches = []
    cursor = None
    while True:
        params: dict[str, object] = {"page_size": page_size}
        if batch_id is not None:
            params["batch_id"] = batch_id
        if cursor is not None:
            params["cursor"] = cursor
        r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=token,
                        params=params)
        assert r.status_code == 200, r.text
        data = r.json()
        batches.append(data)
        if data["next_cursor"] is None:
            return batches, data
        cursor = data["next_cursor"]


def test_scan_returns_every_record_exactly_once(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 6)  # 1 org.created + 6 invites

    batches, last = _scan_all(api, admin_token, org["id"], page_size=2)
    ids = [i["id"] for b in batches for i in b["items"]]
    assert len(ids) == 7
    assert len(set(ids)) == 7                      # no duplicates
    assert ids == sorted(ids)                      # ascending by id
    assert all(b["total"] == 7 for b in batches)   # total stable across batches
    assert last["next_cursor"] is None

    # Items carry the same public fields as the paged endpoint.
    item = batches[0]["items"][0]
    assert set(item) == {"id", "org_id", "created_at", "actor_id",
                         "actor_username", "action", "target_type",
                         "target_id", "before", "after", "batch_id"}
    assert item["action"] == "org.created"


def test_scan_page_size_may_change_between_batches(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 5)  # 6 rows total

    r1 = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=1",
                     token=admin_token).json()
    r2 = api.request("GET",
                     f"/orgs/{org['id']}/audit/scan?page_size=4&cursor={r1['next_cursor']}",
                     token=admin_token).json()
    r3 = api.request("GET",
                     f"/orgs/{org['id']}/audit/scan?page_size=20&cursor={r2['next_cursor']}",
                     token=admin_token).json()
    ids = [i["id"] for r in (r1, r2, r3) for i in r["items"]]
    assert len(r1["items"]) == 1 and len(r2["items"]) == 4 and len(r3["items"]) == 1
    assert ids == sorted(ids) and len(set(ids)) == 6
    assert r3["next_cursor"] is None
    assert r1["total"] == r2["total"] == r3["total"] == 6


def test_scan_exact_full_last_batch_ends(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 3)  # 4 rows total

    # 4 rows with page_size 2: two full batches, second must end the scan.
    batches, last = _scan_all(api, admin_token, org["id"], page_size=2)
    assert len(batches) == 2
    assert len(last["items"]) == 2 and last["next_cursor"] is None

    # 4 rows with page_size 4: a single exactly-full batch ends immediately.
    r = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=4",
                    token=admin_token).json()
    assert len(r["items"]) == 4 and r["next_cursor"] is None


def test_scan_empty_org(api: Api, db):
    """An org with no audit rows yields an empty first (and final) batch."""
    username, token = api.new_user()
    user_id = db.execute("SELECT id FROM users WHERE username = ?",
                         (username,)).fetchone()["id"]
    cur = db.execute(
        "INSERT INTO organizations (name, created_by, created_at)"
        " VALUES (?, ?, 1)",
        (f"empty-{api.unique()}", user_id),
    )
    org_id = cur.lastrowid
    db.execute(
        "INSERT INTO memberships (org_id, user_id, role, status, created_at, updated_at)"
        " VALUES (?, ?, 'admin', 'active', 1, 1)",
        (org_id, user_id),
    )
    db.commit()

    r = api.request("GET", f"/orgs/{org_id}/audit/scan", token=token)
    assert r.status_code == 200
    assert r.json() == {"items": [], "total": 0, "next_cursor": None}


def test_scan_snapshot_excludes_later_entries(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 2)  # 3 rows

    r1 = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=2",
                     token=admin_token).json()
    assert r1["total"] == 3

    # New audit rows committed AFTER the scan started must not enter it.
    api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                json={"username": api.unique(), "role": "member"})

    # Continuing the ORIGINAL scan still sees exactly the original 3 rows.
    r2 = api.request("GET",
                     f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={r1['next_cursor']}",
                     token=admin_token).json()
    ids = [i["id"] for i in r1["items"]] + [i["id"] for i in r2["items"]]
    assert len(ids) == 3
    assert r2["total"] == 3 and r2["next_cursor"] is None

    # A fresh scan (no cursor) starts a new range that includes the new row.
    r3 = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=20",
                     token=admin_token).json()
    assert r3["total"] == 4 and len(r3["items"]) == 4
    assert r3["next_cursor"] is None


def test_scan_repeat_same_cursor_is_idempotent(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 4)  # 5 rows

    r1 = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=2",
                     token=admin_token).json()
    cursor = r1["next_cursor"]
    a = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={cursor}",
                    token=admin_token).json()
    b = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={cursor}",
                    token=admin_token).json()
    assert a == b                                    # nothing consumed
    assert [i["id"] for i in a["items"]] == [i["id"] for i in b["items"]]
    # The repeated batch continues from the same position.
    c = api.request("GET",
                    f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={a['next_cursor']}",
                    token=admin_token).json()
    assert c["items"][0]["id"] > a["items"][-1]["id"]


def test_scan_isolated_across_orgs(api: Api):
    _, admin_token = api.new_user()
    o1 = _make_org_with_audit(api, admin_token, 2)
    o2 = _make_org_with_audit(api, admin_token, 1)

    batches, _ = _scan_all(api, admin_token, o1["id"], page_size=2)
    ids = [i["id"] for b in batches for i in b["items"]]
    assert all(b["total"] == 3 for b in batches)
    assert len(ids) == 3
    items = [i for b in batches for i in b["items"]]
    assert {i["org_id"] for i in items} == {o1["id"]}

    # A cursor minted for org 1 is invalid for org 2.
    cursor = batches[0]["next_cursor"]
    r = api.request("GET", f"/orgs/{o2['id']}/audit/scan?cursor={cursor}",
                    token=admin_token)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_auth_and_admin_required(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 1)
    _, member_token = _invite_member(api, admin_token, org["id"])
    _, outsider_token = api.new_user()

    # No session -> 401.
    assert api.request("GET", f"/orgs/{org['id']}/audit/scan").status_code == 401
    assert api.request("GET", f"/orgs/{org['id']}/audit/scan",
                       token="deadbeef").status_code == 401
    # Plain member / outsider / unknown org -> uniform 403.
    assert api.request("GET", f"/orgs/{org['id']}/audit/scan",
                       token=member_token).status_code == 403
    assert api.request("GET", f"/orgs/{org['id']}/audit/scan",
                       token=outsider_token).status_code == 403
    assert api.request("GET", "/orgs/999999999/audit/scan",
                       token=admin_token).status_code == 403


def test_scan_cursor_does_not_replace_authorization(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 3)
    second_name, second_token = _invite_member(api, admin_token, org["id"],
                                               role="admin")
    second_id = api.request("GET", f"/orgs/{org['id']}/members/me",
                            token=second_token).json()["membership"]["user_id"]

    r1 = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=2",
                     token=admin_token).json()
    cursor = r1["next_cursor"]

    # Demote the second admin: their cursor-based continuation is now 403.
    api.request("PATCH", f"/orgs/{org['id']}/members/{second_id}",
                token=admin_token, json={"role": "member"})
    r = api.request("GET", f"/orgs/{org['id']}/audit/scan?cursor={cursor}",
                    token=second_token)
    assert r.status_code == 403

    # A fresh login does not help a demoted member...
    second_token2 = api.token_for(second_name)
    assert api.request("GET", f"/orgs/{org['id']}/audit/scan?cursor={cursor}",
                       token=second_token2).status_code == 403


    # ...but the still-admin user continues the original range with the
    # same cursor (any valid session of theirs works).
    r2 = api.request("GET", f"/orgs/{org['id']}/audit/scan?cursor={cursor}",
                     token=admin_token)
    assert r2.status_code == 200
    assert r2.json()["items"]


def test_scan_invalid_cursor_and_page_size(api: Api):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 1)

    for bad in ("not-a-cursor", "", "AAAA", "x" * 300):
        r = api.request("GET", f"/orgs/{org['id']}/audit/scan?cursor={bad}",
                        token=admin_token)
        assert r.status_code == 422, bad
        assert r.json()["error"]["code"] == "invalid_cursor"

    # Tampered cursor: valid-looking Fernet token with flipped characters.
    good = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=1",
                       token=admin_token).json()
    if good["next_cursor"] is not None:
        c = good["next_cursor"]
        tampered = c[:-4] + ("AAAA" if c[-4:] != "AAAA" else "BBBB")
        r = api.request("GET", f"/orgs/{org['id']}/audit/scan?cursor={tampered}",
                        token=admin_token)
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "invalid_cursor"

    # page_size outside 1..100 -> 422 validation_error.
    for bad_size in ("0", "101", "-3", "abc"):
        r = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size={bad_size}",
                        token=admin_token)
        assert r.status_code == 422
        assert r.json()["error"]["code"] == "validation_error"


def test_scan_is_read_only(api: Api, db):
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 2)

    before = db.execute("SELECT COUNT(*) AS n FROM audit_logs").fetchone()["n"]
    _scan_all(api, admin_token, org["id"], page_size=1)
    after = db.execute("SELECT COUNT(*) AS n FROM audit_logs").fetchone()["n"]
    assert before == after


def test_paged_endpoint_unchanged(api: Api):
    """The original paged endpoint keeps its parameters, fields and order."""
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 2)

    r = api.request("GET", f"/orgs/{org['id']}/audit?page=1&page_size=2",
                    token=admin_token)
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1 and data["page_size"] == 2 and data["total"] == 3
    assert len(data["items"]) == 2
    ids = [i["id"] for i in data["items"]]
    assert ids == sorted(ids)
    page2 = api.request("GET", f"/orgs/{org['id']}/audit?page=2&page_size=2",
                        token=admin_token).json()
    assert page2["items"][0]["id"] > ids[-1]


# ====================================================== batch_id filtering

def test_scan_batch_filter_returns_only_that_batch_ascending(api: Api):
    admin, org, batch_a, batch_b, _ = _org_with_two_batches(api)

    r = api.request("GET", f"/orgs/{org}/audit/scan?page_size=20&batch_id={batch_a}",
                    token=admin)
    assert r.status_code == 200, r.text
    data = r.json()
    # 2 member changes + 1 delegation invalidation, all carrying batch A.
    assert len(data["items"]) == 3
    assert data["total"] == 3 and data["next_cursor"] is None
    ids = [i["id"] for i in data["items"]]
    assert ids == sorted(ids)
    assert {i["batch_id"] for i in data["items"]} == {batch_a}
    assert {i["action"] for i in data["items"]} == {
        "member.updated", "delegation.invalidated"}
    # Fields are the same the unfiltered scan exposes.
    assert set(data["items"][0]) == {"id", "org_id", "created_at", "actor_id",
                                    "actor_username", "action", "target_type",
                                    "target_id", "before", "after", "batch_id"}
    assert all(i["org_id"] == org for i in data["items"])

    # The other batch is an independent range.
    rb = api.request("GET", f"/orgs/{org}/audit/scan?page_size=20&batch_id={batch_b}",
                     token=admin).json()
    assert len(rb["items"]) == 2 and rb["total"] == 2 and rb["next_cursor"] is None
    assert {i["batch_id"] for i in rb["items"]} == {batch_b}
    assert {i["action"] for i in rb["items"]} == {"member.updated"}


def test_scan_batch_filter_paginates_without_gaps_or_dupes(api: Api):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)  # 3 matching rows

    r1 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                     token=admin).json()
    assert len(r1["items"]) == 1 and r1["total"] == 3
    assert r1["items"][0]["batch_id"] == batch_a

    # Continuation needs just the cursor; the filter rides inside it.
    r2 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=1&cursor={r1['next_cursor']}",
                     token=admin).json()
    assert len(r2["items"]) == 1 and r2["total"] == 3
    # page_size may change between batches.
    r3 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=20&cursor={r2['next_cursor']}",
                     token=admin).json()
    assert len(r3["items"]) == 1 and r3["total"] == 3 and r3["next_cursor"] is None

    ids = [i["id"] for r in (r1, r2, r3) for i in r["items"]]
    assert ids == sorted(ids) and len(ids) == len(set(ids)) == 3


def test_scan_batch_filter_full_last_batch_ends(api: Api):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)  # 3 matching rows

    # page_size equal to the match count: a single exactly-full batch ends.
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?page_size=3&batch_id={batch_a}",
                    token=admin).json()
    assert len(r["items"]) == 3 and r["total"] == 3 and r["next_cursor"] is None

    # Two full batches with page_size that divides evenly must also end.
    batches, last = _scan_all(api, admin, org, page_size=3, batch_id=batch_a)
    assert len(batches) == 1 and last["next_cursor"] is None


def test_scan_batch_filter_unknown_batch_is_empty_200(api: Api):
    admin, org, _, other_batch, _ = _org_with_two_batches(api)

    # Marker that exists nowhere.
    r = api.request("GET", f"/orgs/{org}/audit/scan?batch_id=b_doesnotexist000000000000",
                    token=admin)
    assert r.status_code == 200
    assert r.json() == {"items": [], "total": 0, "next_cursor": None}

    # A marker of ANOTHER org's batch reveals nothing here.
    _, admin2 = api.new_user()
    org2 = api.request("POST", "/orgs", token=admin2,
                       json={"name": f"other-{api.unique()}"}).json()
    r = api.request("GET",
                    f"/orgs/{org2['id']}/audit/scan?batch_id={other_batch}",
                    token=admin2)
    assert r.status_code == 200
    assert r.json() == {"items": [], "total": 0, "next_cursor": None}


def test_scan_batch_filter_exact_match_preserves_space_and_case(api: Api):
    admin, org, batch_a, batch_b, _ = _org_with_two_batches(api)
    # Case folding and whitespace trimming must NOT happen: variants match
    # nothing but still return the normal empty 200.
    for variant in (" " + batch_a, batch_a.upper(), batch_a + " "):
        r = api.request("GET", f"/orgs/{org}/audit/scan", token=admin,
                        params={"batch_id": variant, "page_size": 20})
        assert r.status_code == 200
        assert r.json() == {"items": [], "total": 0, "next_cursor": None}
    # The unmodified value still matches.
    r = api.request("GET", f"/orgs/{org}/audit/scan", token=admin,
                    params={"batch_id": batch_a, "page_size": 20})
    assert r.status_code == 200 and r.json()["total"] == 3
    # A batch id consisting solely of spaces is a valid 1..128-char exact
    # value: it matches no rows, it is not "empty input".
    r = api.request("GET", f"/orgs/{org}/audit/scan", token=admin,
                    params={"batch_id": "   "})
    assert r.status_code == 200 and r.json()["total"] == 0


def test_scan_batch_filter_param_validation(api: Api):
    admin, org, _, _, _ = _org_with_two_batches(api)

    # Empty string -> 422 validation_error (it is "not provided", not a value).
    r = api.request("GET", f"/orgs/{org}/audit/scan?batch_id=", token=admin)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"

    # Overlong -> 422 validation_error.
    r = api.request("GET", f"/orgs/{org}/audit/scan", token=admin,
                    params={"batch_id": "b" * 129})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"

    # Exactly 128 chars is accepted (matches nothing -> empty 200).
    r = api.request("GET", f"/orgs/{org}/audit/scan", token=admin,
                    params={"batch_id": "x" * 128})
    assert r.status_code == 200
    assert r.json() == {"items": [], "total": 0, "next_cursor": None}


def test_scan_batch_filter_snapshot_with_injected_later_row(api, db):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)  # 3 rows for A

    r1 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=2&batch_id={batch_a}",
                     token=admin).json()
    assert r1["total"] == 3 and r1["next_cursor"] is not None

    # Commit a NEWER row tagged with the identical batch marker after the scan
    # began. It must not enter the fixed range even though marker and even a
    # coincident timestamp would match.
    db.execute(
        "INSERT INTO audit_logs (org_id, actor_id, action, target_type,"
        " target_id, before_state, after_state, batch_id, created_at)"
        " SELECT org_id, actor_id, action, target_type, target_id,"
        " before_state, after_state, ?, created_at FROM audit_logs"
        " WHERE batch_id = ? LIMIT 1",
        (batch_a, batch_a),
    )
    db.commit()

    r2 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=2&cursor={r1['next_cursor']}",
                     token=admin).json()
    ids = [i["id"] for i in r1["items"]] + [i["id"] for i in r2["items"]]
    assert len(ids) == 3
    assert r2["total"] == 3 and r2["next_cursor"] is None

    # A fresh filtered scan (no cursor) starts a new range including the row.
    r3 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=20&batch_id={batch_a}",
                     token=admin).json()
    assert r3["total"] == 4 and len(r3["items"]) == 4 and r3["next_cursor"] is None


def test_scan_batch_filter_repeat_cursor_idempotent(api: Api):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)  # 3 rows

    r1 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                     token=admin).json()
    cursor = r1["next_cursor"]
    a = api.request("GET", f"/orgs/{org}/audit/scan?page_size=1&cursor={cursor}",
                    token=admin).json()
    b = api.request("GET", f"/orgs/{org}/audit/scan?page_size=1&cursor={cursor}",
                    token=admin).json()
    assert a == b
    assert {i["batch_id"] for i in a["items"]} == {batch_a}


def test_scan_batch_filter_cursor_rejects_changed_or_added_batch(api: Api):
    admin, org, batch_a, batch_b, _ = _org_with_two_batches(api)

    # Cursor minted for batch A ...
    c_a = api.request("GET",
                      f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                      token=admin).json()["next_cursor"]
    # ... cannot continue batch B.
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={c_a}&batch_id={batch_b}",
                    token=admin)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"

    # Repeating the SAME batch alongside the cursor is allowed.
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={c_a}&batch_id={batch_a}",
                    token=admin)
    assert r.status_code == 200

    # A cursor from an UNFILTERED scan rejects an added batch filter.
    c_all = api.request("GET", f"/orgs/{org}/audit/scan?page_size=1",
                        token=admin).json()["next_cursor"]
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={c_all}&batch_id={batch_a}",
                    token=admin)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"

    # A filtered cursor with NO batch_id presented simply inherits its
    # embedded filter and continues the same filtered scan.
    r = api.request("GET", f"/orgs/{org}/audit/scan?cursor={c_a}", token=admin)
    assert r.status_code == 200
    assert {i["batch_id"] for i in r.json()["items"]} == {batch_a}


def test_scan_batch_filter_cursor_bound_to_org(api: Api):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)
    c = api.request("GET",
                    f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                    token=admin).json()["next_cursor"]
    org2 = _make_org_with_audit(api, admin, 1)
    r = api.request("GET",
                    f"/orgs/{org2['id']}/audit/scan?cursor={c}&batch_id={batch_a}",
                    token=admin)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_batch_filter_auth_enforced_every_batch(api: Api):
    admin, org, batch_a, _, people = _org_with_two_batches(api)
    member_token = people[3][1]
    disabled_token = people[1][1]   # m2 ends disabled after batch A

    # 401 unauthenticated even with a filter.
    r = api.request("GET", f"/orgs/{org}/audit/scan",
                    params={"batch_id": batch_a})
    assert r.status_code == 401
    # Plain member, disabled member, outsider, unknown org -> uniform 403.
    _, outsider = api.new_user()
    assert api.request("GET", f"/orgs/{org}/audit/scan", token=member_token,
                       params={"batch_id": batch_a}).status_code == 403
    assert api.request("GET", f"/orgs/{org}/audit/scan", token=disabled_token,
                       params={"batch_id": batch_a}).status_code == 403
    assert api.request("GET", f"/orgs/{org}/audit/scan", token=outsider,
                       params={"batch_id": batch_a}).status_code == 403
    assert api.request("GET", "/orgs/999999999/audit/scan", token=admin,
                       params={"batch_id": batch_a}).status_code == 403

    # A delegate is still an ordinary member for audit reads: 403 even with
    # an active delegation, on both filtered and unfiltered scans.
    r = api.request("POST", f"/orgs/{org}/delegations", token=admin,
                    json={"user_id": people[3][2], "duration_seconds": 3600})
    assert r.status_code == 201, r.text
    assert api.request("GET", f"/orgs/{org}/audit/scan", token=member_token,
                       params={"batch_id": batch_a}).status_code == 403

    # Demote the admin mid-scan: the cursor continuation is refused.
    second_name, second_token, second_id = _invite_member_id(
        api, admin, org, role="admin")
    r1 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                     token=second_token).json()
    api.request("PATCH", f"/orgs/{org}/members/{second_id}", token=admin,
                json={"role": "member"})
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={r1['next_cursor']}",
                    token=second_token)
    assert r.status_code == 403
    # Fresh login does not restore access; the still-admin caller continues.
    assert api.request(
        "GET", f"/orgs/{org}/audit/scan?cursor={r1['next_cursor']}",
        token=api.token_for(second_name)).status_code == 403
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={r1['next_cursor']}",
                    token=admin)
    assert r.status_code == 200 and r.json()["items"]

    # An admin DISABLED mid-filtered-scan is likewise refused on the next
    # batch, even after a fresh login.
    third_name, third_token, third_id = _invite_member_id(
        api, admin, org, role="admin")
    r1 = api.request("GET",
                     f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                     token=third_token).json()
    api.request("PATCH", f"/orgs/{org}/members/{third_id}", token=admin,
                json={"status": "disabled"})
    assert api.request(
        "GET", f"/orgs/{org}/audit/scan?cursor={r1['next_cursor']}",
        token=api.token_for(third_name)).status_code == 403


def test_scan_batch_filter_is_read_only(api: Api, db):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)
    before = db.execute("SELECT COUNT(*) AS n FROM audit_logs").fetchone()["n"]
    _scan_all(api, admin, org, page_size=1, batch_id=batch_a)
    after = db.execute("SELECT COUNT(*) AS n FROM audit_logs").fetchone()["n"]
    assert before == after


def test_scan_legacy_v1_cursor_valid_only_unfiltered(api: Api, server_sign):
    """A cursor signed before the upgrade (no batch field) keeps working."""
    _, admin_token = api.new_user()
    org = _make_org_with_audit(api, admin_token, 3)  # 4 rows

    first = api.request("GET", f"/orgs/{org['id']}/audit/scan?page_size=20",
                        token=admin_token).json()
    max_id = max(i["id"] for i in first["items"])
    # Mint a legacy v1 cursor directly with the SERVER's key:
    # {"v":1,"org","end","pos"}, no batch field.
    legacy = server_sign(json.dumps(
        {"v": 1, "org": org["id"], "end": max_id, "pos": 0},
        separators=(",", ":")))

    # Still valid for an unfiltered continuation...
    r = api.request("GET",
                    f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={legacy}",
                    token=admin_token)
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["items"]) == 2 and data["total"] == 4
    assert [i["id"] for i in data["items"]] == sorted(i["id"] for i in first["items"])[:2]

    # ...but attaching any batch_id to it is invalid_cursor.
    r = api.request("GET",
                    f"/orgs/{org['id']}/audit/scan?page_size=2&cursor={legacy}"
                    "&batch_id=b_whatever0000000000000000000000000000",
                    token=admin_token)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


def test_scan_batch_filter_new_cursor_is_v2_and_opaque(api: Api):
    admin, org, batch_a, _, _ = _org_with_two_batches(api)
    c = api.request("GET",
                    f"/orgs/{org}/audit/scan?page_size=1&batch_id={batch_a}",
                    token=admin).json()["next_cursor"]
    # Opaque signed token; the raw batch id never appears inside it.
    assert batch_a not in c
    # Tampering flips it back to invalid_cursor.
    tampered = c[:-4] + ("AAAA" if c[-4:] != "AAAA" else "BBBB")
    r = api.request("GET",
                    f"/orgs/{org}/audit/scan?cursor={tampered}&batch_id={batch_a}",
                    token=admin)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_cursor"


