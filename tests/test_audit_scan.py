"""Audit scan: snapshot-consistent cursor iteration over the audit trail."""
from __future__ import annotations

from tests.conftest import Api


def _invite_member(api: Api, admin_token, org_id: int, role: str = "member"):
    name, token = api.new_user()
    inv = api.request("POST", f"/orgs/{org_id}/invites", token=admin_token,
                      json={"username": name, "role": role}).json()
    api.request("POST", "/invites/accept", token=token, json={"token": inv["token"]})
    return name, token


def _make_org_with_audit(api: Api, admin_token, actions: int):
    """Create an org and generate `actions` extra audit rows (invites)."""
    org = api.request("POST", "/orgs", token=admin_token,
                      json={"name": f"scan-{api.unique()}"}).json()
    for _ in range(actions):
        api.request("POST", f"/orgs/{org['id']}/invites", token=admin_token,
                    json={"username": api.unique(), "role": "member"})
    return org


def _scan_all(api: Api, token, org_id: int, page_size: int = 2):
    """Drive a full scan; return (batches, final_response)."""
    batches = []
    cursor = None
    while True:
        params = f"page_size={page_size}"
        if cursor is not None:
            params += f"&cursor={cursor}"
        r = api.request("GET", f"/orgs/{org_id}/audit/scan?{params}", token=token)
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
