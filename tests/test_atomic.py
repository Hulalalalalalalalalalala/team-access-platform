"""Atomic commit: when the audit write fails, the whole transaction rolls back.

The fault-injection table ``_fail_next_actions`` (test-only, created by the
schema) arms a trigger that aborts the audit INSERT for a given action,
proving business rows and audit rows commit together or not at all.
"""
from __future__ import annotations

from tests.conftest import Api


def _arm(db, action: str) -> None:
    db.execute("INSERT OR REPLACE INTO _fail_next_actions(action) VALUES (?)", (action,))
    db.commit()


def _disarm(db, action: str) -> None:
    db.execute("DELETE FROM _fail_next_actions WHERE action = ?", (action,))
    db.commit()


def test_failed_audit_rolls_back_org_creation(api: Api, db):
    before = db.execute("SELECT COUNT(*) AS n FROM organizations").fetchone()["n"]
    _arm(db, "org.created")
    try:
        _, token = api.new_user()
        r = api.request("POST", "/orgs", token=token, json={"name": f"rb-{api.unique()}"})
        assert r.status_code == 500
        assert r.json()["error"]["code"] == "internal_error"
    finally:
        _disarm(db, "org.created")

    after = db.execute("SELECT COUNT(*) AS n FROM organizations").fetchone()["n"]
    assert before == after
    uid = db.execute("SELECT id FROM users ORDER BY id DESC LIMIT 1").fetchone()["id"]
    assert db.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE user_id = ?", (uid,)
    ).fetchone()["n"] == 0


def test_failed_audit_rolls_back_invite_acceptance(api: Api, db):
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin,
                      json={"name": f"ra-{api.unique()}"}).json()
    name, member = api.new_user()
    invite = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                         json={"username": name, "role": "member"}).json()

    _arm(db, "invite.accepted")
    try:
        r = api.request("POST", "/invites/accept", token=member,
                        json={"token": invite["token"]})
        assert r.status_code == 500
    finally:
        _disarm(db, "invite.accepted")

    # No partial write: no membership, invite is still available...
    members = db.execute(
        "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ?", (org["id"],)
    ).fetchone()["n"]
    assert members == 1  # creator only
    status = db.execute("SELECT status FROM invites WHERE id = ?",
                        (invite["id"],)).fetchone()["status"]
    assert status == "available"

    # ...and the exact same invite now succeeds.
    r = api.request("POST", "/invites/accept", token=member,
                    json={"token": invite["token"]})
    assert r.status_code == 200


def test_failed_audit_rolls_back_member_update_and_idempotency(api: Api, db):
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin,
                      json={"name": f"rm-{api.unique()}"}).json()
    name, member = api.new_user()
    inv = api.request("POST", f"/orgs/{org['id']}/invites", token=admin,
                      json={"username": name, "role": "admin"}).json()
    api.request("POST", "/invites/accept", token=member, json={"token": inv["token"]})
    members = api.request("GET", f"/orgs/{org['id']}/members", token=admin).json()["members"]
    target = next(m["user_id"] for m in members if m["username"] == name)

    _arm(db, "member.updated")
    try:
        r = api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=admin,
                        json={"role": "member"}, headers={"Idempotency-Key": "rb-key-1"})
        assert r.status_code == 500
    finally:
        _disarm(db, "member.updated")

    # Both the membership change and the idempotency record rolled back:
    # role is still admin, and the key is not poisoned.
    row = db.execute("SELECT role FROM memberships WHERE user_id = ?", (target,)).fetchone()
    assert row["role"] == "admin"
    n_keys = db.execute("SELECT COUNT(*) AS n FROM idempotency_keys").fetchone()["n"]
    assert n_keys == 0
    r = api.request("PATCH", f"/orgs/{org['id']}/members/{target}", token=admin,
                    json={"role": "member"}, headers={"Idempotency-Key": "rb-key-1"})
    assert r.status_code == 200


def test_raw_tokens_and_passwords_never_persisted(api: Api, db):
    _, admin = api.new_user()
    org = api.request("POST", "/orgs", token=admin,
                      json={"name": f"sec-{api.unique()}"}).json()
    name, _ = api.new_user()
    invite = api.request(
        "POST", f"/orgs/{org['id']}/invites", token=admin,
        json={"username": name, "role": "member"},
        headers={"Idempotency-Key": "persist-key"},
    ).json()
    token = invite["token"]
    db_file = db.execute("PRAGMA database_list").fetchone()[2]
    db.commit()  # ensure WAL is flushed for a fair on-disk check
    with open(db_file, "rb") as f:
        main_bytes = f.read()
    for suffix in ("", "-wal"):
        with open(db_file + suffix, "rb") as f:
            data = f.read()
        assert token.encode() not in data
    assert token.encode() not in main_bytes
