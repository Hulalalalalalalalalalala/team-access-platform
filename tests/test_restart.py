"""Persistence across a full process restart, incl. idempotency replay."""
from __future__ import annotations

import uuid

import httpx

from tests.conftest import Api, Server


def _register_and_login(base_url: str, name: str) -> str:
    with httpx.Client(base_url=base_url, timeout=30) as c:
        r = c.post("/auth/register", json={"username": name, "password": "Passw0rd!"})
        assert r.status_code == 201, r.text
        r = c.post("/auth/login", json={"username": name, "password": "Passw0rd!"})
        return r.json()["token"]


def test_data_sessions_and_idempotency_survive_restart(make_server):
    srv: Server = make_server(f"restart-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        # Two users, an org, an accepted invite, an idempotent invite.
        admin = _register_and_login(srv.base_url, api.unique("ra"))
        member_name = api.unique("rm")
        c.post("/auth/register", json={"username": member_name, "password": "Passw0rd!"})
        member = c.post("/auth/login", json={"username": member_name,
                                             "password": "Passw0rd!"}).json()["token"]
        org = c.post("/orgs", headers={"Authorization": f"Bearer {admin}"},
                     json={"name": f"persist-{api.unique()}"}).json()
        invite1 = c.post(
            f"/orgs/{org['id']}/invites",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "persist-key"},
            json={"username": member_name, "role": "member"},
        ).json()
        assert c.post("/invites/accept", headers={"Authorization": f"Bearer {member}"},
                      json={"token": invite1["token"]}).status_code == 200

    # --- full process restart; same DB file, same secret key file ---
    srv.restart()
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        # Session tokens survive (sessions are persisted, hashed).
        r = c.get("/orgs", headers={"Authorization": f"Bearer {admin}"})
        assert r.status_code == 200
        assert any(o["id"] == org["id"] for o in r.json()["organizations"])

        # Membership + role persisted.
        r = c.get(f"/orgs/{org['id']}/members", headers={"Authorization": f"Bearer {member}"})
        assert r.status_code == 200
        assert any(m["username"] == member_name for m in r.json()["members"])

        # Audit trail persisted.
        r = c.get(f"/orgs/{org['id']}/audit", headers={"Authorization": f"Bearer {admin}"})
        actions = {i["action"] for i in r.json()["items"]}
        assert {"org.created", "invite.created", "invite.accepted"} <= actions

        # Idempotency record survives: replay returns the SAME invite token,
        # no second invite/audit is created.
        before = c.get(f"/orgs/{org['id']}/audit",
                       headers={"Authorization": f"Bearer {admin}"}).json()["total"]
        r = c.post(
            f"/orgs/{org['id']}/invites",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "persist-key"},
            json={"username": member_name, "role": "member"},
        )
        assert r.status_code == 201
        assert r.json()["token"] == invite1["token"]
        after = c.get(f"/orgs/{org['id']}/audit",
                      headers={"Authorization": f"Bearer {admin}"}).json()["total"]
        assert before == after

        # Same key with a different body still conflicts after restart.
        r = c.post(
            f"/orgs/{org['id']}/invites",
            headers={"Authorization": f"Bearer {admin}", "Idempotency-Key": "persist-key"},
            json={"username": member_name, "role": "admin"},
        )
        assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"


def test_logout_survives_restart_as_invalid_session(make_server):
    srv: Server = make_server(f"logout-{uuid.uuid4().hex[:8]}")
    api = Api(srv.base_url)
    token = _register_and_login(srv.base_url, api.unique("lo"))
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        assert c.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    srv.restart()
    with httpx.Client(base_url=srv.base_url, timeout=30) as c:
        r = c.get("/orgs", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        # A brand-new login still works after restart.
        fresh = _register_and_login(srv.base_url, api.unique("fr"))
        assert c.get("/orgs", headers={"Authorization": f"Bearer {fresh}"}).status_code == 200
