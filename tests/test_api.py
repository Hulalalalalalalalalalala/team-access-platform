#!/usr/bin/env python3
"""Automated test suite for the organization member & permission API.

Runs the real server as a subprocess (SQLite file backed), so persistence
across restart is tested by killing and relaunching the server against the
same database file.

Run:
    python3 -m unittest tests.test_api -v
"""

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SERVER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server.py")


# --------------------------------------------------------------------------- #
# HTTP client helpers
# --------------------------------------------------------------------------- #

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def req(method, path, token=None, body=None, idem=None, base=None):
    url = (base or ApiTest.BASE) + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if idem:
        headers["Idempotency-Key"] = idem
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        return e.code, json.loads(raw) if raw else {}


def parallel(fn, args_list):
    with ThreadPoolExecutor(max_workers=max(2, len(args_list))) as ex:
        return list(ex.map(lambda a: fn(*a), args_list))


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Test case
# --------------------------------------------------------------------------- #

class ApiTest(unittest.TestCase):
    BASE = None
    proc = None
    tmpdir = None
    db = None
    logf = None

    # -- server lifecycle ---------------------------------------------------- #
    @classmethod
    def start_server(cls):
        env = dict(os.environ, BCRYPT_ROUNDS="4", PYTHONUNBUFFERED="1")
        cls.logf = open(os.path.join(cls.tmpdir, "server.log"), "ab")
        last_err = None
        for _ in range(8):
            cls.port = free_port()
            cls.BASE = f"http://127.0.0.1:{cls.port}"
            cls.db = os.path.join(cls.tmpdir, "data.db")
            cls.proc = subprocess.Popen(
                [sys.executable, SERVER, "--port", str(cls.port), "--db", cls.db],
                env=env, stdout=cls.logf, stderr=subprocess.STDOUT)
            for _ in range(100):
                try:
                    status, _ = req("GET", "/healthz", base=cls.BASE)
                    if status == 200:
                        return
                except Exception:
                    pass
                time.sleep(0.1)
            # Port likely grabbed between free_port() and bind; retry.
            last_err = cls.proc.poll()
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        raise RuntimeError(f"server failed to start (last exit: {last_err})")

    @classmethod
    def restart_server(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        cls.logf.close()
        cls.start_server()

    @classmethod
    def stop_server(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if cls.logf is not None:
            cls.logf.close()

    # -- setup --------------------------------------------------------------- #
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="orgapi-test-")
        cls.start_server()

        cls.users = {}
        for name in ("alice", "bob", "carol", "dave", "erin", "frank"):
            status, _ = req("POST", "/api/auth/register",
                            body={"username": name, "password": "passw0rd"})
            assert status == 201, f"register {name} failed: {status}"
            status, body = req("POST", "/api/auth/login",
                               body={"username": name, "password": "passw0rd"})
            assert status == 200, f"login {name} failed: {status}"
            cls.users[name] = {"id": body["user_id"], "token": body["token"]}

        # Alice creates the Acme org and becomes its admin.
        status, body = req("POST", "/api/orgs", token=cls.users["alice"]["token"],
                           body={"name": "Acme"}, idem="setup-org")
        assert status == 201, f"create org failed: {status} {body}"
        cls.org_id = body["org"]["id"]

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        if os.environ.get("KEEP_TEST_DIR"):
            print(f"\nKEEP_TEST_DIR={cls.tmpdir}")
        else:
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # -- helpers ------------------------------------------------------------- #
    def db_connect(self):
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        return conn

    # ======================================================================= #
    # 1. Health
    # ======================================================================= #
    def test_01_healthz(self):
        status, body = req("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    # ======================================================================= #
    # 2. Registration / login
    # ======================================================================= #
    def test_02_duplicate_username_409(self):
        status, body = req("POST", "/api/auth/register",
                           body={"username": "alice", "password": "whatever1"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "username_exists")

    def test_03_wrong_password_401(self):
        status, body = req("POST", "/api/auth/login",
                           body={"username": "alice", "password": "wrongpass"})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_credentials")

    def test_04_unauthenticated_401(self):
        status, body = req("GET", "/api/orgs")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")
        # Bogus token also 401.
        status, body = req("GET", "/api/orgs", token="nonsense-token-value")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")

    def test_05_password_not_stored_plaintext(self):
        # Passwords must never appear in plaintext in the db or its WAL.
        with open(self.db, "rb") as f:
            raw = f.read()
        wal = self.db + "-wal"
        if os.path.exists(wal):
            with open(wal, "rb") as f:
                raw += f.read()
        self.assertNotIn(b"passw0rd", raw)
        self.assertNotIn(b"secret123", raw)
        # Register response never carries a password field.
        status, body = req("POST", "/api/auth/register",
                           body={"username": "grace", "password": "secret123"})
        self.assertEqual(status, 201)
        self.assertNotIn("password", json.dumps(body))

    # ======================================================================= #
    # 3. Organizations
    # ======================================================================= #
    def test_06_create_org_idempotent_replay(self):
        status, body = req("POST", "/api/orgs", token=self.users["alice"]["token"],
                           body={"name": "Widgets"}, idem="widgets-org")
        self.assertEqual(status, 201)
        org_id = body["org"]["id"]
        # Replay with same key + same body returns the very same result.
        status2, body2 = req("POST", "/api/orgs", token=self.users["alice"]["token"],
                             body={"name": "Widgets"}, idem="widgets-org")
        self.assertEqual(status2, 201)
        self.assertEqual(body2, body)
        # Same key, different request -> 409 idempotency_conflict.
        status3, body3 = req("POST", "/api/orgs", token=self.users["alice"]["token"],
                             body={"name": "Widgets Inc"}, idem="widgets-org")
        self.assertEqual(status3, 409)
        self.assertEqual(body3["error"]["code"], "idempotency_conflict")
        # Only one org was actually created.
        status4, body4 = req("GET", "/api/orgs", token=self.users["alice"]["token"])
        names = [o["name"] for o in body4["items"]]
        self.assertEqual(names.count("Widgets"), 1)
        self.assertNotIn("Widgets Inc", names)
        self.org_widgets_id = org_id

    def test_07_org_isolation_uniform_403(self):
        # Carol is a stranger to Acme.
        status, body = req("GET", f"/api/orgs/{self.org_id}/members",
                           token=self.users["carol"]["token"])
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "org_access_denied")
        # Same code for an org that does not exist -> existence not leaked.
        status2, body2 = req("GET", "/api/orgs/999999/members",
                             token=self.users["carol"]["token"])
        self.assertEqual(status2, 403)
        self.assertEqual(body2["error"]["code"], "org_access_denied")
        self.assertEqual(body["error"]["code"], body2["error"]["code"])
        # Stranger cannot invite either.
        status3, _ = req("POST", f"/api/orgs/{self.org_id}/invites",
                         token=self.users["carol"]["token"],
                         body={"username": "carol", "role": "member"}, idem="stranger-inv")
        self.assertEqual(status3, 403)

    # ======================================================================= #
    # 4. Invites
    # ======================================================================= #
    def test_08_invite_accept_flow(self):
        # Admin Alice invites Bob as a member.
        status, body = req("POST", f"/api/orgs/{self.org_id}/invites",
                           token=self.users["alice"]["token"],
                           body={"username": "bob", "role": "member"}, idem="invite-bob")
        self.assertEqual(status, 201)
        self.assertEqual(body["invite"]["username"], "bob")
        self.assertEqual(body["invite"]["role"], "member")
        self.assertEqual(body["invite"]["status"], "pending")
        self.assertIn("token", body["invite"])
        invite_token = body["invite"]["token"]

        # Bob accepts.
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["bob"]["token"],
                           body={"token": invite_token})
        self.assertEqual(status, 200)
        self.assertEqual(body["role"], "member")
        self.assertEqual(body["status"], "active")

        # Bob can now list members and see his own membership.
        status, body = req("GET", f"/api/orgs/{self.org_id}/members",
                           token=self.users["bob"]["token"])
        self.assertEqual(status, 200)
        usernames = [m["username"] for m in body["items"]]
        self.assertIn("bob", usernames)
        bob_row = next(m for m in body["items"] if m["username"] == "bob")
        self.assertEqual(bob_row["role"], "member")
        self.assertEqual(bob_row["status"], "active")

        # Bob cannot query audit or issue invites (member, not admin).
        status, _ = req("GET", f"/api/orgs/{self.org_id}/audit",
                        token=self.users["bob"]["token"])
        self.assertEqual(status, 403)
        status, _ = req("POST", f"/api/orgs/{self.org_id}/invites",
                        token=self.users["bob"]["token"],
                        body={"username": "carol", "role": "member"}, idem="bob-inv")
        self.assertEqual(status, 403)

    def test_09_invite_validation_order(self):
        # 1) Nonexistent token -> 409 invite_unavailable.
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["carol"]["token"],
                           body={"token": "does-not-exist-token"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "invite_unavailable")

        # 2) Wrong username -> 403 invite_username_mismatch.
        status, inv = req("POST", f"/api/orgs/{self.org_id}/invites",
                          token=self.users["alice"]["token"],
                          body={"username": "erin", "role": "member"}, idem="invite-erin")
        self.assertEqual(status, 201)
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["carol"]["token"],  # carol, not erin
                           body={"token": inv["invite"]["token"]})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "invite_username_mismatch")

        # 3) Already a member -> 409 already_member (role/status not overwritten).
        status, inv2 = req("POST", f"/api/orgs/{self.org_id}/invites",
                           token=self.users["alice"]["token"],
                           body={"username": "bob", "role": "admin"}, idem="invite-bob-2")
        self.assertEqual(status, 201)
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["bob"]["token"],
                           body={"token": inv2["invite"]["token"]})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "already_member")
        # Bob's role is still member.
        _, members = req("GET", f"/api/orgs/{self.org_id}/members",
                         token=self.users["alice"]["token"])
        bob_row = next(m for m in members["items"] if m["username"] == "bob")
        self.assertEqual(bob_row["role"], "member")

        # 4) Revoked invite -> 409 invite_unavailable.
        status, inv3 = req("POST", f"/api/orgs/{self.org_id}/invites",
                           token=self.users["alice"]["token"],
                           body={"username": "carol", "role": "member"}, idem="invite-carol")
        self.assertEqual(status, 201)
        status, _ = req("POST", f"/api/orgs/{self.org_id}/invites/{inv3['invite']['id']}/revoke",
                       token=self.users["alice"]["token"], idem="revoke-carol")
        self.assertEqual(status, 200)
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["carol"]["token"],
                           body={"token": inv3["invite"]["token"]})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "invite_unavailable")

        # 5) Expired invite (inserted directly with a past expiry) -> 409.
        expired_token = "expired-invite-token-0001"
        conn = self.db_connect()
        conn.execute(
            "INSERT INTO invites (token_hash, org_id, role, invited_by, username, status, "
            "created_at, expires_at) VALUES (?, ?, 'member', ?, 'erin', 'pending', ?, ?)",
            (sha256(expired_token), self.org_id, self.users["alice"]["id"],
             "2020-01-01T00:00:00+00:00", "2020-01-02T00:00:00+00:00"))
        conn.commit()
        conn.close()
        status, body = req("POST", "/api/invites/accept",
                           token=self.users["erin"]["token"],
                           body={"token": expired_token})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "invite_unavailable")

    def test_10_concurrent_accept_single_success(self):
        # A fresh invite for dave; 10 concurrent accepts, exactly one succeeds.
        status, inv = req("POST", f"/api/orgs/{self.org_id}/invites",
                          token=self.users["alice"]["token"],
                          body={"username": "dave", "role": "member"}, idem="invite-dave")
        self.assertEqual(status, 201)
        token = inv["invite"]["token"]
        results = parallel(
            lambda: req("POST", "/api/invites/accept",
                        token=self.users["dave"]["token"], body={"token": token}),
            [()] * 10)
        statuses = [s for s, _ in results]
        self.assertEqual(statuses.count(200), 1, f"expected exactly one success, got {statuses}")
        # Exactly one membership row for dave.
        conn = self.db_connect()
        n = conn.execute(
            "SELECT COUNT(*) AS c FROM members WHERE org_id = ? AND user_id = ?",
            (self.org_id, self.users["dave"]["id"])).fetchone()["c"]
        conn.close()
        self.assertEqual(n, 1)
        # Invite is accepted.
        _, invs = req("GET", f"/api/orgs/{self.org_id}/invites",
                      token=self.users["alice"]["token"])
        dave_inv = next(i for i in invs["items"] if i["username"] == "dave")
        self.assertEqual(dave_inv["status"], "accepted")

    # ======================================================================= #
    # 5. Member role / status management
    # ======================================================================= #
    def test_11_role_change_and_idempotency(self):
        # Alice promotes bob to admin.
        status, body = req("PATCH", f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                           token=self.users["alice"]["token"],
                           body={"role": "admin"}, idem="promote-bob")
        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])
        self.assertEqual(body["member"]["role"], "admin")
        # Replay returns the same result without another audit.
        status2, body2 = req("PATCH", f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                            token=self.users["alice"]["token"],
                            body={"role": "admin"}, idem="promote-bob")
        self.assertEqual(status2, 200)
        self.assertEqual(body2, body)
        # Bob can now manage members.
        status, _ = req("GET", f"/api/orgs/{self.org_id}/audit",
                        token=self.users["bob"]["token"])
        self.assertEqual(status, 200)
        # Alice demotes bob back to member.
        status, body = req("PATCH", f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                           token=self.users["alice"]["token"],
                           body={"role": "member"}, idem="demote-bob")
        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])

    def test_12_last_admin_protection(self):
        # Alice is the only active admin. Self-demotion must fail.
        status, body = req("PATCH", f"/api/orgs/{self.org_id}/members/{self.users['alice']['id']}",
                           token=self.users["alice"]["token"],
                           body={"role": "member"}, idem="self-demote")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "last_admin_required")
        # Self-disable must also fail.
        status, body = req("POST",
                           f"/api/orgs/{self.org_id}/members/{self.users['alice']['id']}/disable",
                           token=self.users["alice"]["token"], idem="self-disable")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "last_admin_required")
        # Alice is still an active admin.
        _, members = req("GET", f"/api/orgs/{self.org_id}/members",
                         token=self.users["alice"]["token"])
        alice = next(m for m in members["items"] if m["username"] == "alice")
        self.assertEqual(alice["role"], "admin")
        self.assertEqual(alice["status"], "active")

    def test_13_concurrent_last_admin_demotion(self):
        # Two concurrent attempts to demote the only admin: both must fail,
        # leaving the org with its admin.
        results = parallel(
            lambda i: req("PATCH",
                          f"/api/orgs/{self.org_id}/members/{self.users['alice']['id']}",
                          token=self.users["alice"]["token"],
                          body={"role": "member"}, idem=f"race-demote-{i}"),
            [(0,), (1,)])
        codes = [b["error"]["code"] for s, b in results if s != 200]
        self.assertTrue(all(c == "last_admin_required" for c in codes),
                        f"unexpected results: {results}")
        _, members = req("GET", f"/api/orgs/{self.org_id}/members",
                         token=self.users["alice"]["token"])
        alice = next(m for m in members["items"] if m["username"] == "alice")
        self.assertEqual(alice["role"], "admin")

    def test_14_disable_enable_instant_and_scoped(self):
        # Bob creates his own org to prove other orgs are unaffected.
        status, body = req("POST", "/api/orgs", token=self.users["bob"]["token"],
                           body={"name": "BobOrg"}, idem="bob-org")
        self.assertEqual(status, 201)
        bob_org = body["org"]["id"]

        # Alice disables bob in Acme.
        status, body = req("POST",
                           f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}/disable",
                           token=self.users["alice"]["token"], idem="disable-bob")
        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])
        self.assertEqual(body["member"]["status"], "disabled")

        # Bob's very next request in Acme is denied (all his sessions lose access).
        status, body = req("GET", f"/api/orgs/{self.org_id}/members",
                           token=self.users["bob"]["token"])
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "org_access_denied")
        status, _ = req("GET", f"/api/orgs/{self.org_id}/audit",
                        token=self.users["bob"]["token"])
        self.assertEqual(status, 403)

        # Bob is unaffected in his own org.
        status, body = req("GET", f"/api/orgs/{bob_org}/members",
                           token=self.users["bob"]["token"])
        self.assertEqual(status, 200)

        # Disabling an already-disabled member is a no-op success (no new audit).
        status, body = req("POST",
                           f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}/disable",
                           token=self.users["alice"]["token"], idem="disable-bob-noop")
        self.assertEqual(status, 200)
        self.assertFalse(body["changed"])

        # Re-enable restores access.
        status, body = req("POST",
                           f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}/enable",
                           token=self.users["alice"]["token"], idem="enable-bob")
        self.assertEqual(status, 200)
        self.assertTrue(body["changed"])
        status, body = req("GET", f"/api/orgs/{self.org_id}/members",
                           token=self.users["bob"]["token"])
        self.assertEqual(status, 200)

    # ======================================================================= #
    # 6. Logout
    # ======================================================================= #
    def test_15_logout_invalidates_session_immediately(self):
        status, body = req("POST", "/api/auth/login",
                           body={"username": "erin", "password": "passw0rd"})
        self.assertEqual(status, 200)
        token = body["token"]
        # Token works.
        status, _ = req("GET", "/api/me", token=token)
        self.assertEqual(status, 200)
        # Logout.
        status, _ = req("POST", "/api/auth/logout", token=token)
        self.assertEqual(status, 200)
        # Same token is dead on the very next request.
        status, body = req("GET", "/api/me", token=token)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")

    # ======================================================================= #
    # 7. Audit
    # ======================================================================= #
    def test_16_audit_contents_and_pagination(self):
        status, body = req("GET", f"/api/orgs/{self.org_id}/audit",
                           token=self.users["alice"]["token"])
        self.assertEqual(status, 200)
        self.assertIn("items", body)
        self.assertIn("next_cursor", body)
        actions = [e["action"] for e in body["items"]]
        for expected in ("org.create", "invite.create", "member.role_change",
                         "member.disable", "member.enable"):
            self.assertIn(expected, actions)
        # Every entry carries actor and before/after state.
        for e in body["items"]:
            self.assertIn("actor_id", e)
            self.assertIn("actor_username", e)
            self.assertIn("before", e)
            self.assertIn("after", e)
            self.assertIn("created_at", e)
        # Pagination: limit=2 yields a cursor and pages are disjoint.
        status2, page1 = req("GET", f"/api/orgs/{self.org_id}/audit?limit=2",
                            token=self.users["alice"]["token"])
        self.assertEqual(status2, 200)
        self.assertEqual(len(page1["items"]), 2)
        self.assertIsNotNone(page1["next_cursor"])
        status3, page2 = req("GET",
                            f"/api/orgs/{self.org_id}/audit?limit=2&cursor={page1['next_cursor']}",
                            token=self.users["alice"]["token"])
        self.assertEqual(status3, 200)
        ids1 = {e["id"] for e in page1["items"]}
        ids2 = {e["id"] for e in page2["items"]}
        self.assertTrue(ids1.isdisjoint(ids2))
        # Audit is append-only: no update/delete routes exist (404).
        status4, _ = req("DELETE", f"/api/orgs/{self.org_id}/audit/1",
                         token=self.users["alice"]["token"])
        self.assertEqual(status4, 404)

    # ======================================================================= #
    # 8. Concurrent idempotent retries
    # ======================================================================= #
    def test_17_concurrent_idempotent_retries_single_change(self):
        key = "concurrent-org-key"
        body = {"name": "ConcurrentOrg"}
        results = parallel(
            lambda: req("POST", "/api/orgs", token=self.users["alice"]["token"],
                        body=body, idem=key),
            [()] * 5)
        statuses = [s for s, _ in results]
        self.assertTrue(all(s == 201 for s in statuses), f"statuses: {statuses}")
        org_ids = {b["org"]["id"] for _, b in results}
        self.assertEqual(len(org_ids), 1, "all retries must return the same org")
        # Exactly one org and one audit entry.
        conn = self.db_connect()
        n_org = conn.execute(
            "SELECT COUNT(*) AS c FROM organizations WHERE name = 'ConcurrentOrg'").fetchone()["c"]
        n_audit = conn.execute(
            "SELECT COUNT(*) AS c FROM audit_log WHERE action = 'org.create' "
            "AND target_id = ?", (str(org_ids.pop()),)).fetchone()["c"]
        n_idem = conn.execute(
            "SELECT COUNT(*) AS c FROM idempotency_keys WHERE key = ?", (key,)).fetchone()["c"]
        conn.close()
        self.assertEqual(n_org, 1)
        self.assertEqual(n_audit, 1)
        self.assertEqual(n_idem, 1)

    # ======================================================================= #
    # 9. Restart persistence & idempotent retry
    # ======================================================================= #
    def test_18_restart_persistence_and_retry(self):
        # Snapshot state before restart.
        _, before = req("GET", "/api/orgs", token=self.users["alice"]["token"])
        before_names = sorted(o["name"] for o in before["items"])

        self.restart_server()

        # Data survived: orgs still listed.
        status, after = req("GET", "/api/orgs", token=self.users["alice"]["token"])
        self.assertEqual(status, 200)
        after_names = sorted(o["name"] for o in after["items"])
        self.assertEqual(before_names, after_names)

        # Old session tokens still work (sessions persisted).
        status, _ = req("GET", "/api/me", token=self.users["alice"]["token"])
        self.assertEqual(status, 200)

        # Idempotent retry after restart returns the first successful result.
        status, body = req("POST", "/api/orgs", token=self.users["alice"]["token"],
                           body={"name": "Widgets"}, idem="widgets-org")
        self.assertEqual(status, 201)
        self.assertEqual(body["org"]["name"], "Widgets")

        # A new write after restart works and persists.
        status, inv = req("POST", f"/api/orgs/{self.org_id}/invites",
                          token=self.users["alice"]["token"],
                          body={"username": "frank", "role": "member"}, idem="invite-frank")
        self.assertEqual(status, 201)
        status, _ = req("POST", "/api/invites/accept",
                        token=self.users["frank"]["token"],
                        body={"token": inv["invite"]["token"]})
        self.assertEqual(status, 200)
        _, members = req("GET", f"/api/orgs/{self.org_id}/members",
                         token=self.users["alice"]["token"])
        self.assertTrue(any(m["username"] == "frank" for m in members["items"]))

    # ======================================================================= #
    # 10. Rollback: failed writes leave no partial state
    # ======================================================================= #
    def test_19_failed_accept_leaves_no_membership(self):
        # Carol already failed to accept erin's invite (username mismatch).
        # Confirm no membership row was created for carol in Acme.
        conn = self.db_connect()
        n = conn.execute(
            "SELECT COUNT(*) AS c FROM members WHERE org_id = ? AND user_id = ?",
            (self.org_id, self.users["carol"]["id"])).fetchone()["c"]
        conn.close()
        self.assertEqual(n, 0)

    def test_20_idempotency_conflict_writes_nothing(self):
        # Reuse a key with a different body: 409, and no new org/audit.
        _, before = req("GET", "/api/orgs", token=self.users["alice"]["token"])
        before_count = len(before["items"])
        status, body = req("POST", "/api/orgs", token=self.users["alice"]["token"],
                           body={"name": "ShouldNotExist"}, idem="setup-org")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "idempotency_conflict")
        _, after = req("GET", "/api/orgs", token=self.users["alice"]["token"])
        self.assertEqual(len(after["items"]), before_count)
        self.assertFalse(any(o["name"] == "ShouldNotExist" for o in after["items"]))

    def test_21_idempotent_replay_rechecks_permission(self):
        # Bob is promoted to admin (idempotent), then demoted. Replaying the
        # same idempotent request must now be rejected (403), not return the
        # cached success -- retries always re-validate current permission.
        status, first = req("PATCH",
                             f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                             token=self.users["alice"]["token"],
                             body={"role": "admin"}, idem="promote-bob-recheck")
        self.assertEqual(status, 200)
        self.assertEqual(first["member"]["role"], "admin")
        # Demote bob back to member.
        status, _ = req("PATCH",
                        f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                        token=self.users["alice"]["token"],
                        body={"role": "member"}, idem="demote-bob-recheck")
        self.assertEqual(status, 200)
        # Bob replays the promote request with the same key: no longer admin -> 403.
        status, body = req("PATCH",
                           f"/api/orgs/{self.org_id}/members/{self.users['bob']['id']}",
                           token=self.users["bob"]["token"],
                           body={"role": "admin"}, idem="promote-bob-recheck")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "org_access_denied")


if __name__ == "__main__":
    unittest.main()
