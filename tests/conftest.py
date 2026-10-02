"""Test fixtures: a real uvicorn subprocess with a throwaway SQLite file.

Using a real process (instead of FastAPI's in-process test client) lets the
suite exercise true cross-thread HTTP concurrency, session behaviour and a
full process restart with on-disk persistence.
"""
from __future__ import annotations

import itertools
import os
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, name: str = "default") -> None:
        self.tmp = Path(os.environ.get("TEST_TMP", "/tmp/team-access-tests")) / name
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.db_path = self.tmp / "test.db"
        self.key_path = self.tmp / "secret.key"
        self.log_path = self.tmp / "server.log"
        for p in (self.db_path, self.key_path, self.log_path,
                  Path(str(self.db_path) + "-wal"), Path(str(self.db_path) + "-shm")):
            p.unlink(missing_ok=True)
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["APP_DB_PATH"] = str(self.db_path)
        env["APP_SECRET_KEY_FILE"] = str(self.key_path)
        env["APP_INVITE_TTL"] = "86400"
        return env

    def start(self) -> None:
        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=REPO_ROOT, env=self._env(), stdout=log, stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early; log:\n{self.log_path.read_text()}")
            try:
                r = httpx.get(f"{self.base_url}/health", timeout=1)
                if r.status_code == 200:
                    return
            except httpx.TransportError:
                time.sleep(0.1)
        raise RuntimeError("server did not become ready")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.proc = None

    def restart(self) -> None:
        self.stop()
        time.sleep(0.3)
        self.start()

    def sqlite(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn


class Api:
    """Thin HTTP helper."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self._counter = itertools.count(1)

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=30)

    def unique(self, prefix: str = "u") -> str:
        # Globally unique across tests/runs: the server DB is session scoped.
        return f"{prefix}_{uuid.uuid4().hex[:16]}"

    def request(self, method: str, path: str, *, token: str | None = None, **kwargs):
        headers = kwargs.pop("headers", {}) or {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with self.client() as c:
            return c.request(method, path, headers=headers, **kwargs)

    # -- sugar -------------------------------------------------------------
    def register(self, username: str, password: str = "Passw0rd!"):
        return self.request("POST", "/auth/register", json={"username": username, "password": password})

    def login(self, username: str, password: str = "Passw0rd!"):
        return self.request("POST", "/auth/login", json={"username": username, "password": password})

    def token_for(self, username: str, password: str = "Passw0rd!") -> str:
        r = self.login(username, password)
        assert r.status_code == 200, r.text
        return r.json()["token"]

    def new_user(self) -> tuple[str, str]:
        u = self.unique()
        r = self.register(u)
        assert r.status_code == 201, r.text
        return u, self.token_for(u)


@pytest.fixture(scope="session")
def server():
    srv = Server()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture()
def api(server) -> Api:
    return Api(server.base_url)


@pytest.fixture()
def db(server) -> sqlite3.Connection:
    """Direct SQLite handle for test-only assertions / state manipulation."""
    conn = server.sqlite()
    yield conn
    conn.close()


@pytest.fixture()
def server_sign(server):
    """Sign text with the RUNNING SERVER's secret key.

    Lets tests hand-mint otherwise-valid signed tokens (e.g. legacy cursors
    signed before an upgrade); importing app.secret directly would use the
    test process's own key file, which does not match the server subprocess.
    """
    import base64
    import hashlib
    import hmac

    def _sign(text: str) -> str:
        key = server.key_path.read_bytes().strip()
        raw_key = base64.urlsafe_b64decode(key)
        sig = hmac.new(raw_key, text.encode("utf-8"), hashlib.sha256).digest()
        return (
            base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
            + "."
            + base64.urlsafe_b64encode(sig).decode("ascii")
        )

    return _sign


@pytest.fixture()
def make_server():
    """Factory for an isolated server instance (used by restart tests)."""
    created: list[Server] = []

    def _make(name: str) -> Server:
        srv = Server(name=f"iso-{name}-{os.getpid()}")
        srv.start()
        created.append(srv)
        return srv

    yield _make
    for srv in created:
        srv.stop()
