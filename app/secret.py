"""Local secret key for encrypting sensitive idempotency replay payloads.

Idempotent replays must re-return the first successful response, which for
invite creation includes the raw single-use invite token. We do not want
that token sitting in plaintext in the SQLite file, so stored replay bodies
are encrypted with a Fernet key that lives outside the database:

* ``APP_SECRET_KEY_FILE`` overrides the key location (default
  ``data/secret.key``);
* if no key file exists one is created with ``0600`` permissions.

The key file persists across restarts (so replays keep working) but is
never part of the database file itself.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet

from . import config

_KEY_FILE = Path(
    os.environ.get(
        "APP_SECRET_KEY_FILE",
        str(config.DB_PATH.parent / "secret.key"),
    )
)
_fernet: Fernet | None = None


def _load() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        _KEY_FILE.write_bytes(key)
        os.chmod(_KEY_FILE, 0o600)
    _fernet = Fernet(key)
    return _fernet


def encrypt_text(text: str) -> str:
    return _load().encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_text(token: str) -> str:
    return _load().decrypt(token.encode("ascii")).decode("utf-8")


def key_bytes() -> bytes:
    """Raw bytes of the local secret key, for HMAC-signed tokens.

    Used by audit scan cursors: a deterministic signature makes identical
    requests return byte-identical cursors (true idempotency), and HMAC
    verification rejects tampering without encrypting the payload.
    """
    _load()  # ensures the key file exists
    return _KEY_FILE.read_bytes().strip()
