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

import base64
import hashlib
import hmac
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
_raw_key: bytes | None = None


def _load() -> Fernet:
    global _fernet, _raw_key
    if _fernet is not None:
        return _fernet
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        _KEY_FILE.write_bytes(key)
        os.chmod(_KEY_FILE, 0o600)
    _raw_key = base64.urlsafe_b64decode(key)
    _fernet = Fernet(key)
    return _fernet


def encrypt_text(text: str) -> str:
    return _load().encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_text(token: str) -> str:
    return _load().decrypt(token.encode("ascii")).decode("utf-8")


def sign_text(text: str) -> str:
    """Deterministic opaque token: base64url(payload) + HMAC-SHA256 tag.

    Unlike Fernet (random IV + timestamp), the same payload always produces
    the same token, which is what cursor-based pagination needs: re-issuing
    a cursor for an unchanged read position must yield the identical string.
    """
    _load()
    sig = hmac.new(_raw_key, text.encode("utf-8"), hashlib.sha256).digest()
    payload_b64 = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii")
    return f"{payload_b64}.{sig_b64}"


def verify_signed_text(token: str) -> str:
    """Inverse of :func:`sign_text`; raises ValueError on any mismatch."""
    _load()
    payload_b64, sep, sig_b64 = token.rpartition(".")
    if not sep or not payload_b64 or not sig_b64:
        raise ValueError("malformed signed token")
    payload = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8")
    expected = hmac.new(_raw_key, payload.encode("utf-8"), hashlib.sha256).digest()
    provided = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
    if not hmac.compare_digest(expected, provided):
        raise ValueError("bad signature")
    return payload
