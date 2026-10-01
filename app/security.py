"""Password hashing, token generation and secret hygiene."""
from __future__ import annotations

import hashlib
import hmac
import os
import time

from . import config


def now_ts() -> int:
    """Unix epoch seconds. Centralized so tests can reason about expiry."""
    return int(time.time())


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    """Return a self-describing PBKDF2-HMAC-SHA256 hash string.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.
    Plaintext passwords are never persisted or logged.
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, config.PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${config.PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iter_s, salt_hex, hash_hex = stored.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        int(iter_s),
    )
    return hmac.compare_digest(dk.hex(), hash_hex)


# ------------------------------------------------------------------ tokens

def generate_session_token() -> str:
    return os.urandom(config.SESSION_TOKEN_BYTES).hex()


def generate_invite_token() -> str:
    return os.urandom(config.INVITE_TOKEN_BYTES).hex()


def generate_batch_id() -> str:
    # Opaque batch marker shared by every audit row of one batch operation.
    return "b_" + os.urandom(16).hex()


def hash_token(token: str) -> str:
    """Tokens are stored and compared only as SHA-256 hashes."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()
