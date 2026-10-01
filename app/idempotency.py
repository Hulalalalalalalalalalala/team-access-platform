"""Idempotency-Key support.

Scope of a key is the operator plus an operation scope, so the same key can
safely be reused across different operations:

* ``org.create``                 -- organization creation
* ``org:<id>:invite.create``     -- issuing an invite in a specific org
* ``org:<id>:member.update``     -- changing a member role/status in an org

A stored record captures the fingerprint of the request body and the first
*successful* response. Replays with the same key+body return the stored
response without performing any new business change or audit write; a
reused key with a different body is ``409 idempotency_conflict``.

Records are persisted, so replays remain valid after process restarts. The
stored response may contain a single-use invite token, so the body column
holds Fernet ciphertext (key file lives outside the database).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Optional

from .secret import decrypt_text, encrypt_text


def scope_org_create() -> str:
    return "org.create"


def scope_invite_create(org_id: int) -> str:
    return f"org:{org_id}:invite.create"


def scope_member_update(org_id: int) -> str:
    return f"org:{org_id}:member.update"


def scope_delegation_create(org_id: int) -> str:
    return f"org:{org_id}:delegation.create"


def fingerprint(raw_body: bytes) -> str:
    """Stable SHA-256 over the JSON body, independent of key ordering.

    Falls back to hashing raw bytes for non-JSON payloads.
    """
    try:
        parsed = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    except (ValueError, UnicodeDecodeError):
        canonical = raw_body.hex()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find(
    conn: sqlite3.Connection, operator_id: int, scope: str, key: str
) -> Optional[sqlite3.Row]:
    return conn.execute(
        """
        SELECT request_hash, response_status, response_body, delegation_id
        FROM idempotency_keys
        WHERE operator_id = ? AND scope = ? AND idempotency_key = ?
        """,
        (operator_id, scope, key),
    ).fetchone()


def replay_body(row: sqlite3.Row) -> dict[str, Any]:
    return json.loads(decrypt_text(row["response_body"]))


def store_encrypted(
    conn: sqlite3.Connection,
    *,
    operator_id: int,
    scope: str,
    key: str,
    request_hash: str,
    status_code: int,
    response_body: dict[str, Any],
    ts: int,
    delegation_id: Optional[int] = None,
) -> None:
    # UNIQUE(operator_id, scope, idempotency_key): a concurrent retry that
    # beats us here raises IntegrityError; the caller rolls back and replays.
    conn.execute(
        """
        INSERT INTO idempotency_keys
            (operator_id, scope, idempotency_key, request_hash,
             response_status, response_body, delegation_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operator_id,
            scope,
            key,
            request_hash,
            status_code,
            encrypt_text(json.dumps(response_body, ensure_ascii=False)),
            delegation_id,
            ts,
        ),
    )
