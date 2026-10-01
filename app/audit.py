"""Audit trail writer.

Every organization / invitation / membership mutation is recorded in the
SAME database transaction as the mutation itself, so the business change and
its audit row commit atomically (or roll back together).

Each entry captures: organization, operator (actor), action, target,
timestamp, and JSON snapshots of the target's before/after state.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional


def _json(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def add_audit(
    conn: sqlite3.Connection,
    *,
    org_id: int,
    actor_id: Optional[int],
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    before: Any = None,
    after: Any = None,
    batch_id: Optional[str] = None,
    ts: int,
) -> None:
    # The BEFORE INSERT trigger (see db.FAIL_TRIGGER) can abort this INSERT
    # when fault injection is armed, rolling back the entire transaction.
    conn.execute(
        """
        INSERT INTO audit_logs
            (org_id, actor_id, action, target_type, target_id,
             before_state, after_state, batch_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            org_id,
            actor_id,
            action,
            target_type,
            None if target_id is None else str(target_id),
            _json(before),
            _json(after),
            batch_id,
            ts,
        ),
    )
