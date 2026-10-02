"""Cursor-based audit scanning for administrators.

``GET /orgs/{org_id}/audit/scan``

Unlike the page-numbered audit endpoint (which re-counts on every request),
a scan fixes its *range* when the FIRST request arrives: only audit rows
already committed at that instant are visible. Later requests walk the
range with an opaque, authenticated cursor, so:

* every row in the range appears exactly once, in id order;
* rows committed after the scan started never enter the range (even rows
  carrying an identical timestamp);
* other organizations' writes do not affect ordering or results;
* replaying the same cursor returns the same page without consuming
  progress;
* changing ``page_size`` between batches does not create gaps or repeats.

The cursor is an HMAC-signed blob carrying the org id, the range end (max
audit id at scan start) and the last seen id. It is opaque to clients and
unforgeable; tampering, garbage or cross-org use yields
``422 invalid_cursor``. The signature is deterministic, so replaying the
same request returns a byte-identical cursor string (true idempotency).
The cursor encodes read position only — it never substitutes for
authentication or authorization, which are re-checked on every batch.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
from typing import Any, Optional

from .secret import key_bytes

CURSOR_VERSION = 1


class InvalidCursor(Exception):
    """Raised when a cursor cannot be decoded or does not match the org."""


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(payload: bytes) -> bytes:
    return hmac.new(key_bytes(), payload, hashlib.sha256).digest()


def make_cursor(*, org_id: int, range_end: int, last_id: int) -> str:
    payload = json.dumps(
        {"v": CURSOR_VERSION, "org": org_id, "end": range_end, "last": last_id},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _b64u_encode(payload) + "." + _b64u_encode(_sign(payload))


def parse_cursor(cursor: str, org_id: int) -> dict[str, int]:
    """Decode and validate a cursor for the given org.

    Raises ``InvalidCursor`` on any failure: undecodable garbage, bad
    signature, unknown version, or a cursor minted for another org.
    """
    try:
        payload_b64, sig_b64 = cursor.split(".", 1)
        payload = _b64u_decode(payload_b64)
        sig = _b64u_decode(sig_b64)
        if not hmac.compare_digest(sig, _sign(payload)):
            raise InvalidCursor()
        obj = json.loads(payload.decode("utf-8"))
    except InvalidCursor:
        raise
    except Exception:
        # Bad base64, malformed JSON, missing signature, ... one stable code.
        raise InvalidCursor()
    if not isinstance(obj, dict):
        raise InvalidCursor()
    if obj.get("v") != CURSOR_VERSION:
        raise InvalidCursor()
    if obj.get("org") != org_id:
        raise InvalidCursor()
    end = obj.get("end")
    last = obj.get("last")
    if not isinstance(end, int) or isinstance(end, bool):
        raise InvalidCursor()
    if not isinstance(last, int) or isinstance(last, bool):
        raise InvalidCursor()
    if end < 0 or last < 0 or last > end:
        raise InvalidCursor()
    return {"end": end, "last": last}


def audit_item_dict(r: sqlite3.Row) -> dict[str, Any]:
    """Public representation of one audit row (shared by both audit APIs)."""
    return {
        "id": r["id"],
        "org_id": r["org_id"],
        "created_at": r["created_at"],
        "actor_id": r["actor_id"],
        "actor_username": r["actor_username"],
        "action": r["action"],
        "target_type": r["target_type"],
        "target_id": r["target_id"],
        "before": json.loads(r["before_state"]) if r["before_state"] else None,
        "after": json.loads(r["after_state"]) if r["after_state"] else None,
        "batch_id": r["batch_id"],
    }


def scan_page(
    conn: sqlite3.Connection,
    *,
    org_id: int,
    page_size: int,
    cursor: Optional[str],
) -> dict[str, Any]:
    """Return one scan page and the cursor for the next batch.

    With no cursor the range is fixed to the currently committed rows of
    the org (``id <= MAX(id)`` at this instant). With a cursor the same
    range is reused and rows strictly after the cursor position are
    returned. ``next_cursor`` is non-null only when more rows remain after
    this batch; a batch that ends exactly on the range boundary (or an
    empty range) yields ``null``.
    """
    if cursor is not None and cursor.strip() == "":
        raise InvalidCursor()

    if cursor is None:
        # Range-fixing instant: only rows committed right now are visible.
        # Audit rows are append-only with monotonically increasing ids, so
        # later commits get higher ids and can never leak into the range.
        row = conn.execute(
            "SELECT MAX(id) AS m FROM audit_logs WHERE org_id = ?", (org_id,)
        ).fetchone()
        range_end = row["m"] or 0
        last_id = 0
    else:
        parsed = parse_cursor(cursor, org_id)
        range_end = parsed["end"]
        last_id = parsed["last"]

    # Total of the FIXED range: rows are never deleted, so this is the same
    # number on every batch of the scan.
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE org_id = ? AND id <= ?",
        (org_id, range_end),
    ).fetchone()["n"]

    rows = conn.execute(
        """
        SELECT a.*, u.username AS actor_username
        FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_id
        WHERE a.org_id = ? AND a.id <= ? AND a.id > ?
        ORDER BY a.id ASC
        LIMIT ?
        """,
        (org_id, range_end, last_id, page_size),
    ).fetchall()

    items = [audit_item_dict(r) for r in rows]

    next_cursor: Optional[str] = None
    if rows and len(rows) == page_size and rows[-1]["id"] < range_end:
        # The batch is full AND the range continues past its last row.
        next_cursor = make_cursor(
            org_id=org_id, range_end=range_end, last_id=rows[-1]["id"]
        )
    return {"items": items, "total": total, "next_cursor": next_cursor}
