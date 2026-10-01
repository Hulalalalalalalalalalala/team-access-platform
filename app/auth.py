"""Authentication & authorization dependencies.

Session tokens travel in ``Authorization: Bearer <token>`` (or the
``X-Session-Token`` header). Only SHA-256 hashes of tokens are stored, and
tokens are never written to logs.
"""
from __future__ import annotations

import sqlite3
from typing import Optional

from fastapi import Depends, Header, Request

from .db import get_conn
from .errors import forbidden, unauthorized
from .security import hash_token, now_ts


class CurrentUser:
    def __init__(self, row: sqlite3.Row, session_id: int, token: str):
        self.id: int = row["id"]
        self.username: str = row["username"]
        self.session_id = session_id
        self.token = token  # kept in memory only, never logged/returned elsewhere


def _extract_token(authorization: Optional[str], x_session_token: Optional[str]) -> Optional[str]:
    if authorization:
        parts = authorization.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
    if x_session_token:
        return x_session_token.strip()
    return None


async def current_user_optional(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    authorization: Optional[str] = Header(default=None),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
) -> Optional[CurrentUser]:
    token = _extract_token(authorization, x_session_token)
    if not token:
        return None
    row = conn.execute(
        """
        SELECT s.id AS session_id, s.expires_at, s.revoked_at,
               u.id AS id, u.username AS username
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (hash_token(token),),
    ).fetchone()
    if row is None or row["revoked_at"] is not None or row["expires_at"] <= now_ts():
        # Unknown, explicitly logged-out, or expired: uniformly 401.
        raise unauthorized("invalid or expired session")
    return CurrentUser(row, row["session_id"], token)


async def current_user(user: Optional[CurrentUser] = Depends(current_user_optional)) -> CurrentUser:
    if user is None:
        raise unauthorized()
    return user


def require_membership(
    conn: sqlite3.Connection,
    user: CurrentUser,
    org_id: int,
    *,
    admin: bool = False,
) -> sqlite3.Row:
    """Return the membership row or raise 403.

    Non-members, disabled members, and (when ``admin``) non-admins all get
    the same ``403 forbidden`` — including when the organization does not
    exist, so its existence is never revealed to outsiders.
    """
    m = conn.execute(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
        (org_id, user.id),
    ).fetchone()
    if m is None or m["status"] != "active":
        raise forbidden()
    if admin and m["role"] != "admin":
        raise forbidden()
    return m
