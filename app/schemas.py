"""Pydantic request/response schemas.

Responses are built as plain dicts in the service layer; request bodies are
validated here. Nothing in any response schema can carry a password hash or
a secret token (tokens are only ever returned once, at creation/login).
"""
from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _username_shape(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("username may contain only letters, digits, '_', '.', '-'")
        return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    # Both fields are plain strings of 1..256 chars; spaces and case are
    # preserved. The explicit before-validator guarantees non-string values
    # (ints, bools, lists, dicts, None) are 422 validation_error rather than
    # being coerced or silently accepted.
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)

    @field_validator("current_password", "new_password", mode="before")
    @classmethod
    def _must_be_string(cls, v: object) -> object:
        if not isinstance(v, str):
            raise ValueError("must be a string")
        return v


class CreateOrgRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class CreateInviteRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    role: Literal["admin", "member"]


class RevokeInviteRequest(BaseModel):
    # Token travels in the body (not the URL path) so it never appears in
    # reverse-proxy/access log lines.
    token: str = Field(min_length=8, max_length=128)


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=8, max_length=128)


class UpdateMemberRequest(BaseModel):
    role: Optional[Literal["admin", "member"]] = None
    status: Optional[Literal["active", "disabled"]] = None


class BatchMemberChange(BaseModel):
    # Strict positive integer: floats/strings/booleans are 422, not silently
    # coerced; role/status reuse the single-entry values.
    user_id: int = Field(gt=0, strict=True)
    role: Optional[Literal["admin", "member"]] = None
    status: Optional[Literal["active", "disabled"]] = None


class BatchUpdateMembersRequest(BaseModel):
    # 1..100 changes per batch; cross-item rules (duplicates, items without
    # any adjustment field) are checked in the endpoint so they share the
    # stable 422 validation_error envelope.
    changes: list[BatchMemberChange] = Field(min_length=1, max_length=100)


class CreateDelegationRequest(BaseModel):
    # strict int: floats / strings / booleans are 422, not silently coerced.
    user_id: int
    duration_seconds: int = Field(ge=60, le=86400, strict=True)
