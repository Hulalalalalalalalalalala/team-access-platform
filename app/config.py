"""Runtime configuration, read from environment."""
from __future__ import annotations

import os
from pathlib import Path

# SQLite database file. Data persists across restarts.
DB_PATH = Path(
    os.environ.get(
        "APP_DB_PATH",
        str(Path(__file__).resolve().parent.parent / "data" / "app.db"),
    )
)

# Idle backstop for sessions (absolute cap); logout always invalidates immediately.
SESSION_TTL_SECONDS = int(os.environ.get("APP_SESSION_TTL", str(60 * 60 * 24 * 30)))

# Single-use invitations expire 24h after creation.
INVITE_TTL_SECONDS = int(os.environ.get("APP_INVITE_TTL", str(24 * 60 * 60)))

# PBKDF2 parameters for password hashing.
PBKDF2_ITERATIONS = int(os.environ.get("APP_PBKDF2_ITERATIONS", "240000"))

# Token entropy.
SESSION_TOKEN_BYTES = 32  # 256-bit session ids
INVITE_TOKEN_BYTES = 20   # 160-bit invite tokens
