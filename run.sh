#!/usr/bin/env bash
# Start the Team Access Platform HTTP service.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip >/dev/null
    ./.venv/bin/pip install -r requirements.txt
fi

export APP_HOST="${APP_HOST:-127.0.0.1}"
export APP_PORT="${APP_PORT:-8000}"
export APP_DB_PATH="${APP_DB_PATH:-$(pwd)/data/app.db}"
# export APP_INVITE_TTL=86400   # invite lifetime seconds (default 24h)

exec ./.venv/bin/uvicorn app.main:app --host "$APP_HOST" --port "$APP_PORT"
