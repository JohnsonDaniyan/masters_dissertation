#!/bin/sh
set -e
ENV_FILE="${MOCK_LAB_ENV_PATH:-/app/.env}"
mkdir -p "$(dirname "$ENV_FILE")"
if [ ! -s "$ENV_FILE" ]; then
  cp /app/.env.example "$ENV_FILE"
fi
chmod 777 "$(dirname "$ENV_FILE")"
chmod 666 "$ENV_FILE"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
