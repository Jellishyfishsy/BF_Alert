#!/usr/bin/env bash
# Gui tin nhan thu de kiem tra DISCORD_WEBHOOK_URL trong file .env
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Chua co moi truong .venv -> hay chay truoc: bash scripts/setup_ubuntu.sh"; exit 1; }
cd "$ROOT"
exec "$PY" -m detector test-discord
