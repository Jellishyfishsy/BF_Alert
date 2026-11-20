#!/usr/bin/env bash
# Che do 1 (mac dinh): giam sat thoi gian thuc, canh bao qua Discord.
#   sudo ./scripts/run_live.sh -i enp0s8
#   sudo ./scripts/run_live.sh -i enp0s8 --quiet --cooldown 30
# Xem tat ca tuy chon: ./scripts/run_live.sh --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Chua co moi truong .venv -> hay chay truoc: bash scripts/setup_ubuntu.sh"; exit 1; }

if [[ "${1:-}" != "--help" && "${1:-}" != "-h" && "$EUID" -ne 0 ]]; then
    echo "Can quyen root de bat goi tin -> chay lai bang sudo"
    exec sudo "$0" "$@"
fi

cd "$ROOT"
exec "$PY" -W ignore -m detector live "$@"
