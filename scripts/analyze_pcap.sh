#!/usr/bin/env bash
# Che do 2: phan tich file pcap va dem so luong brute-force theo tung mo hinh.
#   ./scripts/analyze_pcap.sh capture.pcap
#   ./scripts/analyze_pcap.sh capture.pcap --attacker-ip 192.168.56.101   # tinh Recall/Precision
#   ./scripts/analyze_pcap.sh capture.pcap --notify                       # gui tom tat len Discord
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Chua co moi truong .venv -> hay chay truoc: bash scripts/setup_ubuntu.sh"; exit 1; }

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Cach dung: $0 <file.pcap|file.pcapng> [--attacker-ip IP | --benign] [--notify] [--all-ports] [-o ket_qua.csv]"
    exec "$PY" -m detector pcap --help
fi

PCAP="$(realpath "$1")"
shift
[[ -f "$PCAP" ]] || { echo "Khong tim thay file: $PCAP"; exit 1; }

cd "$ROOT"
exec "$PY" -W ignore -m detector pcap "$PCAP" "$@"
