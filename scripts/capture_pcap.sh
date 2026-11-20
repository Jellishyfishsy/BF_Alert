#!/usr/bin/env bash
# Ghi lai luu luong cong 21/22 thanh file pcap trong luc kiem thu (Ctrl+C de dung).
#   sudo ./scripts/capture_pcap.sh enp0s8 pcaps/hydra_ssh.pcap
set -euo pipefail

IFACE="${1:?Cach dung: $0 <interface> <file.pcap>}"
OUT="${2:?Cach dung: $0 <interface> <file.pcap>}"

mkdir -p "$(dirname "$OUT")"
echo "Dang ghi $IFACE (cong 21, 22) vao $OUT ... Nhan Ctrl+C de dung."
exec sudo tcpdump -i "$IFACE" -s 0 -w "$OUT" 'tcp and (port 21 or port 22)'
