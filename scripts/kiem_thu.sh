#!/usr/bin/env bash
# Chay MOT kich ban kiem thu tren may Ubuntu: ghi pcap -> (Kali tan cong) -> phan tich.
#   sudo ./scripts/kiem_thu.sh <interface> <ten_kich_ban> <IP_Kali | --benign>
#
# Vi du:
#   sudo ./scripts/kiem_thu.sh enp0s8 03_hydra_ssh 192.168.56.101
#   sudo ./scripts/kiem_thu.sh enp0s8 07_binh_thuong --benign
#
# Ket qua (ten co dinh theo kich ban de buoc tong hop doc duoc):
#   pcaps/<ten>.pcap
#   Results/kiem_thu/<ten>.csv            du doan tung luong
#   Results/kiem_thu/<ten>_danh_gia.csv   TP/FN/FP/Recall/Precision tung mo hinh
# Sau khi chay du cac kich ban: .venv/bin/python src/07_tong_hop_kiem_thu.py
set -euo pipefail

if [[ $# -lt 3 ]]; then
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

IFACE="$1"
TEN="$2"
NHAN="$3"
shift 3

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Chua co .venv -> chay truoc: ./scripts/setup_ubuntu.sh"; exit 1; }

if [[ "$EUID" -ne 0 ]]; then
    echo "Can quyen root de bat goi tin -> chay lai bang sudo"
    exec sudo "$0" "$IFACE" "$TEN" "$NHAN" "$@"
fi

if [[ "$NHAN" == "--benign" ]]; then
    DANH_GIA=(--benign)
    SYN_FILTER='tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
else
    DANH_GIA=(--attacker-ip "$NHAN")
    SYN_FILTER="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and src host $NHAN"
fi

# File ket qua thuoc ve user thuong (khong phai root) de sua/xoa duoc ve sau
CHU="${SUDO_USER:-root}"
chay_user() { if [[ "$CHU" != root ]]; then sudo -u "$CHU" "$@"; else "$@"; fi; }

cd "$ROOT"
PCAP="pcaps/$TEN.pcap"
OUT_DIR="Results/kiem_thu"
chay_user mkdir -p pcaps "$OUT_DIR"

if [[ -f "$PCAP" ]]; then
    read -r -p "Da co $PCAP. Ghi de? [y/N] " tl
    [[ "$tl" =~ ^[yY]$ ]] || { echo "Huy."; exit 1; }
fi

echo "=================================================================="
echo " Kich ban: $TEN | interface: $IFACE | nhan: $NHAN"
echo "=================================================================="
tcpdump -i "$IFACE" -s 0 -U -w "$PCAP" 'tcp and (port 21 or port 22)' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1
kill -0 "$TCPDUMP_PID" 2>/dev/null || { echo "tcpdump khong chay duoc (sai interface?)"; exit 1; }

echo ">> Dang ghi pcap. Bay gio chay lenh tan cong tren Kali."
echo ">> Khi Kali chay XONG, doi them ~5 giay roi nhan Enter de dung ghi va phan tich."
read -r _
kill -INT "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null || true
chown "$CHU": "$PCAP" 2>/dev/null || true

SO_SYN=$(tcpdump -r "$PCAP" -nn "$SYN_FILTER" 2>/dev/null | wc -l)
echo ">> So ket noi mo (goi SYN) trong pcap: $SO_SYN"
if [[ "$SO_SYN" -eq 0 ]]; then
    echo "[!] Khong co ket noi nao -> kiem tra lai IP Kali/interface. Bo qua phan tich."
    exit 1
fi

chay_user "$PY" -W ignore -m detector pcap "$PCAP" "${DANH_GIA[@]}" -o "$OUT_DIR/$TEN.csv" "$@"
