#!/usr/bin/env bash
# Cai dat moi truong tren may nan nhan Ubuntu (24.04 tro len, can Python >= 3.12).
#   ./scripts/setup_ubuntu.sh            # cai thu vien + tao .venv
#   ./scripts/setup_ubuntu.sh --services # cai them OpenSSH server va vsftpd de lam muc tieu
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Loi o mot nguon goi (vd. nguon cdrom con sot lai sau khi cai tu ISO) khong nen
# chan ca qua trinh: cac nguon con lai van duoc cap nhat
sudo apt-get update || echo ">> [!] apt-get update co loi o mot nguon goi (xem o tren) - van tiep tuc cai dat"
sudo apt-get install -y python3 python3-venv python3-pip tcpdump libpcap0.8

if [[ "${1:-}" == "--services" ]]; then
    sudo apt-get install -y openssh-server vsftpd
    sudo systemctl enable --now ssh vsftpd
fi

python3 - <<'EOF'
import sys
if sys.version_info < (3, 12):
    sys.exit("Can Python >= 3.12 (cicflowmeter 0.5.0). Hay dung Ubuntu 24.04 tro len.")
EOF

# .venv chep tu Windows (co Scripts/ thay vi bin/) khong dung duoc tren Linux
if [[ -d .venv && ! -x .venv/bin/python ]]; then
    echo ">> Xoa .venv khong dung duoc tren Linux (co the chep tu Windows)"
    rm -rf .venv
fi

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

if [[ ! -f .env ]]; then
    cp .env.example .env
    echo ">> Da tao .env - hay dien DISCORD_WEBHOOK_URL roi chay: ./scripts/test_discord.sh"
fi

chmod +x scripts/*.sh
echo ">> Cai dat xong. Interface mang hien co:"
ip -brief address
