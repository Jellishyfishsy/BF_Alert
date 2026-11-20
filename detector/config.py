"""Cau hinh chung: duong dan, cong dich vu, cac nguong thoi gian.

Cac buoc huan luyen trong src/ cung dung file nay (qua src/dung_chung.py), nen ten
file model va bang xep hang chi duoc dinh nghia o day.
"""

import os
from pathlib import Path
from typing import NamedTuple

# Thu muc goc cua project (cha cua thu muc detector/)
ROOT = Path(__file__).resolve().parents[1]

MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "Results"
RANKING_FILE = MODELS_DIR / "ket_qua_so_sanh.csv"
LABEL_ENCODER_FILE = MODELS_DIR / "label_encoder.joblib"

# Ten mo hinh (trung voi cot "Mo hinh" trong ket_qua_so_sanh.csv do buoc 04 ghi)
MODEL_NAMES = ("XGBoost", "Random Forest", "Decision Tree")


def model_key(name: str) -> str:
    """Ten ngan cho ten file va tien to cot ket qua: "Random Forest" -> "random_forest"."""
    return name.lower().replace(" ", "_")


# Thong tin luc huan luyen (phien ban thu vien, dac trung, cach chia du lieu)
METADATA_FILE = MODELS_DIR / "metadata.json"
# Bao cao lech mien dac trung dataset (Java) <-> pcap that (Python), do src/08 ghi
DRIFT_DIR = RESULTS_DIR / "lech_mien"
DRIFT_FILE = DRIFT_DIR / "dac_trung_lech.csv"

# Thu tu uu tien khi xep hang mo hinh (cot trong ket_qua_so_sanh.csv, lon hon = tot hon).
# Recall_Attack (trung binh recall cac lop tan cong) dung dau: voi IDS, bo sot tan cong
# nguy hiem hon bao nham. F1_Macro dung de phan dinh khi bang nhau.
RANKING_COLUMNS = ("Recall_Attack", "F1_Macro")


def sort_ranking(df):
    """Sap xep bang ket qua (DataFrame) theo RANKING_COLUMNS, bo qua cot khong co
    (bang xep hang cu chi co F1_Macro)."""
    cot = [c for c in RANKING_COLUMNS if c in df.columns]
    return df.sort_values(cot, ascending=False, kind="stable").reset_index(drop=True)


BENIGN_LABEL = "BENIGN"


class Service(NamedTuple):
    name: str          # ten dich vu
    attack_label: str  # nhan tan cong brute-force tuong ung trong CIC-IDS2017
    color: int         # mau canh bao Discord


# Dich vu can giam sat theo cong (scripts/capture_pcap.sh cung loc cong 21, 22)
SERVICES = {
    21: Service("FTP", "FTP-Patator", 0xE67E22),
    22: Service("SSH", "SSH-Patator", 0xE74C3C),
}
DEFAULT_PORTS = tuple(SERVICES)

# CICFlowMeter (Java) ket thuc luong sau 120 giay ke tu goi dau tien
FLOW_TIMEOUT = 120.0
# Luong khong co goi moi trong khoang nay se duoc dong de du doan
IDLE_TIMEOUT = 30.0
# Trong khoang nay chi gui 1 canh bao chi tiet cho moi cap (IP tan cong, dich vu),
# cac luong tan cong tiep theo duoc gom thanh 1 tin nhan tong hop
ALERT_COOLDOWN = 60.0


def load_env_file(path: Path = ROOT / ".env") -> None:
    """Doc file .env (KEY=VALUE) vao bien moi truong, khong ghi de bien da co."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
