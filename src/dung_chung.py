"""Duong dan va ham dung chung cho cac buoc huan luyen (src/01 ... 07).

Ten file model, bang xep hang, thu muc ket qua... lay tu detector/config.py de
buoc huan luyen va he thong phat hien luon khop nhau.
"""

import sys
from pathlib import Path

import pandas as pd

# Chay truc tiep "python src/04_....py" thi chi co src/ trong sys.path:
# them thu muc goc vao de import duoc goi detector
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector.config import (  # noqa: E402
    BENIGN_LABEL,
    DRIFT_DIR,
    DRIFT_FILE,
    LABEL_ENCODER_FILE,
    METADATA_FILE,
    MODELS_DIR,
    RANKING_COLUMNS,
    RANKING_FILE,
    RESULTS_DIR,
    ROOT,
    SERVICES,
    model_key,
    sort_ranking,
)

RAW_FILE = ROOT / "Dataset" / "Raw" / "CIC-IDS2017" / "Tuesday-WorkingHours.pcap_ISCX.csv"
CLEAN_FILE = ROOT / "Dataset" / "Processed" / "Tuesday_Clean.csv"
SPLIT_DIR = ROOT / "Dataset" / "Processed" / "Train_Test"
# Buoc 03 ghi cach chia du lieu vao day, buoc 04 chep sang models/metadata.json
SPLIT_INFO_FILE = SPLIT_DIR / "thong_tin_chia.json"
# Bang ket qua thi nghiem bo cot "Destination Port" (buoc 04)
PORT_ABLATION_FILE = MODELS_DIR / "thi_nghiem_bo_port.csv"


def importance_file(ten_mo_hinh):
    """File muc do quan trong dac trung cua mot mo hinh (buoc 04 ghi, 05/08 doc)."""
    return MODELS_DIR / f"{model_key(ten_mo_hinh)}_feature_importance.csv"


def doc_du_lieu_goc():
    """Doc CSV goc CIC-IDS2017 (Tuesday), bo khoang trang thua o ten cot va nhan."""
    df = pd.read_csv(RAW_FILE, low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].astype(str).str.strip()
    return df
