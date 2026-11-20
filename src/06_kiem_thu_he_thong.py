"""Buoc 07: kiem thu he thong phat hien (detector/) tren tap X_test.

Dung chinh EnsemblePredictor cua che do live/pcap (ca 3 mo hinh, xep hang theo Recall tan cong roi F1-macro)
roi so voi nhan thuc te y_test. Confusion matrix cua tung mo hinh phai trung voi buoc 04;
neu khac nghia la detector du doan khac luc huan luyen.
"""

import sys

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from dung_chung import MODELS_DIR, RESULTS_DIR, SPLIT_DIR, model_key
from detector.predictor import EnsemblePredictor  # import sau dung_chung (them thu muc goc vao sys.path)

# 1. Doc du lieu kiem thu
X_test = pd.read_csv(SPLIT_DIR / "X_test.csv")
y_thuc = pd.read_csv(SPLIT_DIR / "y_test.csv").squeeze("columns").astype(str)

# 2. Du doan bang he thong phat hien
he_thong = EnsemblePredictor()
nhan_du_doan = he_thong.labels(he_thong.predict(X_test))
cac_nhan = he_thong.classes

print("===== KET QUA KIEM THU HE THONG =====")
print("So mau kiem thu:", len(X_test))

# 3. Danh gia tung mo hinh va doi chieu voi buoc 04
khong_khop = []
for ten, y_du_doan in nhan_du_doan.items():
    vai_tro = " (mo hinh chinh)" if ten == he_thong.primary else ""
    print(f"\n===== {ten}{vai_tro} =====")
    print("Accuracy:", round(accuracy_score(y_thuc, y_du_doan), 6))
    print(classification_report(y_thuc, y_du_doan, labels=cac_nhan, digits=4, zero_division=0))

    bang_cm = pd.DataFrame(
        confusion_matrix(y_thuc, y_du_doan, labels=cac_nhan),
        index=cac_nhan,
        columns=cac_nhan
    )
    print(bang_cm)
    print("So mau du doan dung:", int((y_thuc == y_du_doan).sum()),
          "| sai:", int((y_thuc != y_du_doan).sum()))

    buoc_04 = pd.read_csv(MODELS_DIR / f"{model_key(ten)}_confusion_matrix.csv", index_col=0)
    khop = (buoc_04.to_numpy() == bang_cm.to_numpy()).all()
    print("Trung voi confusion matrix buoc 04:", "CO" if khop else "KHONG")
    if not khop:
        khong_khop.append(ten)

    bang_cm.to_csv(RESULTS_DIR / f"{model_key(ten)}_confusion_matrix_kiem_thu.csv",
                   encoding="utf-8-sig")

# 4. Ket luan
if khong_khop:
    print("\n[!] Detector du doan khac buoc 04 voi:", ", ".join(khong_khop))
    sys.exit(1)

print(f"\nDetector cho ket qua giong buoc 04 voi ca {len(nhan_du_doan.columns)} mo hinh.")
print("HOAN THANH BUOC 07!")
