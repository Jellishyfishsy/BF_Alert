"""Buoc 03: tach X/y va chia Train/Test.

Hai cach chia (tham so --chia):
  thoi_gian  (mac dinh) Voi TUNG nhan, 80% luong dau tien (theo thu tu trong file goc,
             gan dung thu tu thoi gian) vao Train, 20% cuoi vao Test. Test vi vay la
             phan SAU cua dot tan cong, mo hinh chua thay -> danh gia sat thuc te hon.
  ngau_nhien Chia ngau nhien co phan tang (cach cu). Cac luong cua cung mot dot
             patator gan nhu giong het nhau roi vao ca Train lan Test, nen diem Test
             gan 100% chu yeu do mo hinh "nho" du lieu.

File CSV goc CIC-IDS2017 (MachineLearningCVE) khong co cot Timestamp, nhung cac dong
duoc ghi theo thu tu luong ket thuc: FTP-Patator (sang) nam truoc SSH-Patator (chieu).
Buoc 02 chi xoa dong (dropna, drop_duplicates) nen thu tu nay duoc giu nguyen.
"""

import argparse
import json

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from dung_chung import CLEAN_FILE, SPLIT_DIR, SPLIT_INFO_FILE

TY_LE_TEST = 0.2

parser = argparse.ArgumentParser(description="Chia du lieu Train/Test")
parser.add_argument("--chia", choices=["thoi_gian", "ngau_nhien"], default="thoi_gian",
                    help="Cach chia du lieu (mac dinh: thoi_gian)")
args = parser.parse_args()


def chia_theo_thoi_gian(X, y, ty_le_test):
    """Voi moi nhan: phan dau -> Train, phan cuoi -> Test (giu thu tu dong)."""
    la_test = pd.Series(False, index=y.index)
    for nhan, idx in y.groupby(y, sort=False).groups.items():
        idx = sorted(idx)  # theo thu tu dong trong file = gan dung thu tu thoi gian
        so_test = int(round(len(idx) * ty_le_test))
        la_test.loc[idx[len(idx) - so_test:]] = True
    return X[~la_test], X[la_test], y[~la_test], y[la_test]


# ==========================================
# 1. DOC DU LIEU DA TIEN XU LY
# ==========================================

print("Dang doc du lieu...")

df = pd.read_csv(CLEAN_FILE)

print("Kich thuoc Dataset:", df.shape)


# ==========================================
# 2. KIEM TRA DU LIEU
# ==========================================

print("\n===== KIEM TRA DU LIEU =====")

print("Tong NaN:", df.isnull().sum().sum())
print("So dong trung lap:", df.duplicated().sum())

if "Label" not in df.columns:
    raise ValueError("Khong tim thay cot Label!")

if df.isnull().sum().sum() > 0:
    raise ValueError("Du lieu van con gia tri thieu!")

# Kiem tra cac cot vo cuc
so_infinity = np.isinf(df.select_dtypes(include=np.number)).sum().sum()

if so_infinity > 0:
    raise ValueError("Du lieu van con Infinity!")


# ==========================================
# 3. TACH X VA y
# ==========================================

print("\n===== TACH X VA y =====")

X = df.drop(columns=["Label"])
y = df["Label"]

print("So cot dac trung X:", X.shape[1])
print("So mau nhan y:", y.shape[0])

# Kiem tra X co cot khong phai dang so hay khong
cot_khong_phai_so = X.select_dtypes(exclude=np.number).columns.tolist()

if cot_khong_phai_so:
    raise ValueError(
        f"Cac cot X khong phai dang so: {cot_khong_phai_so}"
    )


# ==========================================
# 4. CHIA TRAIN VA TEST
# ==========================================

print("\n===== CHIA DU LIEU TRAIN / TEST =====")
print("Cach chia:", args.chia)

if args.chia == "thoi_gian":
    X_train, X_test, y_train, y_test = chia_theo_thoi_gian(X, y, TY_LE_TEST)
else:
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TY_LE_TEST,
        random_state=42,
        stratify=y
    )

print("So mau Train:", len(X_train))
print("So mau Test:", len(X_test))


# ==========================================
# 5. KIEM TRA TY LE NHAN
# ==========================================

print("\n===== TY LE NHAN TRONG TRAIN =====")

print(y_train.value_counts())
print(y_train.value_counts(normalize=True) * 100)

print("\n===== TY LE NHAN TRONG TEST =====")

print(y_test.value_counts())
print(y_test.value_counts(normalize=True) * 100)


# ==========================================
# 6. LUU DU LIEU
# ==========================================

print("\n===== LUU DU LIEU =====")

SPLIT_DIR.mkdir(parents=True, exist_ok=True)

X_train.to_csv(SPLIT_DIR / "X_train.csv", index=False)
X_test.to_csv(SPLIT_DIR / "X_test.csv", index=False)
y_train.to_csv(SPLIT_DIR / "y_train.csv", index=False)
y_test.to_csv(SPLIT_DIR / "y_test.csv", index=False)

# Ghi lai cach chia de buoc 04 luu vao metadata cua mo hinh
SPLIT_INFO_FILE.write_text(json.dumps({
    "cach_chia": args.chia,
    "ty_le_test": TY_LE_TEST,
    "so_mau_train": len(X_train),
    "so_mau_test": len(X_test),
}, ensure_ascii=False, indent=2), encoding="utf-8")

print("Da luu du lieu tai:", SPLIT_DIR)

print("\n===== HOAN THANH CHUAN BI DU LIEU =====")
