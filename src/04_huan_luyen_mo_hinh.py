"""Buoc 04: huan luyen va danh gia 3 mo hinh (Decision Tree, Random Forest, XGBoost).

    python src/04_huan_luyen_mo_hinh.py                     # dung tat ca dac trung
    python src/04_huan_luyen_mo_hinh.py --bo-port           # bo "Destination Port"
    python src/04_huan_luyen_mo_hinh.py --bo-co-tcp         # bo 12 cot co TCP (artefact Java)
    python src/04_huan_luyen_mo_hinh.py --bo-cot-lech       # bo dac trung lech (buoc 08)
    python src/04_huan_luyen_mo_hinh.py --bo-cot "SYN Flag Count" "Flow Bytes/s"

Ket qua trong models/ (detector/ nap truc tiep):
    <mo_hinh>.joblib, label_encoder.joblib
    <mo_hinh>_report.txt, <mo_hinh>_confusion_matrix.csv
    <mo_hinh>_feature_importance.csv     do quan trong tung dac trung
    ket_qua_so_sanh.csv                  bang xep hang (Recall_Attack, roi F1_Macro)
    thi_nghiem_bo_port.csv               so sanh co / khong co "Destination Port"
    metadata.json                        phien ban thu vien, dac trung, cach chia du lieu
"""

import argparse
import json
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from dung_chung import (
    BENIGN_LABEL,
    DRIFT_FILE,
    LABEL_ENCODER_FILE,
    METADATA_FILE,
    MODELS_DIR,
    PORT_ABLATION_FILE,
    RANKING_COLUMNS,
    RANKING_FILE,
    SPLIT_DIR,
    SPLIT_INFO_FILE,
    importance_file,
    model_key,
    sort_ranking,
)

from detector.features import TCP_FLAG_FEATURES  # noqa: E402  (sau dung_chung)

COT_PORT = "Destination Port"


# ==========================================
# 1. DOC VA KIEM TRA DU LIEU
# ==========================================

def doc_du_lieu():
    print("Dang doc du lieu...")
    X_train = pd.read_csv(SPLIT_DIR / "X_train.csv")
    X_test = pd.read_csv(SPLIT_DIR / "X_test.csv")
    y_train = pd.read_csv(SPLIT_DIR / "y_train.csv").squeeze("columns")
    y_test = pd.read_csv(SPLIT_DIR / "y_test.csv").squeeze("columns")
    print("Kich thuoc X_train:", X_train.shape)
    print("Kich thuoc X_test:", X_test.shape)
    return X_train, X_test, y_train, y_test


def kiem_tra_du_lieu(X_train, X_test, y_train, y_test):
    print("\n===== KIEM TRA DU LIEU =====")
    if list(X_train.columns) != list(X_test.columns):
        raise ValueError("Cot Train va Test khong khop!")
    if len(X_train) != len(y_train):
        raise ValueError("So mau X_train va y_train khong khop!")
    if len(X_test) != len(y_test):
        raise ValueError("So mau X_test va y_test khong khop!")
    if not np.isfinite(X_train.to_numpy()).all():
        raise ValueError("X_train co gia tri NaN hoac Infinity!")
    if not np.isfinite(X_test.to_numpy()).all():
        raise ValueError("X_test co gia tri NaN hoac Infinity!")
    print("Du lieu hop le!")


def chon_cot_loai_bo(args, cac_cot):
    """Gom cac cot can bo theo tham so dong lenh, bao loi neu ten cot khong ton tai."""
    bo = list(args.bo_cot)
    if args.bo_port:
        bo.append(COT_PORT)
    if args.bo_co_tcp:
        bo += [c for c in TCP_FLAG_FEATURES if c in cac_cot]
    if args.bo_cot_lech:
        if not DRIFT_FILE.exists():
            raise FileNotFoundError(
                f"Chua co {DRIFT_FILE}. Chay truoc: python src/08_kiem_tra_lech_mien.py ...")
        lech = pd.read_csv(DRIFT_FILE)
        bo += lech.loc[lech["Lech"], "Dac_trung"].tolist()

    bo = list(dict.fromkeys(bo))  # bo trung, giu thu tu
    khong_co = [c for c in bo if c not in cac_cot]
    if khong_co:
        raise ValueError(f"Khong co cot: {khong_co}")
    return bo


# ==========================================
# 2. KHOI TAO MO HINH
# ==========================================

def tao_mo_hinh(so_lop, y_train_ma):
    """Ten mo hinh -> (mo hinh, tham so them cho fit)."""
    # XGBoost khong co class_weight nhu DT/RF nen can bang lop bang trong so tung mau
    trong_so_mau = compute_sample_weight(class_weight="balanced", y=y_train_ma)

    return {
        "Decision Tree": (DecisionTreeClassifier(
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42
        ), {}),

        "Random Forest": (RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1
        ), {}),

        "XGBoost": (XGBClassifier(
            objective="multi:softprob",
            num_class=so_lop,
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1
        ), {"sample_weight": trong_so_mau}),
    }


# ==========================================
# 3. DANH GIA
# ==========================================

def tinh_chi_so(y_that, y_du_doan, cac_lop):
    """Cac chi so tong + recall tung lop + chi so rieng cho lop tan cong."""
    nhan = np.arange(len(cac_lop))
    recall_lop = recall_score(y_that, y_du_doan, labels=nhan, average=None, zero_division=0)

    benign = list(cac_lop).index(BENIGN_LABEL)
    lop_tan_cong = [i for i in nhan if i != benign]

    la_tan_cong = y_that != benign
    bao_benign = y_du_doan == benign

    chi_so = {
        "Accuracy": accuracy_score(y_that, y_du_doan),
        "Precision_Macro": precision_score(y_that, y_du_doan, average="macro", zero_division=0),
        "Recall_Macro": recall_score(y_that, y_du_doan, average="macro", zero_division=0),
        "F1_Macro": f1_score(y_that, y_du_doan, average="macro", zero_division=0),
        "F1_Weighted": f1_score(y_that, y_du_doan, average="weighted", zero_division=0),
        # Trung binh recall cac lop tan cong: tieu chi xep hang chinh (RANKING_COLUMNS)
        "Recall_Attack": float(np.mean(recall_lop[lop_tan_cong])),
        # Luong tan cong bi doan la BENIGN (bo sot hoan toan, khong canh bao)
        "Bo_sot_tan_cong": int((la_tan_cong & bao_benign).sum()),
        # Luong BENIGN bi bao la tan cong
        "Bao_nham": int((~la_tan_cong & ~bao_benign).sum()),
    }
    for i in nhan:
        chi_so[f"Recall_{cac_lop[i]}"] = float(recall_lop[i])
    return chi_so


def do_quan_trong(mo_hinh, cac_cot):
    """Muc do quan trong dac trung (chuan hoa tong = 1), sap xep giam dan."""
    gia_tri = np.asarray(mo_hinh.feature_importances_, dtype=float)
    if gia_tri.sum() > 0:
        gia_tri = gia_tri / gia_tri.sum()
    return (pd.DataFrame({"Dac_trung": cac_cot, "Do_quan_trong": gia_tri})
            .sort_values("Do_quan_trong", ascending=False)
            .reset_index(drop=True))


# ==========================================
# 4. HUAN LUYEN
# ==========================================

def huan_luyen(X_train, X_test, y_train_ma, y_test_ma, cac_lop, luu=True):
    """Huan luyen 3 mo hinh, tra ve bang ket qua. luu=True: ghi model + bao cao vao models/."""
    ket_qua = []
    nhan = np.arange(len(cac_lop))

    for ten_mo_hinh, (mo_hinh, tham_so_fit) in tao_mo_hinh(len(cac_lop), y_train_ma).items():

        print("\n" + "=" * 50)
        print("DANG HUAN LUYEN:", ten_mo_hinh)
        print("=" * 50)

        bat_dau = time.time()
        mo_hinh.fit(X_train, y_train_ma, **tham_so_fit)
        thoi_gian_train = time.time() - bat_dau
        print("Thoi gian huan luyen:", round(thoi_gian_train, 2), "giay")

        bat_dau = time.time()
        y_du_doan = mo_hinh.predict(X_test)
        thoi_gian_du_doan = time.time() - bat_dau

        chi_so = tinh_chi_so(y_test_ma, y_du_doan, cac_lop)

        print("\n===== KET QUA DANH GIA =====")
        for k in ("Accuracy", "Precision_Macro", "Recall_Macro", "F1_Macro", "F1_Weighted",
                  "Recall_Attack"):
            print(f"{k}: {chi_so[k]:.4f}")
        print("Bo sot tan cong:", chi_so["Bo_sot_tan_cong"], "| Bao nham:", chi_so["Bao_nham"])

        ket_qua.append({
            "Mo hinh": ten_mo_hinh,
            **chi_so,
            "Thoi_gian_train": thoi_gian_train,
            "Thoi_gian_du_doan": thoi_gian_du_doan,
        })

        if not luu:
            continue

        ten_file = model_key(ten_mo_hinh)

        bao_cao = classification_report(
            y_test_ma, y_du_doan, labels=nhan, target_names=cac_lop, digits=4, zero_division=0
        )
        print("\n===== CLASSIFICATION REPORT =====")
        print(bao_cao)
        (MODELS_DIR / f"{ten_file}_report.txt").write_text(bao_cao, encoding="utf-8")

        df_ma_tran = pd.DataFrame(
            confusion_matrix(y_test_ma, y_du_doan, labels=nhan),
            index=["Thuc_te_" + x for x in cac_lop],
            columns=["Du_doan_" + x for x in cac_lop]
        )
        print("\n===== CONFUSION MATRIX =====")
        print(df_ma_tran)
        df_ma_tran.to_csv(MODELS_DIR / f"{ten_file}_confusion_matrix.csv")

        # Mo hinh dua vao dac trung nao: neu 1 dac trung (vd. Destination Port) chiem
        # gan het thi mo hinh de bi qua mat khi dich vu chay o cong khac
        df_qt = do_quan_trong(mo_hinh, list(X_train.columns))
        print("\n===== 10 DAC TRUNG QUAN TRONG NHAT =====")
        print(df_qt.head(10).to_string(index=False, float_format=lambda v: f"{v:.4f}"))
        df_qt.to_csv(importance_file(ten_mo_hinh), index=False)

        joblib.dump(mo_hinh, MODELS_DIR / f"{ten_file}.joblib")

    return pd.DataFrame(ket_qua)


def thi_nghiem_bo_port(ket_qua_goc, X_train, X_test, y_train_ma, y_test_ma, cac_lop):
    """Huan luyen lai 3 mo hinh KHONG co Destination Port (khong luu model) va so sanh.

    Neu diem giam manh khi bo port, mo hinh dang nhan dien tan cong chu yeu bang so
    cong chu khong phai bang hanh vi luong -> se bo sot khi SSH/FTP chay o cong khac.
    """
    print("\n" + "#" * 60)
    print(f"THI NGHIEM: HUAN LUYEN LAI KHONG CO '{COT_PORT}'")
    print("#" * 60)

    khong_port = huan_luyen(X_train.drop(columns=[COT_PORT]), X_test.drop(columns=[COT_PORT]),
                            y_train_ma, y_test_ma, cac_lop, luu=False)

    cot = ["F1_Macro", "Recall_Attack", "Bo_sot_tan_cong", "Bao_nham"]
    bang = ket_qua_goc.set_index("Mo hinh")[cot].join(
        khong_port.set_index("Mo hinh")[cot], lsuffix="_co_port", rsuffix="_khong_port")
    for c in ("F1_Macro", "Recall_Attack"):
        bang[f"{c}_chenh_lech"] = bang[f"{c}_khong_port"] - bang[f"{c}_co_port"]
    bang = bang.reset_index()

    print("\n===== SO SANH CO / KHONG CO DESTINATION PORT =====")
    print(bang.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    bang.to_csv(PORT_ABLATION_FILE, index=False)
    return bang


# ==========================================
# 5. CHUONG TRINH CHINH
# ==========================================

def main(argv=None):
    parser = argparse.ArgumentParser(description="Huan luyen 3 mo hinh phat hien brute-force")
    parser.add_argument("--bo-cot", nargs="+", default=[], metavar="COT",
                        help="Bo cac dac trung nay khi huan luyen")
    parser.add_argument("--bo-port", action="store_true",
                        help=f"Bo '{COT_PORT}' (mo hinh phai hoc hanh vi, khong dua vao so cong)")
    parser.add_argument("--bo-co-tcp", action="store_true",
                        help="Bo 12 cot co TCP (artefact cua CICFlowMeter Java, khong tai tao duoc)")
    parser.add_argument("--bo-cot-lech", action="store_true",
                        help=f"Bo cac dac trung bi danh dau lech trong {DRIFT_FILE.name} (buoc 08)")
    parser.add_argument("--khong-thi-nghiem-port", action="store_true",
                        help="Bo qua thi nghiem huan luyen lai khong co Destination Port")
    args = parser.parse_args(argv)

    X_train, X_test, y_train, y_test = doc_du_lieu()
    kiem_tra_du_lieu(X_train, X_test, y_train, y_test)

    cot_bo = chon_cot_loai_bo(args, list(X_train.columns))
    if cot_bo:
        print(f"\nBo {len(cot_bo)} dac trung: {cot_bo}")
        X_train = X_train.drop(columns=cot_bo)
        X_test = X_test.drop(columns=cot_bo)
    print("So dac trung dung de huan luyen:", X_train.shape[1])

    # --- Ma hoa nhan ---
    print("\n===== MA HOA NHAN =====")
    bo_ma_hoa = LabelEncoder()
    y_train_ma = bo_ma_hoa.fit_transform(y_train)
    y_test_ma = bo_ma_hoa.transform(y_test)
    cac_lop = list(bo_ma_hoa.classes_)
    print("Danh sach nhan:", cac_lop)

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(bo_ma_hoa, LABEL_ENCODER_FILE)

    # --- Huan luyen + xep hang ---
    df_ket_qua = sort_ranking(huan_luyen(X_train, X_test, y_train_ma, y_test_ma, cac_lop))

    print("\n===== BANG SO SANH MO HINH =====")
    print(f"(xep hang theo {' roi '.join(RANKING_COLUMNS)})")
    print(df_ket_qua.to_string(index=False))
    df_ket_qua.to_csv(RANKING_FILE, index=False)

    # --- Thi nghiem bo Destination Port ---
    if COT_PORT in X_train.columns and not args.khong_thi_nghiem_port:
        thi_nghiem_bo_port(df_ket_qua, X_train, X_test, y_train_ma, y_test_ma, cac_lop)

    # --- Metadata ---
    thong_tin_chia = (json.loads(SPLIT_INFO_FILE.read_text(encoding="utf-8"))
                      if SPLIT_INFO_FILE.exists() else {"cach_chia": "khong ro"})
    METADATA_FILE.write_text(json.dumps({
        "ngay_huan_luyen": datetime.now().isoformat(timespec="seconds"),
        "phien_ban": {
            "scikit-learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "chia_du_lieu": thong_tin_chia,
        "nhan": cac_lop,
        "dac_trung_bi_bo": cot_bo,
        "dac_trung": list(X_train.columns),
        "xep_hang_theo": list(RANKING_COLUMNS),
        "mo_hinh_chinh": df_ket_qua.iloc[0]["Mo hinh"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\nDa luu tat ca ket qua tai:", MODELS_DIR)
    print("Mo hinh chinh (hang 1):", df_ket_qua.iloc[0]["Mo hinh"])
    print("\n===== HOAN THANH HUAN LUYEN =====")


if __name__ == "__main__":
    main()
