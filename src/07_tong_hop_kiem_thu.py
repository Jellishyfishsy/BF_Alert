"""Buoc 07 (kiem thu that): gom cac file Results/kiem_thu/*_danh_gia.csv thanh bang
so sanh 3 mo hinh x cac kich ban tan cong (Patator/Hydra/Medusa/Ncrack/binh thuong).

Chay sau khi da dung scripts/kiem_thu.sh cho tung kich ban tren may Ubuntu:
    .venv/bin/python src/07_tong_hop_kiem_thu.py

Ket qua:
    Results/kiem_thu/tong_hop_recall.csv     Recall tung mo hinh x kich ban
    Results/kiem_thu/tong_hop_bao_nham.csv   Ty le bao nham tung mo hinh x kich ban
    Results/kiem_thu/tong_hop.csv            bang gop day du (dlong form)
"""

import sys
from pathlib import Path

import pandas as pd

from dung_chung import RESULTS_DIR

KT_DIR = RESULTS_DIR / "kiem_thu"


def doc_cac_bang():
    """Doc moi *_danh_gia.csv -> dict {ten_kich_ban: DataFrame}."""
    files = sorted(KT_DIR.glob("*_danh_gia.csv"))
    if not files:
        sys.exit(f"Khong tim thay file *_danh_gia.csv trong {KT_DIR}. "
                 "Hay chay scripts/kiem_thu.sh cho tung kich ban truoc.")
    bang = {}
    for f in files:
        ten = f.name[:-len("_danh_gia.csv")]
        df = pd.read_csv(f)
        # Cot "Mo hinh" co the kem hau to " (chinh)" -> bo di de khop giua cac kich ban
        df["Mo hinh"] = df["Mo hinh"].str.replace(r"\s*\(chinh\)$", "", regex=True)
        bang[ten] = df.set_index("Mo hinh")
    return bang


def main():
    bang = doc_cac_bang()
    print(f"Da doc {len(bang)} kich ban: {', '.join(bang)}")

    # Bang dong (long form): moi dong = 1 mo hinh trong 1 kich ban
    gop = pd.concat(
        {ten: df for ten, df in bang.items()}, names=["Kich ban", "Mo hinh"]
    ).reset_index()
    gop.to_csv(KT_DIR / "tong_hop.csv", index=False, encoding="utf-8-sig")

    # Bang Recall: hang = mo hinh, cot = kich ban
    recall = gop.pivot(index="Mo hinh", columns="Kich ban", values="Recall")
    recall.to_csv(KT_DIR / "tong_hop_recall.csv", encoding="utf-8-sig")

    bao_nham = gop.pivot(index="Mo hinh", columns="Kich ban", values="Ty le bao nham")
    bao_nham.to_csv(KT_DIR / "tong_hop_bao_nham.csv", encoding="utf-8-sig")

    fmt = lambda v: "-" if pd.isna(v) else f"{v:.4f}"
    print("\n===== RECALL (ty le phat hien) theo mo hinh x kich ban =====")
    print(recall.to_string(float_format=fmt, na_rep="-"))
    print("\n===== TY LE BAO NHAM theo mo hinh x kich ban =====")
    print("(kich ban binh thuong --benign khong co tan cong nen Recall = '-')")
    print(bao_nham.to_string(float_format=fmt, na_rep="-"))

    # Xep hang tren luu luong THAT: diem tap test (buoc 04) qua lac quan, nen day moi la
    # can cu chinh de chon mo hinh chinh cho detector
    xep_hang = pd.DataFrame({
        "Recall_TB": recall.mean(axis=1),            # trung binh cac kich ban tan cong
        "Recall_thap_nhat": recall.min(axis=1),      # kich ban te nhat
        "Bao_nham_TB": bao_nham.mean(axis=1),
    }).sort_values(["Recall_TB", "Bao_nham_TB"], ascending=[False, True])
    xep_hang.rename_axis("Mo hinh").reset_index().to_csv(
        KT_DIR / "xep_hang_that.csv", index=False, encoding="utf-8-sig")

    print("\n===== XEP HANG TREN LUU LUONG THAT (Recall TB giam dan, bao nham tang dan) =====")
    print(xep_hang.to_string(float_format=fmt, na_rep="-"))
    tot_nhat = xep_hang.index[0]
    print(f"\n=> Nen dung mo hinh chinh: {tot_nhat}")
    print(f"   sudo ./scripts/run_live.sh -i <iface> --primary-model \"{tot_nhat}\"")

    print("\nDa luu:")
    for ten in ("tong_hop.csv", "tong_hop_recall.csv", "tong_hop_bao_nham.csv", "xep_hang_that.csv"):
        print("  ", KT_DIR / ten)


if __name__ == "__main__":
    main()
