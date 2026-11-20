"""Buoc 08: kiem tra LECH MIEN dac trung giua dataset va luu luong that.

Mo hinh hoc tren dac trung do CICFlowMeter ban Java sinh ra (CIC-IDS2017), nhung khi
chay that dac trung lai do cicflowmeter ban Python tinh (detector/features.py). Neu mot
dac trung co phan phoi khac han giua hai ben ma mo hinh lai dua nhieu vao no, mo hinh
se doan sai tren luu luong that du diem tren tap test rat cao (vd. Random Forest bo sot
100% SSH khi kiem thu bang Kali).

Script nay, voi tung lop (FTP-Patator, SSH-Patator, BENIGN tren cong 21/22):
  1. Trich dac trung tu cac file pcap kiem thu bang chinh pipeline cua detector.
  2. So sanh phan phoi tung dac trung voi dataset bang kiem dinh Kolmogorov-Smirnov
     (KS = 0: giong het, KS = 1: tach biet hoan toan), kem trung vi hai ben.
  3. Danh dau dac trung LECH (KS >= nguong) va tinh xem bao nhieu % "do quan trong"
     cua tung mo hinh nam tren cac dac trung lech do (= muc rui ro cua mo hinh).

Cach dung (tren may co pcap, thuong la Ubuntu sau khi chay scripts/kiem_thu.sh):
    .venv/bin/python src/08_kiem_tra_lech_mien.py pcaps/01_patator_ssh.pcap \\
        pcaps/02_patator_ftp.pcap --attacker-ip 192.168.56.101 \\
        --benign pcaps/08_binh_thuong.pcap

    # Lan sau (hoac tren may khac) dung lai dac trung da trich, khong can doc pcap:
    python src/08_kiem_tra_lech_mien.py --tu-csv Results/lech_mien/dac_trung_pcap.csv

Ket qua (Results/lech_mien/):
    dac_trung_pcap.csv      dac trung da trich tu pcap + nhan (de chay lai/nhanh)
    lech_<lop>.csv          chi tiet tung dac trung cho moi lop
    dac_trung_lech.csv      tong hop: KS lon nhat, co lech hay khong, rui ro theo mo hinh
Buoc 04 co the bo cac dac trung lech khi huan luyen: python src/04_... --bo-cot-lech
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

from dung_chung import (
    BENIGN_LABEL,
    CLEAN_FILE,
    DRIFT_DIR,
    DRIFT_FILE,
    SERVICES,
    importance_file,
)
from detector.config import MODEL_NAMES  # noqa: E402  (sau dung_chung: da them goc vao sys.path)
from detector.features import check_feature_names, records_to_frames  # noqa: E402

PCAP_FEATURE_FILE = DRIFT_DIR / "dac_trung_pcap.csv"
# It hon so luong nay o mot phia thi KS khong dang tin -> bo qua lop do
MIN_SAMPLES = 20


# ==========================================
# 1. TRICH DAC TRUNG TU PCAP
# ==========================================

def trich_pcap(path, feature_names, attacker_ip, benign):
    """Doc mot file pcap bang FlowTracker cua detector, gan nhan cho tung luong.

    Gan nhan giong CIC-IDS2017 (theo CHIEU luong, goi dau tien quyet dinh chieu):
      - src = IP tan cong, dst port = 21/22  -> FTP-/SSH-Patator (ke ca manh vun)
      - dst port = 21/22, src khac           -> BENIGN
      - con lai (vd. manh vun do may chu mo, dst port la cong tam cua client): BO, vi
        dataset chi co cong 21/22 o cot Destination Port cua cac lop dang so sanh.
    """
    from detector.cli import read_pcap  # can scapy + cicflowmeter
    from detector.flow_tracker import FlowTracker

    ports = tuple(SERVICES)
    print(f"Dang doc {path} ...")
    records = read_pcap(path, FlowTracker(ports=ports))
    if not records:
        print("  (khong co luong nao tren cong 21/22)")
        return None

    meta, X = records_to_frames(records, feature_names, ports)
    toi_dich_vu = meta["dst_port"].isin(ports)
    if benign:
        la_tan_cong = pd.Series(False, index=meta.index)
    else:
        la_tan_cong = (meta["src_ip"] == attacker_ip) & toi_dich_vu
    nhan_tan_cong = meta["dst_port"].map({p: s.attack_label for p, s in SERVICES.items()})
    nhan = nhan_tan_cong.where(la_tan_cong, BENIGN_LABEL)

    X["Label"] = nhan.to_numpy()
    X["has_syn"] = meta["has_syn"].to_numpy()
    X["Nguon"] = Path(path).name
    X = X[toi_dich_vu.to_numpy()].reset_index(drop=True)
    print(f"  {len(X)} luong: " + ", ".join(f"{k}={v}" for k, v in X["Label"].value_counts().items()))
    return X


# ==========================================
# 2. SO SANH PHAN PHOI
# ==========================================

def so_sanh_lop(ds, pc, feature_names, nguong):
    """Bang so sanh tung dac trung giua dataset (ds) va pcap (pc) cua cung mot lop."""
    hang = []
    for cot in feature_names:
        a = ds[cot].to_numpy(dtype=float)
        b = pc[cot].to_numpy(dtype=float)
        ks = ks_2samp(a, b)
        tv_a, tv_b = float(np.median(a)), float(np.median(b))
        hang.append({
            "Dac_trung": cot,
            "KS": ks.statistic,
            "p_value": ks.pvalue,
            "Trung_vi_dataset": tv_a,
            "Trung_vi_pcap": tv_b,
            # Ty le pcap/dataset, de thay loi don vi (vd. lech 1e6 lan)
            "Ty_le_trung_vi": tv_b / tv_a if tv_a else (np.nan if tv_b else 1.0),
            "Ty_le_0_dataset": float((a == 0).mean()),
            "Ty_le_0_pcap": float((b == 0).mean()),
        })
    bang = pd.DataFrame(hang)
    bang["Lech"] = bang["KS"] >= nguong
    return bang.sort_values("KS", ascending=False).reset_index(drop=True)


def doc_do_quan_trong(feature_names):
    """Do quan trong dac trung cua tung mo hinh (buoc 04 ghi). Thieu file thi bo qua."""
    bang = {}
    for ten in MODEL_NAMES:
        f = importance_file(ten)
        if f.exists():
            s = pd.read_csv(f, index_col="Dac_trung")["Do_quan_trong"]
            bang[ten] = s.reindex(feature_names).fillna(0.0)
    if not bang:
        print("[!] Chua co file *_feature_importance.csv (chay lai buoc 04) -> bo qua phan rui ro.")
    return pd.DataFrame(bang)


# ==========================================

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("pcap", nargs="*", help="File pcap co tan cong tu --attacker-ip")
    p.add_argument("--attacker-ip", help="IP may Kali trong cac file pcap tan cong")
    p.add_argument("--benign", nargs="+", default=[], metavar="PCAP",
                   help="File pcap chi co luu luong binh thuong")
    p.add_argument("--tu-csv", type=Path,
                   help=f"Dung dac trung da trich san (mac dinh ghi o {PCAP_FEATURE_FILE})")
    p.add_argument("--nguong", type=float, default=0.5,
                   help="KS >= nguong thi coi la lech (mac dinh 0.5)")
    p.add_argument("--chi-ket-noi", action="store_true",
                   help="Chi dung luong co goi SYN phia pcap (mac dinh dung ca manh vun, giong dataset)")
    args = p.parse_args(argv)

    if not args.tu_csv and not (args.pcap or args.benign):
        p.error("Can it nhat mot file pcap hoac --tu-csv")
    if args.pcap and not args.attacker_ip:
        p.error("File pcap tan cong can --attacker-ip")

    # --- Dataset ---
    print("Dang doc dataset:", CLEAN_FILE)
    ds = pd.read_csv(CLEAN_FILE)
    feature_names = [c for c in ds.columns if c != "Label"]
    check_feature_names(feature_names)
    # Pcap chi bat cong 21/22 -> so BENIGN voi phan BENIGN cua dataset tren cung cong do
    ds = ds[(ds["Label"] != BENIGN_LABEL) | ds["Destination Port"].isin(list(SERVICES))]

    # --- Pcap ---
    DRIFT_DIR.mkdir(parents=True, exist_ok=True)
    if args.tu_csv:
        pc = pd.read_csv(args.tu_csv)
    else:
        phan = [trich_pcap(f, feature_names, args.attacker_ip, False) for f in args.pcap]
        phan += [trich_pcap(f, feature_names, None, True) for f in args.benign]
        phan = [x for x in phan if x is not None]
        if not phan:
            sys.exit("Khong trich duoc luong nao tu cac file pcap.")
        pc = pd.concat(phan, ignore_index=True)
        pc.to_csv(PCAP_FEATURE_FILE, index=False, encoding="utf-8")
        print("Da luu dac trung pcap:", PCAP_FEATURE_FILE)

    if args.chi_ket_noi:
        pc = pc[pc["has_syn"].astype(bool)]

    # --- So sanh tung lop ---
    ket_qua = {}
    for lop in sorted(set(ds["Label"]) & set(pc["Label"])):
        a, b = ds[ds["Label"] == lop], pc[pc["Label"] == lop]
        if min(len(a), len(b)) < MIN_SAMPLES:
            print(f"\n[bo qua] {lop}: qua it mau (dataset {len(a)}, pcap {len(b)})")
            continue
        bang = so_sanh_lop(a, b, feature_names, args.nguong)
        bang.to_csv(DRIFT_DIR / f"lech_{lop}.csv", index=False, encoding="utf-8-sig")
        ket_qua[lop] = bang

        print(f"\n===== {lop}: dataset {len(a)} luong | pcap {len(b)} luong =====")
        print(f"So dac trung lech (KS >= {args.nguong}): {int(bang['Lech'].sum())}/{len(bang)}")
        cot_in = ["Dac_trung", "KS", "Trung_vi_dataset", "Trung_vi_pcap", "Ty_le_trung_vi"]
        print(bang[cot_in].head(15).to_string(index=False, float_format=lambda v: f"{v:.4g}"))

    if not ket_qua:
        sys.exit("Khong co lop nao du mau de so sanh.")

    # --- Tong hop: moi dac trung lay KS lon nhat qua cac lop ---
    ks = pd.DataFrame({lop: b.set_index("Dac_trung")["KS"] for lop, b in ket_qua.items()})
    tong = pd.DataFrame({
        "KS_max": ks.max(axis=1),
        "Lop_lech_nhat": ks.idxmax(axis=1),
    })
    tong["Lech"] = tong["KS_max"] >= args.nguong
    for lop in ks.columns:
        tong[f"KS_{lop}"] = ks[lop]

    quan_trong = doc_do_quan_trong(feature_names)
    for ten in quan_trong.columns:
        tong[f"Quan_trong_{ten}"] = quan_trong[ten]
        tong[f"Rui_ro_{ten}"] = tong["KS_max"] * quan_trong[ten]

    tong = tong.sort_values("KS_max", ascending=False).rename_axis("Dac_trung").reset_index()
    tong.to_csv(DRIFT_FILE, index=False, encoding="utf-8-sig")

    lech = tong[tong["Lech"]]
    print("\n" + "=" * 60)
    print(f"TONG HOP: {len(lech)}/{len(tong)} dac trung lech (KS >= {args.nguong})")
    print("=" * 60)
    if len(lech):
        print(", ".join(lech["Dac_trung"]))

    if len(quan_trong.columns):
        print("\nPhan do quan trong cua moi mo hinh nam tren dac trung LECH")
        print("(cang cao, mo hinh cang de doan sai tren luu luong that):")
        for ten in quan_trong.columns:
            phan_tram = quan_trong.loc[lech["Dac_trung"], ten].sum() * 100
            top = lech.sort_values(f"Rui_ro_{ten}", ascending=False)["Dac_trung"].head(3)
            print(f"  {ten:<14} {phan_tram:6.2f}%   (rui ro nhat: {', '.join(top)})")

    print("\nDa luu:", DRIFT_FILE)
    print("Huan luyen lai khong dung cac dac trung lech: python src/04_huan_luyen_mo_hinh.py --bo-cot-lech")


if __name__ == "__main__":
    main()
