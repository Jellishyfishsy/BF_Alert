import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from dung_chung import (
    MODELS_DIR,
    PORT_ABLATION_FILE,
    RANKING_COLUMNS,
    RANKING_FILE,
    RESULTS_DIR,
    importance_file,
    model_key,
    sort_ranking,
)

# ==========================================
# 1. DOC BANG KET QUA SO SANH (BUOC 04)
# ==========================================

print("Dang doc ket qua...")

RESULTS_DIR.mkdir(exist_ok=True)

df = pd.read_csv(RANKING_FILE)

print("\n===== KET QUA CAC MO HINH =====")
print(df.to_string(index=False))


# ==========================================
# 2. KIEM TRA DU LIEU
# ==========================================

print("\n===== KIEM TRA DU LIEU =====")

if df.empty:
    raise ValueError("Bang ket qua khong co du lieu!")

cac_cot_can_thiet = [
    "Mo hinh",
    "Accuracy",
    "Precision_Macro",
    "Recall_Macro",
    "F1_Macro",
    "F1_Weighted",
    "Thoi_gian_train",
    "Thoi_gian_du_doan"
]

for cot in cac_cot_can_thiet:
    if cot not in df.columns:
        raise ValueError(f"Thieu cot: {cot}")

print("Du lieu hop le!")


# ==========================================
# 3. VE BIEU DO SO SANH CAC CHI SO
# ==========================================

print("\nDang ve bieu do so sanh...")

cac_chi_so = [
    "Accuracy",
    "Precision_Macro",
    "Recall_Macro",
    "F1_Macro"
]

# Bang tu buoc 04 moi co them Recall_Attack (tieu chi xep hang chinh)
if "Recall_Attack" in df.columns:
    cac_chi_so.append("Recall_Attack")

df_ve = df.set_index("Mo hinh")[cac_chi_so]

ax = df_ve.plot(
    kind="bar",
    figsize=(12, 6),
    width=0.8
)

plt.title("So sanh cac chi so danh gia mo hinh")
plt.xlabel("Mo hinh")
plt.ylabel("Gia tri")
plt.ylim(0, 1.05)
plt.xticks(rotation=0)
plt.legend(title="Chi so")
plt.grid(axis="y", alpha=0.3)

plt.tight_layout()

plt.savefig(RESULTS_DIR / "01_so_sanh_chi_so.png", dpi=300)

plt.close()


# ==========================================
# 4. VE CONFUSION MATRIX
# ==========================================

print("\nDang ve Confusion Matrix...")

# Buoc 04 ghi confusion matrix cho moi mo hinh co trong bang ket qua
for ten_mo_hinh in df["Mo hinh"]:

    ma_tran = pd.read_csv(
        MODELS_DIR / f"{model_key(ten_mo_hinh)}_confusion_matrix.csv",
        index_col=0
    )

    fig, ax = plt.subplots(figsize=(8, 6))

    hinh = ax.imshow(ma_tran.values)

    fig.colorbar(hinh, ax=ax)

    ax.set_xticks(np.arange(len(ma_tran.columns)))
    ax.set_yticks(np.arange(len(ma_tran.index)))

    ax.set_xticklabels(
        [x.replace("Du_doan_", "") for x in ma_tran.columns],
        rotation=20
    )

    ax.set_yticklabels(
        [x.replace("Thuc_te_", "") for x in ma_tran.index]
    )

    ax.set_xlabel("Nhan du doan")
    ax.set_ylabel("Nhan thuc te")

    ax.set_title("Confusion Matrix - " + ten_mo_hinh)

    # Hien thi so luong tren tung o
    for i in range(ma_tran.shape[0]):
        for j in range(ma_tran.shape[1]):

            ax.text(
                j,
                i,
                str(ma_tran.iloc[i, j]),
                ha="center",
                va="center"
            )

    plt.tight_layout()

    plt.savefig(RESULTS_DIR / f"{model_key(ten_mo_hinh)}_confusion_matrix.png", dpi=300)

    plt.close()


# ==========================================
# 5. SO SANH THOI GIAN HUAN LUYEN
# ==========================================

print("\nDang ve bieu do thoi gian...")

ax = df.plot(
    x="Mo hinh",
    y="Thoi_gian_train",
    kind="bar",
    figsize=(9, 5),
    legend=False
)

plt.title("So sanh thoi gian huan luyen")
plt.xlabel("Mo hinh")
plt.ylabel("Thoi gian (giay)")
plt.xticks(rotation=0)
plt.grid(axis="y", alpha=0.3)

plt.tight_layout()

plt.savefig(RESULTS_DIR / "05_thoi_gian_huan_luyen.png", dpi=300)

plt.close()


# ==========================================
# 6. XEP HANG CAC MO HINH
# ==========================================

print("\n===== XEP HANG MO HINH =====")

print("(xep hang theo", " roi ".join(c for c in RANKING_COLUMNS if c in df.columns) + ")")

df_xep_hang = sort_ranking(df)

df_xep_hang.insert(
    0,
    "Hang",
    np.arange(1, len(df_xep_hang) + 1)
)

print(df_xep_hang.to_string(index=False))

df_xep_hang.to_csv(RESULTS_DIR / "bang_xep_hang.csv", index=False)


# ==========================================
# 7. LUA CHON MO HINH TOT NHAT
# ==========================================

mo_hinh_tot_nhat = df_xep_hang.iloc[0]

print("\n===== MO HINH TOT NHAT (MO HINH CHINH CUA DETECTOR) =====")

print("Ten mo hinh:", mo_hinh_tot_nhat["Mo hinh"])
print("Accuracy:", round(mo_hinh_tot_nhat["Accuracy"], 4))
print("Precision:", round(mo_hinh_tot_nhat["Precision_Macro"], 4))
print("Recall:", round(mo_hinh_tot_nhat["Recall_Macro"], 4))
print("F1 Macro:", round(mo_hinh_tot_nhat["F1_Macro"], 4))
if "Recall_Attack" in df_xep_hang.columns:
    print("Recall tan cong:", round(mo_hinh_tot_nhat["Recall_Attack"], 4))
    print("Bo sot tan cong:", int(mo_hinh_tot_nhat["Bo_sot_tan_cong"]),
          "| Bao nham:", int(mo_hinh_tot_nhat["Bao_nham"]))
print("Thoi gian train:",
      round(mo_hinh_tot_nhat["Thoi_gian_train"], 2),
      "giay")


# ==========================================
# 8. DO QUAN TRONG DAC TRUNG
# ==========================================

print("\nDang ve bieu do do quan trong dac trung...")

for ten_mo_hinh in df["Mo hinh"]:

    f = importance_file(ten_mo_hinh)

    if not f.exists():
        print("  [bo qua] chua co", f.name, "(chay lai buoc 04)")
        continue

    df_qt = pd.read_csv(f).head(15).iloc[::-1]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(df_qt["Dac_trung"], df_qt["Do_quan_trong"])
    ax.set_xlabel("Do quan trong (tong = 1)")
    ax.set_title("15 dac trung quan trong nhat - " + ten_mo_hinh)
    ax.grid(axis="x", alpha=0.3)

    plt.tight_layout()
    plt.savefig(RESULTS_DIR / f"{model_key(ten_mo_hinh)}_feature_importance.png", dpi=300)
    plt.close()

    top = df_qt.iloc[-1]
    print(f"  {ten_mo_hinh:<14} dac trung quan trong nhat: {top['Dac_trung']} "
          f"({top['Do_quan_trong'] * 100:.1f}%)")


# ==========================================
# 9. THI NGHIEM BO DESTINATION PORT (BUOC 04)
# ==========================================

if PORT_ABLATION_FILE.exists():
    print("\n===== THI NGHIEM BO DESTINATION PORT =====")
    print(pd.read_csv(PORT_ABLATION_FILE).to_string(
        index=False, float_format=lambda v: f"{v:.4f}"))


# ==========================================
# 10. HOAN THANH
# ==========================================

print("\n===== HOAN THANH BUOC 05 =====")

print("Da luu ket qua tai:", RESULTS_DIR)
