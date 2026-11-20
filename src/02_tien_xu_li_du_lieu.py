import numpy as np

from dung_chung import CLEAN_FILE, doc_du_lieu_goc

# ==========================================
# 1. DOC DU LIEU GOC
# ==========================================

print("Dang doc du lieu...")

df = doc_du_lieu_goc()

print("So dong ban dau:", len(df))


# ==========================================
# 2. CHUYEN INFINITY THANH NaN
# ==========================================

print("\n===== XU LY INFINITY =====")

cot_so = df.select_dtypes(include=np.number).columns

so_inf_truoc = np.isinf(df[cot_so]).sum().sum()

print("Tong Infinity truoc xu ly:", so_inf_truoc)

df.replace([np.inf, -np.inf], np.nan, inplace=True)

print("Tong NaN sau khi chuyen Infinity:")
print(df.isnull().sum().sum())


# ==========================================
# 3. XU LY DU LIEU THIEU
# ==========================================

print("\n===== XU LY DU LIEU THIEU =====")

so_dong_truoc = len(df)

df.dropna(inplace=True)

so_dong_sau = len(df)

print("So dong truoc:", so_dong_truoc)
print("So dong sau:", so_dong_sau)
print("So dong da xoa:", so_dong_truoc - so_dong_sau)


# ==========================================
# 4. XU LY DU LIEU TRUNG LAP
# ==========================================

print("\n===== XU LY DU LIEU TRUNG LAP =====")

so_dong_truoc = len(df)

df.drop_duplicates(inplace=True)

so_dong_sau = len(df)

print("So dong truoc:", so_dong_truoc)
print("So dong sau:", so_dong_sau)
print("So dong trung lap da xoa:", so_dong_truoc - so_dong_sau)


# ==========================================
# 5. KIEM TRA LAI DU LIEU
# ==========================================

print("\n===== KIEM TRA SAU TIEN XU LY =====")

print("Kich thuoc Dataset:", df.shape)

print("Tong NaN:", df.isnull().sum().sum())

cot_so = df.select_dtypes(include=np.number).columns

print("Tong Infinity:", np.isinf(df[cot_so]).sum().sum())

print("So dong trung lap:", df.duplicated().sum())

print("\nTy le cac nhan sau xu ly:")

print(df["Label"].value_counts(normalize=True) * 100)


# ==========================================
# 6. LUU DATASET DA XU LY
# ==========================================

print("\n===== LUU DU LIEU =====")

CLEAN_FILE.parent.mkdir(parents=True, exist_ok=True)

df.to_csv(CLEAN_FILE, index=False)

print("Da luu tai:", CLEAN_FILE)

print("\n===== HOAN THANH TIEN XU LY =====")
