import numpy as np

from dung_chung import doc_du_lieu_goc

# ==========================================
# 1. DOC DATASET
# 2. CHUAN HOA TEN COT VA NHAN (trong doc_du_lieu_goc)
# ==========================================

print("Dang doc du lieu...")

df = doc_du_lieu_goc()


# ==========================================
# 3. KIEM TRA KICH THUOC DATASET
# ==========================================

print("\n===== KICH THUOC DATASET =====")

print("So dong:", df.shape[0])
print("So cot:", df.shape[1])


# ==========================================
# 4. THONG KE TY LE CAC NHAN
# ==========================================

print("\n===== TY LE CAC NHAN =====")

print(df["Label"].value_counts(normalize=True) * 100)


# ==========================================
# 5. KIEM TRA GIA TRI INFINITY
# ==========================================

print("\n===== KIEM TRA INFINITY =====")

cot_so = df.select_dtypes(include=np.number).columns

so_inf = np.isinf(df[cot_so]).sum()

print("So Infinity tren tung cot:")
print(so_inf[so_inf > 0])

so_dong_inf = np.isinf(df[cot_so]).any(axis=1).sum()

print("So dong co Infinity:", so_dong_inf)


# ==========================================
# 6. KIEM TRA CAC COT DANG CHUOI
# ==========================================

print("\n===== CAC COT DANG CHUOI =====")

cot_chuoi = df.select_dtypes(
    include=["object", "str"]
).columns.tolist()

print(cot_chuoi)


# ==========================================
# 7. KIEM TRA DU LIEU THIEU
# ==========================================

print("\n===== DU LIEU THIEU =====")

so_thieu = df.isnull().sum()

print(so_thieu[so_thieu > 0])

print("Tong gia tri thieu:", df.isnull().sum().sum())


# ==========================================
# 8. KIEM TRA DU LIEU TRUNG LAP
# ==========================================

print("\n===== DU LIEU TRUNG LAP =====")

print("So dong trung lap:", df.duplicated().sum())


# ==========================================
# 9. THONG KE CAC DAC TRUNG SO
# ==========================================

print("\n===== THONG KE DAC TRUNG =====")

print(df[cot_so].describe().T)


# ==========================================
# 10. KET THUC
# ==========================================

print("\n===== HOAN THANH KHAO SAT DU LIEU =====")
