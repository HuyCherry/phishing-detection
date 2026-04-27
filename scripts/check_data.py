import pandas as pd
import os

# Đường dẫn file
file_path = "data/phishing_dataset.csv"

# Đọc file (thử các encoding phổ biến nếu lỗi)
try:
    df = pd.read_csv(file_path, encoding='utf-8')
except:
    df = pd.read_csv(file_path, encoding='latin-1')

# Hiển thị thông tin cơ bản
print("Thong tin dataset:")
print(f"- So dong: {len(df)}")
print(f"- Cot: {list(df.columns)}")
print(f"\n5 dong dau:")
print(df.head())

# Tìm cột label
label_col = None
for col in ['CLASS_LABEL', 'class_label', 'label', 'class', 'type']:
    if col in df.columns:
        label_col = col
        break

if label_col:
    # Chuyển label về số 0/1 nếu là string
    if df[label_col].dtype == object:
        df[label_col] = df[label_col].map({'benign':0, 'good':0, 'safe':0, 'phishing':1, 'malicious':1, 'bad':1})
    
    # Lọc dòng hợp lệ
    df = df.dropna()
    df[label_col] = df[label_col].astype(int)
    
    # Lưu lại file sạch
    os.makedirs("data", exist_ok=True)
    df.to_csv("data/clean_data.csv", index=False)
    print(f"\nDa luu {len(df)} dong hop le vao data/clean_data.csv")
    print(f"Phan phoi label:\n{df[label_col].value_counts()}")
else:
    print("\nKhong tim thay cot label hop le!")