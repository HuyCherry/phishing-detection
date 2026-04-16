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
print("📊 Thông tin dataset:")
print(f"- Số dòng: {len(df)}")
print(f"- Cột: {list(df.columns)}")
print(f"\n📋 5 dòng đầu:")
print(df.head())

# Chuẩn hóa tên cột về lowercase
df.columns = df.columns.str.strip().str.lower()

# Đổi tên cột url/label nếu cần
if 'class' in df.columns and 'label' not in df.columns:
    df['label'] = df['class']
if 'type' in df.columns and 'label' not in df.columns:
    df['label'] = df['type'].map({'benign': 0, 'phishing': 1, 'malware': 1, 'defacement': 1})

# Chuyển label về số 0/1
if df['label'].dtype == object:
    df['label'] = df['label'].map({'benign':0, 'good':0, 'safe':0, 'phishing':1, 'malicious':1, 'bad':1})

# Lọc dòng hợp lệ
df = df[['url', 'label']].dropna()
df['label'] = df['label'].astype(int)

# Lưu lại file sạch
df.to_csv("data/clean_data.csv", index=False)
print(f"\n✅ Đã lưu {len(df)} dòng hợp lệ vào data/clean_data.csv")
print(f"📈 Phân phối label:\n{df['label'].value_counts()}")