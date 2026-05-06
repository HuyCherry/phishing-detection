"""
app.py — PhishGuardAI Streamlit UI entry point.
"""
import sys
import pickle
import base64
from pathlib import Path

import streamlit as st

# ─── Setup paths & imports ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")

from config import MODEL_PATH
from ui import tab_check, tab_history, tab_guide, tab_html

# ─── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuardAI — Chống Phishing VN",
    page_icon="🛡️", layout="centered",
)

# ─── Load CSS ────────────────────────────────────────────────────────────────
def load_css():
    css_path = BASE_DIR / "app" / "ui" / "styles.css"
    if css_path.exists():
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# ─── Load model ──────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    with open(MODEL_PATH, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['feature_names']

@st.cache_data
def get_base64_of_bin_file(bin_file):
    try:
        with open(bin_file, 'rb') as f:
            data = f.read()
        return base64.b64encode(data).decode()
    except Exception:
        return ""

# ─── Hero ────────────────────────────────────────────────────────────────────
img_b64 = get_base64_of_bin_file(BASE_DIR / "assets" / "hero.png")
img_html = f'<img src="data:image/png;base64,{img_b64}" style="width: 100%; max-width: 600px; margin-top: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5);">' if img_b64 else ''

st.markdown(f"""
<div class="hero-card" style="margin-bottom: 2rem;">
  <div class="badge">🛡️ Bảo vệ người dùng Việt Nam</div>
  <h1>PhishGuardAI</h1>
  <p>Phân tích tức thì · Machine Learning · Cơ sở dữ liệu mối đe dọa thực tế</p>
  {img_html}
</div>
""", unsafe_allow_html=True)

if not MODEL_PATH.exists():
    st.warning("⚠️ Model chưa được tạo. Chạy: `python scripts/retrain.py`")
    st.stop()

try:
    model, feature_names = load_model()
except Exception as e:
    st.error(f"Lỗi load model: {e}. Chạy lại `python scripts/retrain.py`.")
    st.stop()


# ─── Tabs ────────────────────────────────────────────────────────────────────
t_check, t_html, t_history, t_guide = st.tabs([
    "🔍 Kiểm tra URL", "🌐 Kiểm tra HTML", "📋 Lịch sử & Thống kê", "📖 Hướng dẫn"
])

with t_check:
    tab_check.render(model, feature_names)

with t_html:
    tab_html.render()

with t_history:
    tab_history.render()

with t_guide:
    tab_guide.render()

# ─── Footer ──────────────────────────────────────────────────────────────────
st.divider()
st.caption("🔒  Dữ liệu được lưu trữ và quản lý bởi hệ thống MongoDB nội bộ.")
st.caption("🛡️ Ensemble ML: Random Forest + XGBoost + LightGBM | SSL + WHOIS + VirusTotal + Google SB + URLhaus")