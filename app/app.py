import streamlit as st
import pickle, re, math
import pandas as pd
from pathlib import Path

st.set_page_config(page_title="Chống Lừa Đảo URL", page_icon="🛡️", layout="centered")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Be Vietnam Pro', sans-serif; }

.hero {
    background: linear-gradient(135deg, #0f4c81 0%, #1a6cb5 60%, #2196f3 100%);
    border-radius: 20px;
    padding: 2.5rem 2rem 2rem;
    text-align: center;
    margin-bottom: 2rem;
}
.hero h1 { color: white; font-size: 2rem; font-weight: 700; margin-bottom: 0.3rem; }
.hero p  { color: rgba(255,255,255,0.85); font-size: 1rem; margin: 0; }
.hero .badge {
    display: inline-block; background: rgba(255,255,255,0.2);
    color: white; border-radius: 20px; padding: 3px 14px;
    font-size: 0.75rem; margin-bottom: 1rem;
}

.result-safe {
    background: #e8f5e9; border-left: 5px solid #2e7d32;
    border-radius: 12px; padding: 1.5rem; margin: 1rem 0;
}
.result-safe h2 { color: #1b5e20; margin: 0 0 0.5rem; font-size: 1.4rem; }
.result-safe p  { color: #2e7d32; margin: 0; }

.result-danger {
    background: #ffebee; border-left: 5px solid #c62828;
    border-radius: 12px; padding: 1.5rem; margin: 1rem 0;
}
.result-danger h2 { color: #b71c1c; margin: 0 0 0.5rem; font-size: 1.4rem; }
.result-danger p  { color: #c62828; margin: 0; }

.result-warn {
    background: #fff8e1; border-left: 5px solid #f57f17;
    border-radius: 12px; padding: 1.5rem; margin: 1rem 0;
}
.result-warn h2 { color: #e65100; margin: 0 0 0.5rem; font-size: 1.4rem; }
.result-warn p  { color: #f57f17; margin: 0; }

.flag-item {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 14px; border-radius: 8px;
    margin-bottom: 8px; font-size: 0.9rem;
}
.flag-high   { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
.flag-medium { background: #fff3e0; color: #e65100; border: 1px solid #ffe0b2; }
.flag-low    { background: #f3f8ff; color: #1565c0; border: 1px solid #bbdefb; }
.flag-ok     { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }

.score-bar-container {
    background: #e0e0e0; border-radius: 10px;
    height: 14px; margin: 0.5rem 0 1.5rem; overflow: hidden;
}
.score-bar-fill {
    height: 100%; border-radius: 10px;
    transition: width 0.8s ease;
}

.stat-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 10px; margin: 1rem 0;
}
.stat-box {
    background: #f5f5f5; border-radius: 10px;
    padding: 12px; text-align: center;
}
.stat-box .val { font-size: 1.4rem; font-weight: 700; color: #0f4c81; }
.stat-box .lbl { font-size: 0.7rem; color: #757575; margin-top: 2px; }
</style>
""", unsafe_allow_html=True)

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "phishing_model.pkl"

@st.cache_resource
def load_model():
    with open(MODEL_PATH, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['feature_names']

def url_entropy(url):
    if not url: return 0
    return -sum((url.count(c)/len(url))*math.log2(url.count(c)/len(url))
                for c in set(url) if url.count(c) > 0)

def extract_features(url, feature_names):
    features = {k: 0 for k in feature_names}
    try:
        if '//' in url:
            parts = url.split('//')[1].split('/')
            domain = parts[0]
            path = '/'.join(parts[1:]) if len(parts) > 1 else ""
        else:
            domain = ""; path = ""

        query = url.split('?')[1] if '?' in url else ""

        features.update({
            'UrlLength':           len(url),
            'NumDots':             url.count('.'),
            'NumDash':             url.count('-'),
            'NumDashInHostname':   domain.count('-'),
            'AtSymbol':            1 if '@' in url else 0,
            'TildeSymbol':         1 if '~' in url else 0,
            'NumUnderscore':       url.count('_'),
            'NumPercent':          url.count('%'),
            'NumAmpersand':        url.count('&'),
            'NumHash':             url.count('#'),
            'NumNumericChars':     sum(c.isdigit() for c in url),
            'NoHttps':             0 if url.startswith('https') else 1,
            'IpAddress':           1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', url) else 0,
            'SubdomainLevel':      domain.count('.'),
            'HostnameLength':      len(domain),
            'PathLength':          len(path),
            'QueryLength':         len(query),
            'DoubleSlashInPath':   1 if '//' in path else 0,
            'NumSensitiveWords':   sum(1 for w in
                ['login','bank','secure','verify','update','account',
                 'signin','password','confirm','paypal','wallet','free',
                 'lucky','prize','winner','click','urgent'] if w in url.lower()),
            'NumQueryComponents':  query.count('&') + 1 if query else 0,
            'DomainInPaths':       1 if re.search(r'[a-z0-9-]+\.[a-z]{2,}', path) else 0,
            'HttpsInHostname':     1 if 'https' in domain.lower() else 0,
            'RandomString':        1 if url_entropy(url) > 4.2 else 0,
        })
    except: pass
    return features

# ─── UI ───────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="badge">🛡️ Powered by Machine Learning</div>
  <h1>Kiểm tra URL Lừa Đảo</h1>
  <p>Phân tích tức thì — bảo vệ bạn khỏi các trang web giả mạo, lừa đảo</p>
</div>
""", unsafe_allow_html=True)

model = None
if not MODEL_PATH.exists():
    st.warning("⚠️ Chưa có model. Hãy chạy `python train_model.py` trước.")
    st.stop()
try:
    model, feature_names = load_model()
except Exception as e:
    st.error(f"❌ Lỗi load model: {e}")
    st.stop()

url_input = st.text_input("", placeholder="Dán URL vào đây... vd: https://example.com",
                          label_visibility="collapsed")
col1, col2, col3 = st.columns([3,1,3])
with col2:
    check = st.button("🔍 Kiểm tra", type="primary", use_container_width=True)

if check:
    if not url_input.strip():
        st.warning("Vui lòng nhập URL cần kiểm tra.")
    else:
        url = url_input.strip()
        if not url.startswith('http'):
            url = 'https://' + url

        with st.spinner("Đang phân tích..."):
            feat = extract_features(url, feature_names)
            X = pd.DataFrame([feat])[feature_names]
            pred = model.predict(X)[0]
            prob = model.predict_proba(X)[0]
            danger = round(prob[1] * 100, 1)
            safe   = round(prob[0] * 100, 1)

        # Kết quả chính
        if danger >= 70:
            st.markdown(f"""
            <div class="result-danger">
              <h2>⛔ CẢNH BÁO: URL Nguy Hiểm</h2>
              <p>Xác suất lừa đảo: <strong>{danger}%</strong> — Không nên truy cập trang này!</p>
            </div>""", unsafe_allow_html=True)
        elif danger >= 40:
            st.markdown(f"""
            <div class="result-warn">
              <h2>⚠️ Đáng Ngờ — Cẩn Thận</h2>
              <p>Xác suất lừa đảo: <strong>{danger}%</strong> — Hãy xác minh trước khi nhập thông tin.</p>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="result-safe">
              <h2>✅ URL Có Vẻ An Toàn</h2>
              <p>Xác suất an toàn: <strong>{safe}%</strong> — Không phát hiện dấu hiệu lừa đảo rõ ràng.</p>
            </div>""", unsafe_allow_html=True)

        # Thanh tiến trình
        color = "#c62828" if danger >= 70 else "#f57f17" if danger >= 40 else "#2e7d32"
        st.markdown(f"""
        <p style="font-size:0.85rem;color:#666;margin-bottom:4px">Mức độ nguy hiểm</p>
        <div class="score-bar-container">
          <div class="score-bar-fill" style="width:{danger}%;background:{color}"></div>
        </div>""", unsafe_allow_html=True)

        # Thống kê nhanh
        domain = url.split('//')[1].split('/')[0] if '//' in url else url
        st.markdown(f"""
        <div class="stat-grid">
          <div class="stat-box"><div class="val">{feat.get('UrlLength',0)}</div><div class="lbl">Độ dài URL</div></div>
          <div class="stat-box"><div class="val">{feat.get('NumDots',0)}</div><div class="lbl">Số dấu chấm</div></div>
          <div class="stat-box"><div class="val">{feat.get('NumSensitiveWords',0)}</div><div class="lbl">Từ nhạy cảm</div></div>
          <div class="stat-box"><div class="val">{'Có' if feat.get('IpAddress') else 'Không'}</div><div class="lbl">Dùng IP</div></div>
        </div>""", unsafe_allow_html=True)

        # Dấu hiệu chi tiết
        st.markdown("#### 🔎 Phân tích dấu hiệu")
        flags = []
        if feat.get('IpAddress'):         flags.append(('high',   '🔴 Dùng địa chỉ IP thay tên miền — dấu hiệu lừa đảo phổ biến'))
        if feat.get('AtSymbol'):          flags.append(('high',   '🔴 Chứa ký tự @ trong URL'))
        if feat.get('NoHttps'):           flags.append(('medium', '🟠 Không dùng HTTPS — kết nối không mã hóa'))
        if feat.get('NumSensitiveWords',0) >= 2:
            flags.append(('high',   f'🔴 Chứa {feat["NumSensitiveWords"]} từ khóa nhạy cảm (login, bank, verify...)'))
        elif feat.get('NumSensitiveWords',0) == 1:
            flags.append(('medium', '🟠 Chứa từ khóa nhạy cảm trong URL'))
        if feat.get('UrlLength', 0) > 80: flags.append(('medium', f'🟠 URL rất dài ({feat["UrlLength"]} ký tự)'))
        if feat.get('NumDash', 0) > 4:    flags.append(('medium', f'🟠 Nhiều dấu gạch ngang ({feat["NumDash"]})'))
        if feat.get('SubdomainLevel',0) >= 3: flags.append(('high', f'🔴 Tên miền con quá nhiều cấp ({feat["SubdomainLevel"]})'))
        if feat.get('DoubleSlashInPath'):  flags.append(('medium', '🟠 Chứa // trong đường dẫn'))
        if feat.get('RandomString'):      flags.append(('medium', '🟠 Chuỗi ký tự ngẫu nhiên — entropy cao'))
        if feat.get('HttpsInHostname'):   flags.append(('medium', '🟠 Chứa chữ "https" trong tên miền để đánh lừa'))

        if not flags:
            st.markdown('<div class="flag-item flag-ok">✅ Không phát hiện dấu hiệu đáng ngờ rõ ràng</div>', unsafe_allow_html=True)
        else:
            for level, msg in flags:
                css = 'flag-high' if level == 'high' else 'flag-medium' if level == 'medium' else 'flag-low'
                st.markdown(f'<div class="flag-item {css}">{msg}</div>', unsafe_allow_html=True)

        with st.expander("📊 Xem toàn bộ feature vector"):
            st.dataframe(pd.DataFrame([feat]).T.rename(columns={0: 'Giá trị'}),
                         use_container_width=True)

st.divider()
st.caption("🔒 Hệ thống dùng Ensemble ML (Random Forest + XGBoost + Gradient Boosting) · Dữ liệu không được lưu trữ")