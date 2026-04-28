"""
app.py — Streamlit UI for Phishing URL Detection.
"""
import os
import sys
import time
import pickle
import sqlite3
import pandas as pd
import streamlit as st
from pathlib import Path
from datetime import datetime

# Load .env
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model" / "phishing_model.pkl"
DB_PATH = BASE_DIR / "data" / "history.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Import advanced features
sys.path.insert(0, str(BASE_DIR))
from utils.advanced_features import (
    extract_lexical_features,
    check_ssl,
    check_domain_age,
    check_homograph,
    check_virustotal,
    check_google_safe_browsing,
    check_urlhaus,
)

# ─── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(page_title="Chong Lua Dao URL", page_icon="🛡️", layout="centered")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Be Vietnam Pro', sans-serif; }

.hero {
    background: linear-gradient(135deg, #0f4c81 0%, #1a6cb5 60%, #2196f3 100%);
    border-radius: 20px; padding: 2.5rem 2rem 2rem; text-align: center; margin-bottom: 2rem;
}
.hero h1 { color: white; font-size: 2rem; font-weight: 700; margin-bottom: 0.3rem; }
.hero p  { color: rgba(255,255,255,0.85); font-size: 1rem; margin: 0; }
.hero .badge {
    display: inline-block; background: rgba(255,255,255,0.2);
    color: white; border-radius: 20px; padding: 3px 14px;
    font-size: 0.75rem; margin-bottom: 1rem;
}

.result-safe   { background: #e8f5e9; border-left: 5px solid #2e7d32; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-safe h2 { color: #1b5e20; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-safe p  { color: #2e7d32; margin: 0; }

.result-danger  { background: #ffebee; border-left: 5px solid #c62828; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-danger h2 { color: #b71c1c; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-danger p  { color: #c62828; margin: 0; }

.result-warn   { background: #fff8e1; border-left: 5px solid #f57f17; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-warn h2 { color: #e65100; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-warn p  { color: #f57f17; margin: 0; }

.flag-item   { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:8px; margin-bottom:8px; font-size:.9rem; }
.flag-high   { background:#ffebee; color:#c62828; border:1px solid #ffcdd2; }
.flag-medium { background:#fff3e0; color:#e65100; border:1px solid #ffe0b2; }
.flag-low    { background:#fffde7; color:#f57f17; border:1px solid #fff9c4; }
.flag-ok     { background:#e8f5e9; color:#2e7d32; border:1px solid #c8e6c9; }

.score-bar-container { background:#e0e0e0; border-radius:10px; height:14px; margin:.5rem 0 1.5rem; overflow:hidden; }
.score-bar-fill      { height:100%; border-radius:10px; transition:width .8s ease; }

.stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:1rem 0; }
.stat-box  { background:#f5f5f5; border-radius:10px; padding:12px; text-align:center; }
.stat-box .val { font-size:1.4rem; font-weight:700; color:#0f4c81; }
.stat-box .lbl { font-size:.7rem; color:#757575; margin-top:2px; }
</style>
""", unsafe_allow_html=True)


# ─── SQLite helpers ───────────────────────────────────────────────────────────

def _init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            risk_score REAL,
            verdict TEXT,
            checked_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def _save_history(url, risk_score, verdict):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO history (url, risk_score, verdict, checked_at) VALUES (?,?,?,?)",
        (url, risk_score, verdict, str(datetime.now()))
    )
    conn.commit()
    conn.close()

def _load_history(limit=20):
    conn = sqlite3.connect(str(DB_PATH))
    df = pd.read_sql_query(
        "SELECT url, risk_score, verdict, checked_at FROM history ORDER BY id DESC LIMIT ?",
        conn, params=(limit,)
    )
    conn.close()
    return df

def _clear_history():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()

_init_db()


# ─── Load model ──────────────────────────────────────────────────────────────

@st.cache_resource
def load_model():
    with open(MODEL_PATH, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['feature_names']


# ─── Hero ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero">
  <div class="badge">🛡️ Powered by Machine Learning</div>
  <h1>Kiem tra URL Lua Dao</h1>
  <p>Phan tich tuc thi — bao ve ban khoi cac trang web gia mao, lua dao</p>
</div>
""", unsafe_allow_html=True)

if not MODEL_PATH.exists():
    st.warning("Model chua duoc tao. Chay: python scripts/retrain.py")
    st.stop()

try:
    model, feature_names = load_model()
except EOFError:
    st.error("File model bi hong (EOFError). Chay lai retrain.py.")
    st.stop()
except Exception as e:
    st.error(f"Loi load model: {e}")
    st.stop()


# ─── Tabs ─────────────────────────────────────────────────────────────────────

tab_check, tab_history = st.tabs(["🔍 Kiem tra URL", "📋 Lich su kiem tra"])

with tab_check:
    mode = st.toggle("Kiem tra day du (bao gom API)", value=False)
    use_apis = mode

    url_input = st.text_input("", placeholder="Dan URL vao day... vd: example.com",
                              label_visibility="collapsed")
    col1, col2, col3 = st.columns([3, 1, 3])
    with col2:
        check_btn = st.button("🔍 Kiem tra", type="primary", use_container_width=True)

    if check_btn:
        if not url_input.strip():
            st.warning("Vui long nhap URL can kiem tra.")
        else:
            url = url_input.strip()
            if not url.startswith('http'):
                url = 'https://' + url

            # Parse domain
            try:
                domain = url.split('//')[1].split('/')[0].split(':')[0]
            except Exception:
                domain = url

            # ── Progress bar ──────────────────────────────────────────────
            steps = 7 if use_apis else 4
            progress = st.progress(0)

            with st.status("Dang phan tich...", expanded=True) as status:

                # 1) Lexical
                st.write("Trich xuat dac trung URL...")
                lexical = extract_lexical_features(url)
                progress.progress(1 / steps)

                # 2) SSL
                st.write("Kiem tra SSL...")
                ssl_info = check_ssl(domain)
                progress.progress(2 / steps)

                # 3) Domain age
                st.write("Kiem tra tuoi domain...")
                age_info = check_domain_age(domain)
                progress.progress(3 / steps)

                # 4) Homograph
                st.write("Kiem tra domain gia mao...")
                homo_info = check_homograph(domain)
                progress.progress(4 / steps)

                vt_info = {'vt_positives': 0, 'vt_total': 0, 'vt_is_malicious': 0}
                gsb_info = {'gsb_is_dangerous': 0, 'gsb_threat_type': 'none'}
                uh_info = {'urlhaus_is_malicious': 0, 'urlhaus_threat': 'none'}

                if use_apis:
                    vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
                    gsb_key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

                    st.write("Truy van VirusTotal...")
                    vt_info = check_virustotal(url, vt_key)
                    progress.progress(5 / steps)

                    st.write("Truy van Google Safe Browsing...")
                    gsb_info = check_google_safe_browsing(url, gsb_key)
                    progress.progress(6 / steps)

                    st.write("Truy van URLhaus...")
                    uh_info = check_urlhaus(url)
                    progress.progress(7 / steps)

                progress.progress(1.0)
                status.update(label="Hoan tat!", state="complete")

            # ── ML Prediction ─────────────────────────────────────────────
            ordered = {k: lexical.get(k, 0) for k in feature_names}
            X_pred = pd.DataFrame([ordered])
            prob = model.predict_proba(X_pred)[0]
            ml_score = round(prob[1] * 100, 1)

            # ── Risk score ────────────────────────────────────────────────
            risk = ml_score
            if vt_info.get('vt_is_malicious'):
                risk += 30
            if gsb_info.get('gsb_is_dangerous'):
                risk += 25
            if uh_info.get('urlhaus_is_malicious'):
                risk += 20
            if age_info.get('domain_is_new'):
                risk += 10
            if homo_info.get('is_lookalike'):
                risk += 15
            if ssl_info.get('ssl_valid') == 0:
                risk += 10
            risk = min(risk, 100)
            risk = round(risk, 1)

            # ── Verdict ───────────────────────────────────────────────────
            if risk >= 70:
                verdict = "NGUY HIEM"
                st.markdown(f"""<div class="result-danger">
                  <h2>⛔ NGUY HIEM CAO</h2>
                  <p>Risk score: <strong>{risk}%</strong> — Khong nen truy cap!</p>
                </div>""", unsafe_allow_html=True)
            elif risk >= 40:
                verdict = "DANG NGO"
                st.markdown(f"""<div class="result-warn">
                  <h2>⚠️ DANG NGO</h2>
                  <p>Risk score: <strong>{risk}%</strong> — Can than khi nhap thong tin.</p>
                </div>""", unsafe_allow_html=True)
            else:
                verdict = "AN TOAN"
                st.markdown(f"""<div class="result-safe">
                  <h2>✅ AN TOAN</h2>
                  <p>Risk score: <strong>{risk}%</strong> — Khong phat hien dau hieu lua dao.</p>
                </div>""", unsafe_allow_html=True)

            # ── Progress bar visual ───────────────────────────────────────
            color = "#c62828" if risk >= 70 else "#f57f17" if risk >= 40 else "#2e7d32"
            st.markdown(f"""
            <p style="font-size:.85rem;color:#666;margin-bottom:4px">Muc do nguy hiem</p>
            <div class="score-bar-container">
              <div class="score-bar-fill" style="width:{risk}%;background:{color}"></div>
            </div>""", unsafe_allow_html=True)

            # ── Row 1: 4 cards ────────────────────────────────────────────
            st.markdown(f"""
            <div class="stat-grid">
              <div class="stat-box"><div class="val">{ml_score}%</div><div class="lbl">ML Score</div></div>
              <div class="stat-box"><div class="val">{risk}%</div><div class="lbl">Risk Score</div></div>
              <div class="stat-box"><div class="val">{'✅' if ssl_info['ssl_valid'] else '❌'}</div><div class="lbl">SSL</div></div>
              <div class="stat-box"><div class="val">{age_info['domain_age_days']}d</div><div class="lbl">Domain Age</div></div>
            </div>""", unsafe_allow_html=True)

            # ── Row 2: 4 cards ────────────────────────────────────────────
            st.markdown(f"""
            <div class="stat-grid">
              <div class="stat-box"><div class="val">{vt_info['vt_positives']}/{vt_info['vt_total']}</div><div class="lbl">VirusTotal</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if gsb_info['gsb_is_dangerous'] else '✅'}</div><div class="lbl">Google SB</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if uh_info['urlhaus_is_malicious'] else '✅'}</div><div class="lbl">URLhaus</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if homo_info['is_lookalike'] else '✅'}</div><div class="lbl">Homograph</div></div>
            </div>""", unsafe_allow_html=True)

            # ── Flags ─────────────────────────────────────────────────────
            st.markdown("#### 🔎 Phan tich dau hieu")
            flags = []

            # Red flags
            if vt_info.get('vt_is_malicious'):
                flags.append(('high', f"🔴 VirusTotal: {vt_info['vt_positives']} engines phat hien doc hai"))
            if gsb_info.get('gsb_is_dangerous'):
                flags.append(('high', f"🔴 Google Safe Browsing: {gsb_info['gsb_threat_type']}"))
            if lexical.get('IpAddress'):
                flags.append(('high', '🔴 Dung dia chi IP thay ten mien'))
            if homo_info.get('is_lookalike'):
                flags.append(('high', f"🔴 Domain giong '{homo_info['lookalike_brand']}' (homograph)"))

            # Orange flags
            if uh_info.get('urlhaus_is_malicious'):
                flags.append(('medium', f"🟠 URLhaus: {uh_info['urlhaus_threat']}"))
            if age_info.get('domain_is_new'):
                flags.append(('medium', f"🟠 Domain moi ({age_info['domain_age_days']} ngay)"))
            if ssl_info.get('ssl_valid') == 0:
                flags.append(('medium', '🟠 Khong co SSL hop le'))
            if lexical.get('NumSensitiveWords', 0) >= 2:
                flags.append(('medium', f"🟠 Chua {lexical['NumSensitiveWords']} tu khoa nhay cam"))

            # Yellow flags
            if lexical.get('NoHttps'):
                flags.append(('low', '🟡 Khong dung HTTPS'))
            if lexical.get('UrlLength', 0) > 80:
                flags.append(('low', f"🟡 URL dai ({lexical['UrlLength']} ky tu)"))
            if lexical.get('SuspiciousTLD'):
                flags.append(('low', '🟡 TLD dang ngo'))
            if homo_info.get('has_punycode'):
                flags.append(('low', '🟡 Chua Punycode (xn--)'))

            if not flags:
                st.markdown('<div class="flag-item flag-ok">✅ Khong phat hien dau hieu dang ngo</div>',
                            unsafe_allow_html=True)
            else:
                for level, msg in flags:
                    css = {'high': 'flag-high', 'medium': 'flag-medium', 'low': 'flag-low'}[level]
                    st.markdown(f'<div class="flag-item {css}">{msg}</div>', unsafe_allow_html=True)

            # ── Feature vector ────────────────────────────────────────────
            with st.expander("📊 Xem toan bo feature vector"):
                all_feat = {**lexical, **ssl_info, **age_info, **homo_info, **vt_info, **gsb_info, **uh_info}
                st.dataframe(pd.DataFrame([all_feat]).T.rename(columns={0: 'Gia tri'}),
                             use_container_width=True)

            # Save to history
            _save_history(url, risk, verdict)

with tab_history:
    st.markdown("#### 📋 Lich su kiem tra (20 gan nhat)")
    hist_df = _load_history()
    if hist_df.empty:
        st.info("Chua co lich su kiem tra.")
    else:
        st.dataframe(hist_df, use_container_width=True)

    if st.button("🗑️ Xoa lich su"):
        _clear_history()
        st.success("Da xoa lich su.")
        st.rerun()

st.divider()
st.caption("🔒 Ensemble ML: Random Forest + XGBoost + LightGBM | SSL + WHOIS + VirusTotal + Google SB + URLhaus")