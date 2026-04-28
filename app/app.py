"""
app.py — Streamlit UI cho hệ thống phát hiện URL lừa đảo.
Bảo vệ người dùng Việt Nam khỏi phishing, scam, malware.
"""
import os
import sys
import time
import pickle
import pandas as pd
import streamlit as st
from pathlib import Path
from datetime import datetime

# ─── Setup paths & imports ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")

from config import (
    MODEL_PATH, RISK_DANGEROUS, RISK_SUSPICIOUS,
    WEIGHT_VT_MALICIOUS, WEIGHT_GSB_DANGEROUS, WEIGHT_URLHAUS_MALICIOUS,
    WEIGHT_LOOKALIKE, WEIGHT_DOMAIN_NEW, WEIGHT_SSL_INVALID,
    WEIGHT_SUBDOMAIN_SPOOF, REPORT_TYPES,
)
from utils.advanced_features import (
    extract_lexical_features, check_ssl, check_domain_age,
    check_homograph, check_virustotal, check_google_safe_browsing,
    check_urlhaus,
)
from utils.legit_domain_checker import check_legitimate_domain
from utils.community_reports import (
    log_check, submit_report, get_url_report_count,
    get_recent_checks, get_recent_reports, get_stats, clear_checks,
)

# ─── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Kiểm tra URL Lừa Đảo — Chống Phishing VN",
    page_icon="🛡️", layout="centered",
)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Be Vietnam Pro', sans-serif; }

.hero {
    background: linear-gradient(135deg, #0f4c81 0%, #1976d2 60%, #42a5f5 100%);
    border-radius: 20px; padding: 2.5rem 2rem 2rem; text-align: center;
    margin-bottom: 2rem; box-shadow: 0 8px 32px rgba(15,76,129,0.3);
}
.hero h1 { color: white; font-size: 2rem; font-weight: 700; margin-bottom: 0.3rem; }
.hero p  { color: rgba(255,255,255,0.85); font-size: 1rem; margin: 0; }
.hero .badge {
    display: inline-block; background: rgba(255,255,255,0.2);
    color: white; border-radius: 20px; padding: 3px 14px;
    font-size: 0.75rem; margin-bottom: 1rem;
}

.result-safe   { background: #e8f5e9; border-left: 5px solid #2e7d32;
                  border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-safe h2 { color: #1b5e20; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-safe p  { color: #2e7d32; margin: 0; }

.result-danger  { background: #ffebee; border-left: 5px solid #c62828;
                  border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-danger h2 { color: #b71c1c; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-danger p  { color: #c62828; margin: 0; }

.result-warn   { background: #fff8e1; border-left: 5px solid #f57f17;
                 border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.result-warn h2 { color: #e65100; margin: 0 0 .5rem; font-size: 1.4rem; }
.result-warn p  { color: #f57f17; margin: 0; }

.result-official { background: #e3f2fd; border-left: 5px solid #1565c0;
                   border-radius: 12px; padding: 1rem 1.5rem; margin: .5rem 0; }
.result-official p { color: #0d47a1; margin: 0; font-weight: 600; }

.flag-item   { display:flex; align-items:center; gap:10px; padding:10px 14px;
               border-radius:8px; margin-bottom:8px; font-size:.9rem; }
.flag-high   { background:#ffebee; color:#c62828; border:1px solid #ffcdd2; }
.flag-medium { background:#fff3e0; color:#e65100; border:1px solid #ffe0b2; }
.flag-low    { background:#fffde7; color:#f57f17; border:1px solid #fff9c4; }
.flag-ok     { background:#e8f5e9; color:#2e7d32; border:1px solid #c8e6c9; }

.score-bar-container { background:#e0e0e0; border-radius:10px; height:14px;
                       margin:.5rem 0 1.5rem; overflow:hidden; }
.score-bar-fill      { height:100%; border-radius:10px; transition:width .8s ease; }

.stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin:1rem 0; }
.stat-box  { background:#f5f5f5; border-radius:10px; padding:12px; text-align:center; }
.stat-box .val { font-size:1.4rem; font-weight:700; color:#0f4c81; }
.stat-box .lbl { font-size:.7rem; color:#757575; margin-top:2px; }
</style>
""", unsafe_allow_html=True)


# ─── Load model ──────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    with open(MODEL_PATH, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['feature_names']


# ─── Hero ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
  <div class="badge">🛡️ Bảo vệ người dùng Việt Nam</div>
  <h1>Kiểm tra URL Lừa Đảo</h1>
  <p>Phân tích tức thì · Machine Learning · Cơ sở dữ liệu mối đe dọa thực tế</p>
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
tab_check, tab_history, tab_guide = st.tabs([
    "🔍 Kiểm tra URL", "📋 Lịch sử & Thống kê", "📖 Hướng dẫn"
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1: KIỂM TRA URL
# ══════════════════════════════════════════════════════════════════════════════
with tab_check:
    url_input = st.text_input(
        "", placeholder="Dán URL vào đây... VD: vietcombank.com.vn",
        label_visibility="collapsed",
    )

    col_q, col_f = st.columns(2)
    with col_q:
        quick_btn = st.button("⚡ Kiểm tra nhanh", use_container_width=True)
    with col_f:
        full_btn = st.button("🔍 Kiểm tra đầy đủ", type="primary", use_container_width=True)

    check_btn = quick_btn or full_btn
    use_apis = full_btn

    if check_btn:
        if not url_input.strip():
            st.warning("Vui lòng nhập URL cần kiểm tra.")
        else:
            url = url_input.strip()
            if not url.startswith('http'):
                url = 'https://' + url

            try:
                domain = url.split('//')[1].split('/')[0].split(':')[0]
            except Exception:
                domain = url

            steps = 8 if use_apis else 5
            progress = st.progress(0)

            with st.status("Đang phân tích...", expanded=True) as status:
                # 1) Lexical
                st.write("📝 Trích xuất đặc trưng URL...")
                lexical = extract_lexical_features(url)
                progress.progress(1 / steps)

                # 2) SSL
                st.write("🔒 Kiểm tra SSL...")
                ssl_info = check_ssl(domain)
                progress.progress(2 / steps)

                # 3) Domain age
                st.write("📅 Kiểm tra tuổi domain...")
                age_info = check_domain_age(domain)
                progress.progress(3 / steps)

                # 4) Homograph
                st.write("🔤 Kiểm tra domain giả mạo...")
                homo_info = check_homograph(domain)
                progress.progress(4 / steps)

                # 5) Legit domain
                st.write("✅ Xác minh domain chính thức...")
                legit_info = check_legitimate_domain(url)
                progress.progress(5 / steps)

                # API defaults
                vt_info = {'vt_positives': 0, 'vt_total': 0, 'vt_is_malicious': 0}
                gsb_info = {'gsb_is_dangerous': 0, 'gsb_threat_type': 'none'}
                uh_info = {'urlhaus_is_malicious': 0, 'urlhaus_threat': 'none'}

                if use_apis:
                    vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
                    gsb_key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

                    st.write("🦠 Truy vấn VirusTotal...")
                    vt_info = check_virustotal(url, vt_key)
                    progress.progress(6 / steps)

                    st.write("🔍 Truy vấn Google Safe Browsing...")
                    gsb_info = check_google_safe_browsing(url, gsb_key)
                    progress.progress(7 / steps)

                    st.write("🕷️ Truy vấn URLhaus...")
                    uh_info = check_urlhaus(url)
                    progress.progress(8 / steps)

                progress.progress(1.0)
                status.update(label="Hoàn tất phân tích!", state="complete")

            # ── ML Prediction ────────────────────────────────────────────
            ordered = {k: lexical.get(k, 0) for k in feature_names}
            X_pred = pd.DataFrame([ordered])
            prob = model.predict_proba(X_pred)[0]
            ml_score = round(prob[1] * 100, 1)

            # ── Risk score (additive) ────────────────────────────────────
            risk = ml_score
            if vt_info.get('vt_is_malicious'):
                risk += WEIGHT_VT_MALICIOUS
            if gsb_info.get('gsb_is_dangerous'):
                risk += WEIGHT_GSB_DANGEROUS
            if uh_info.get('urlhaus_is_malicious'):
                risk += WEIGHT_URLHAUS_MALICIOUS
            if homo_info.get('is_lookalike'):
                risk += WEIGHT_LOOKALIKE
            if age_info.get('domain_is_new'):
                risk += WEIGHT_DOMAIN_NEW
            if ssl_info.get('ssl_valid') == 0:
                risk += WEIGHT_SSL_INVALID
            if legit_info.get('is_subdomain_spoof'):
                risk += WEIGHT_SUBDOMAIN_SPOOF
            risk = min(risk, 100)

            # ── Legit domain bonus (giảm false positive) ─────────────────
            if legit_info.get('is_exact_match'):
                risk = min(risk, 20)

            risk = round(risk, 1)

            # ── Verdict ──────────────────────────────────────────────────
            if risk >= RISK_DANGEROUS:
                verdict = "NGUY HIỂM"
                st.markdown(f"""<div class="result-danger">
                  <h2>⛔ NGUY HIỂM — Không nên truy cập!</h2>
                  <p>Điểm nguy hiểm: <strong>{risk}%</strong></p>
                </div>""", unsafe_allow_html=True)
            elif risk >= RISK_SUSPICIOUS:
                verdict = "ĐÁNG NGỜ"
                st.markdown(f"""<div class="result-warn">
                  <h2>⚠️ ĐÁNG NGỜ — Xác minh trước khi nhập thông tin</h2>
                  <p>Điểm nguy hiểm: <strong>{risk}%</strong></p>
                </div>""", unsafe_allow_html=True)
            else:
                verdict = "AN TOÀN"
                st.markdown(f"""<div class="result-safe">
                  <h2>✅ AN TOÀN — Không phát hiện dấu hiệu lừa đảo</h2>
                  <p>Điểm nguy hiểm: <strong>{risk}%</strong></p>
                </div>""", unsafe_allow_html=True)

            # ── Official domain banner ───────────────────────────────────
            if legit_info.get('is_official_bank'):
                st.markdown("""<div class="result-official">
                  <p>🏦 Đây là website ngân hàng chính thức tại Việt Nam</p>
                </div>""", unsafe_allow_html=True)
            elif legit_info.get('is_official_gov'):
                st.markdown("""<div class="result-official">
                  <p>🏛️ Đây là website cơ quan nhà nước Việt Nam</p>
                </div>""", unsafe_allow_html=True)
            elif legit_info.get('is_social_media') and legit_info.get('is_exact_match'):
                st.markdown("""<div class="result-official">
                  <p>🌐 Đây là website chính thức đã được xác minh</p>
                </div>""", unsafe_allow_html=True)

            # ── Score bar ────────────────────────────────────────────────
            color = "#c62828" if risk >= RISK_DANGEROUS else "#f57f17" if risk >= RISK_SUSPICIOUS else "#2e7d32"
            st.markdown(f"""
            <p style="font-size:.85rem;color:#666;margin-bottom:4px">Mức độ nguy hiểm</p>
            <div class="score-bar-container">
              <div class="score-bar-fill" style="width:{risk}%;background:{color}"></div>
            </div>""", unsafe_allow_html=True)

            # ── Stat cards row 1 ─────────────────────────────────────────
            report_count = get_url_report_count(url)
            st.markdown(f"""
            <div class="stat-grid">
              <div class="stat-box"><div class="val">{ml_score}%</div><div class="lbl">ML Score</div></div>
              <div class="stat-box"><div class="val">{risk}%</div><div class="lbl">Risk Score</div></div>
              <div class="stat-box"><div class="val">{'✅' if ssl_info['ssl_valid'] else '❌'}</div><div class="lbl">SSL</div></div>
              <div class="stat-box"><div class="val">{age_info['domain_age_days']}d</div><div class="lbl">Tuổi domain</div></div>
            </div>""", unsafe_allow_html=True)

            # ── Stat cards row 2 ─────────────────────────────────────────
            st.markdown(f"""
            <div class="stat-grid">
              <div class="stat-box"><div class="val">{vt_info['vt_positives']}/{vt_info['vt_total']}</div><div class="lbl">VirusTotal</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if gsb_info['gsb_is_dangerous'] else '✅'}</div><div class="lbl">Google SB</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if uh_info['urlhaus_is_malicious'] else '✅'}</div><div class="lbl">URLhaus</div></div>
              <div class="stat-box"><div class="val">{'⚠️' if homo_info['is_lookalike'] else '✅'}</div><div class="lbl">Homograph</div></div>
            </div>""", unsafe_allow_html=True)

            # ── Flags ────────────────────────────────────────────────────
            st.markdown("#### 🔎 Phân tích dấu hiệu")
            flags = []

            # 🔴 Critical
            if vt_info.get('vt_is_malicious'):
                flags.append(('high', f"🔴 VirusTotal: {vt_info['vt_positives']} engines phát hiện độc hại"))
            if gsb_info.get('gsb_is_dangerous'):
                flags.append(('high', f"🔴 Google Safe Browsing: {gsb_info['gsb_threat_type']}"))
            if legit_info.get('is_subdomain_spoof'):
                flags.append(('high', "🔴 Giả mạo subdomain — domain chính không hợp lệ"))
            if homo_info.get('is_lookalike'):
                flags.append(('high', f"🔴 Domain giống '{homo_info['lookalike_brand']}' (homograph)"))
            if lexical.get('IpAddress'):
                flags.append(('high', '🔴 Dùng địa chỉ IP thay tên miền'))
            if lexical.get('AtSymbol'):
                flags.append(('high', '🔴 Chứa ký tự @ trong URL'))

            # 🟠 High
            if uh_info.get('urlhaus_is_malicious'):
                flags.append(('medium', f"🟠 URLhaus: {uh_info['urlhaus_threat']}"))
            if age_info.get('domain_is_new'):
                flags.append(('medium', f"🟠 Domain mới ({age_info['domain_age_days']} ngày)"))
            if ssl_info.get('ssl_valid') == 0:
                flags.append(('medium', '🟠 Không có SSL hợp lệ'))
            if lexical.get('NumSensitiveWords', 0) >= 2:
                flags.append(('medium', f"🟠 Chứa {lexical['NumSensitiveWords']} từ khóa nhạy cảm"))
            if lexical.get('SubdomainLevel', 0) >= 3:
                flags.append(('medium', f"🟠 Nhiều subdomain ({lexical['SubdomainLevel']} cấp)"))

            # 🟡 Medium
            if lexical.get('NoHttps'):
                flags.append(('low', '🟡 Không dùng HTTPS'))
            if lexical.get('UrlLength', 0) > 100:
                flags.append(('low', f"🟡 URL dài ({lexical['UrlLength']} ký tự)"))
            if lexical.get('SuspiciousTLD'):
                flags.append(('low', '🟡 TLD đáng ngờ'))
            if homo_info.get('has_punycode'):
                flags.append(('low', '🟡 Chứa Punycode (xn--)'))
            if lexical.get('RandomString'):
                flags.append(('low', '🟡 URL chứa chuỗi ngẫu nhiên (entropy cao)'))

            if not flags:
                st.markdown('<div class="flag-item flag-ok">✅ Không phát hiện dấu hiệu đáng ngờ</div>',
                            unsafe_allow_html=True)
            else:
                for level, msg in flags:
                    css = {'high': 'flag-high', 'medium': 'flag-medium', 'low': 'flag-low'}[level]
                    st.markdown(f'<div class="flag-item {css}">{msg}</div>', unsafe_allow_html=True)

            # ── Community report count ───────────────────────────────────
            if report_count > 0:
                st.warning(f"⚠️ URL này đã bị báo cáo **{report_count}** lần bởi cộng đồng.")

            # ── Report form ──────────────────────────────────────────────
            with st.expander("📢 Báo cáo URL này"):
                rtype = st.selectbox("Loại vi phạm", REPORT_TYPES,
                                     format_func=lambda x: {
                                         'phishing': '🎣 Phishing (giả mạo)',
                                         'scam': '💰 Lừa đảo (scam)',
                                         'malware': '🦠 Phần mềm độc hại',
                                         'false_positive': '✅ Báo cáo sai (false positive)',
                                     }.get(x, x))
                rdesc = st.text_area("Mô tả (tùy chọn)", placeholder="Nhập mô tả thêm...")
                if st.button("📨 Gửi báo cáo", key="submit_report"):
                    if submit_report(url, rtype, rdesc):
                        st.success("✅ Đã gửi báo cáo. Cảm ơn bạn đã đóng góp!")
                    else:
                        st.error("❌ Lỗi khi gửi báo cáo.")

            # ── Feature vector ───────────────────────────────────────────
            with st.expander("📊 Xem toàn bộ feature vector"):
                all_feat = {**lexical, **ssl_info, **age_info, **homo_info,
                            **vt_info, **gsb_info, **uh_info, **legit_info}
                st.dataframe(
                    pd.DataFrame([all_feat]).T.rename(columns={0: 'Giá trị'}),
                    use_container_width=True,
                )

            # ── Save to DB ───────────────────────────────────────────────
            check_mode = "full" if use_apis else "quick"
            log_check(url, risk, ml_score, verdict, check_mode)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2: LỊCH SỬ & THỐNG KÊ
# ══════════════════════════════════════════════════════════════════════════════
with tab_history:
    stats = get_stats()
    st.markdown(f"""
    <div class="stat-grid">
      <div class="stat-box"><div class="val">{stats['total_checks']}</div><div class="lbl">Tổng kiểm tra</div></div>
      <div class="stat-box"><div class="val">{stats['dangerous_detected']}</div><div class="lbl">Phát hiện nguy hiểm</div></div>
      <div class="stat-box"><div class="val">{stats['total_reports']}</div><div class="lbl">Báo cáo cộng đồng</div></div>
      <div class="stat-box"><div class="val">{stats['today_checks']}</div><div class="lbl">Hôm nay</div></div>
    </div>""", unsafe_allow_html=True)

    st.markdown("#### 📋 Lịch sử kiểm tra (20 gần nhất)")
    checks = get_recent_checks(20)
    if checks:
        st.dataframe(pd.DataFrame(checks), use_container_width=True)
    else:
        st.info("Chưa có lịch sử kiểm tra.")

    st.markdown("#### 📢 Báo cáo cộng đồng (20 gần nhất)")
    reports = get_recent_reports(20)
    if reports:
        st.dataframe(pd.DataFrame(reports), use_container_width=True)
    else:
        st.info("Chưa có báo cáo cộng đồng.")

    if st.button("🗑️ Xóa lịch sử cá nhân"):
        clear_checks()
        st.success("Đã xóa lịch sử.")
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3: HƯỚNG DẪN
# ══════════════════════════════════════════════════════════════════════════════
with tab_guide:
    st.markdown("#### 🎯 5 dấu hiệu nhận biết URL lừa đảo tại Việt Nam")
    st.markdown("""
1. **Domain giả mạo ngân hàng**: `vietcombank.com.vn.evil.xyz` thay vì `vietcombank.com.vn`
2. **TLD lạ**: `.tk`, `.xyz`, `.top`, `.click` — các TLD miễn phí hay bị lạm dụng
3. **Chứa từ khóa khẩn cấp**: "xác nhận tài khoản", "cập nhật mật khẩu", "tài khoản bị khóa"
4. **URL quá dài hoặc chứa IP**: `http://192.168.1.1/login` hoặc URL > 100 ký tự
5. **Không có HTTPS** hoặc chứng chỉ SSL không hợp lệ
    """)

    st.markdown("#### 🔑 Cách lấy API key")
    st.markdown("""
**VirusTotal** (miễn phí, 4 request/phút):
1. Đăng ký tại [virustotal.com](https://www.virustotal.com/gui/sign-in)
2. Vào Profile → API Key → Copy

**Google Safe Browsing** (miễn phí, 10,000 request/ngày):
1. Đăng nhập [console.cloud.google.com](https://console.cloud.google.com)
2. Tạo Project → Bật Safe Browsing API → Tạo API Key
    """)

    st.markdown("#### 🔗 Tài nguyên hữu ích")
    st.markdown("""
- 🛡️ [chongluadao.vn](https://chongluadao.vn) — Cộng đồng chống lừa đảo VN
- 🚨 [canhbao.ncsc.gov.vn](https://canhbao.ncsc.gov.vn) — Trung tâm An ninh mạng Quốc gia
- 📋 [takethemdown.com.vn](https://takethemdown.com.vn) — Báo cáo website lừa đảo
    """)

# ─── Footer ──────────────────────────────────────────────────────────────────
st.divider()
st.caption("🔒 Dữ liệu không được lưu lên server · Mọi kiểm tra lưu cục bộ trên máy bạn")
st.caption("🛡️ Ensemble ML: Random Forest + XGBoost + LightGBM | SSL + WHOIS + VirusTotal + Google SB + URLhaus")