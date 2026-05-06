"""
tab_check.py — Logic for the URL Check tab.
"""
import os
import streamlit as st
import pandas as pd

from config import (
    RISK_DANGEROUS, RISK_SUSPICIOUS,
    WEIGHT_VT_MALICIOUS, WEIGHT_GSB_DANGEROUS, WEIGHT_URLHAUS_MALICIOUS,
    WEIGHT_LOOKALIKE, WEIGHT_DOMAIN_NEW, WEIGHT_SSL_INVALID,
    WEIGHT_SUBDOMAIN_SPOOF, REPORT_TYPES
)
from utils.advanced_features import (
    extract_lexical_features, check_ssl, check_domain_age,
    check_homograph, check_virustotal, check_google_safe_browsing,
    check_urlhaus,
)
from utils.legit_domain_checker import check_legitimate_domain, extract_domain
from utils.database import log_check, submit_report, get_url_report_count

def render(model, feature_names):
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

            domain = extract_domain(url)

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
                df_feat = pd.DataFrame([all_feat]).T.rename(columns={0: 'Giá trị'})
                st.dataframe(
                    df_feat.astype(str),
                    use_container_width=True,
                )

            # ── Save to DB ───────────────────────────────────────────────
            check_mode = "full" if use_apis else "quick"
            log_check(url, risk, ml_score, verdict, check_mode)
