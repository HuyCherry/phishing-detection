import streamlit as st
import pandas as pd
from utils.html_analyzer import analyze_html, fetch_and_analyze

def render():
    st.markdown("### 🌐 Phân tích Mã nguồn Trang web (HTML Analyzer)")
    st.write("Công cụ này cho phép bạn kiểm tra sâu cấu trúc HTML của một trang web để phát hiện các dấu hiệu lừa đảo như form đánh cắp dữ liệu, mã ẩn, mạo danh thương hiệu.")

    mode = st.radio("Chọn phương thức kiểm tra:", ["🔗 Tự động tải từ URL", "📝 Dán mã nguồn thô (Raw HTML)"], horizontal=True)

    with st.container():
        if "Tự động" in mode:
            url_input = st.text_input("Nhập URL của trang web:", placeholder="https://example.com/login")
            analyze_btn = st.button("🚀 Tải & Phân tích HTML", type="primary", use_container_width=True)
            if analyze_btn:
                if not url_input.strip():
                    st.warning("Vui lòng nhập URL.")
                else:
                    url = url_input.strip()
                    if not url.startswith('http'):
                        url = 'https://' + url
                    with st.spinner(f"Đang tải mã nguồn từ {url}..."):
                        result = fetch_and_analyze(url)
                    _show_results(result)
        else:
            source_url = st.text_input("Source URL (Tùy chọn - Giúp AI biết mã nguồn này thuộc tên miền nào)", placeholder="https://example.com")
            html_content = st.text_area("Dán mã nguồn HTML thô vào đây (Raw HTML)", height=300, placeholder="<html>\n  <body>...</body>\n</html>")
            analyze_btn = st.button("🚀 Phân tích HTML", type="primary", use_container_width=True)
            if analyze_btn:
                if not html_content.strip():
                    st.warning("Vui lòng dán mã nguồn HTML để phân tích.")
                else:
                    with st.spinner("Đang phân tích cấu trúc DOM và nội dung..."):
                        result = analyze_html(html_content, source_url)
                    _show_results(result)

def _show_results(result):
    risk_score = result.get("html_risk_score", 0.0)
    flags = result.get("html_flags", [])

    # Verdict
    if risk_score >= 50:
        st.markdown(f"""<div class="result-danger">
          <h2>⛔ NGUY HIỂM — Trang web chứa mã độc/lừa đảo!</h2>
          <p>HTML Risk Score: <strong>{risk_score}%</strong></p>
        </div>""", unsafe_allow_html=True)
    elif risk_score >= 20:
        st.markdown(f"""<div class="result-warn">
          <h2>⚠️ ĐÁNG NGỜ — Có dấu hiệu rủi ro trong mã nguồn</h2>
          <p>HTML Risk Score: <strong>{risk_score}%</strong></p>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""<div class="result-safe">
          <h2>✅ AN TOÀN — Không phát hiện mã HTML độc hại</h2>
          <p>HTML Risk Score: <strong>{risk_score}%</strong></p>
        </div>""", unsafe_allow_html=True)

    # Details
    st.markdown("#### 🔎 Dấu hiệu nhận biết")
    if not flags:
        st.markdown('<div class="flag-item flag-ok">✅ Cấu trúc HTML bình thường, không chứa mã độc.</div>', unsafe_allow_html=True)
    else:
        for flag in flags:
            st.markdown(f'<div class="flag-item flag-high">🔴 {flag}</div>', unsafe_allow_html=True)
    
    with st.expander("📊 Xem thông số kỹ thuật (Raw Vector)"):
        df_feat = pd.DataFrame([result]).T.rename(columns={0: 'Giá trị'})
        st.dataframe(df_feat.astype(str), use_container_width=True)
