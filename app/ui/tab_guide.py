"""
tab_guide.py — Logic for the Guide tab.
"""
import streamlit as st

def render():
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
