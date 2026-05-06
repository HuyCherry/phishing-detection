"""
tab_history.py — Logic for the History and Stats tab.
"""
import streamlit as st
import pandas as pd
from utils.database import get_stats, get_recent_checks, get_recent_reports, clear_checks

def render():
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
