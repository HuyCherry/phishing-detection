"""
community_reports.py — Hệ thống báo cáo cộng đồng kiểu TakeThemDown.vn.
Dùng SQLite, không cần server riêng.
"""
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, date

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import DB_PATH, REPORT_TYPES


def _get_conn():
    """Tạo connection tới SQLite DB."""
    return sqlite3.connect(str(DB_PATH))


def init_db():
    """Tạo tables nếu chưa có."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score REAL,
            ml_score REAL,
            verdict TEXT,
            checked_at TEXT,
            check_mode TEXT DEFAULT 'quick'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            report_type TEXT NOT NULL,
            description TEXT DEFAULT '',
            reported_at TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)
    conn.commit()
    conn.close()


def log_check(url: str, risk_score: float, ml_score: float,
              verdict: str = "", check_mode: str = "quick"):
    """Lưu lịch sử kiểm tra."""
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO url_checks (url, risk_score, ml_score, verdict, checked_at, check_mode) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, risk_score, ml_score, verdict, str(datetime.now()), check_mode)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def submit_report(url: str, report_type: str, description: str = "") -> bool:
    """Gửi báo cáo cộng đồng. Returns True nếu thành công."""
    try:
        if report_type not in REPORT_TYPES:
            report_type = 'phishing'
        conn = _get_conn()
        conn.execute(
            "INSERT INTO community_reports (url, report_type, description, reported_at) "
            "VALUES (?, ?, ?, ?)",
            (url, report_type, description, str(datetime.now()))
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_url_report_count(url: str) -> int:
    """Đếm số lần URL bị report."""
    try:
        conn = _get_conn()
        cur = conn.execute(
            "SELECT COUNT(*) FROM community_reports WHERE url = ?", (url,)
        )
        count = cur.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def get_recent_checks(limit: int = 20) -> list:
    """Lấy N lần kiểm tra gần nhất."""
    try:
        conn = _get_conn()
        cur = conn.execute(
            "SELECT url, risk_score, ml_score, verdict, checked_at, check_mode "
            "FROM url_checks ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {'url': r[0], 'risk_score': r[1], 'ml_score': r[2],
             'verdict': r[3], 'checked_at': r[4], 'check_mode': r[5]}
            for r in rows
        ]
    except Exception:
        return []


def get_recent_reports(limit: int = 20) -> list:
    """Lấy N báo cáo gần nhất."""
    try:
        conn = _get_conn()
        cur = conn.execute(
            "SELECT url, report_type, description, reported_at, status "
            "FROM community_reports ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {'url': r[0], 'report_type': r[1], 'description': r[2],
             'reported_at': r[3], 'status': r[4]}
            for r in rows
        ]
    except Exception:
        return []


def get_stats() -> dict:
    """Thống kê tổng quan."""
    try:
        conn = _get_conn()
        total_checks = conn.execute("SELECT COUNT(*) FROM url_checks").fetchone()[0]
        total_reports = conn.execute("SELECT COUNT(*) FROM community_reports").fetchone()[0]
        dangerous = conn.execute(
            "SELECT COUNT(*) FROM url_checks WHERE risk_score >= 70"
        ).fetchone()[0]
        today = str(date.today())
        today_checks = conn.execute(
            "SELECT COUNT(*) FROM url_checks WHERE checked_at LIKE ?",
            (today + '%',)
        ).fetchone()[0]
        conn.close()
        return {
            'total_checks': total_checks,
            'total_reports': total_reports,
            'dangerous_detected': dangerous,
            'today_checks': today_checks,
        }
    except Exception:
        return {'total_checks': 0, 'total_reports': 0,
                'dangerous_detected': 0, 'today_checks': 0}


def clear_checks():
    """Xóa toàn bộ lịch sử kiểm tra."""
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM url_checks")
        conn.commit()
        conn.close()
    except Exception:
        pass


# Initialize DB on import
init_db()


if __name__ == "__main__":
    init_db()
    print("✅ Database initialized")
    print(f"   Stats: {get_stats()}")
