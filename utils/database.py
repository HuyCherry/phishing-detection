import os
import sys
from datetime import datetime, date
from pathlib import Path
from pymongo import MongoClient

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import REPORT_TYPES

def get_db():
    """Khởi tạo client MongoDB và trả về database."""
    uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    db_name = os.getenv("MONGO_DB_NAME", "phishing_db")
    client = MongoClient(uri)
    return client[db_name]


def log_check(url: str, risk_score: float, ml_score: float,
              verdict: str = "", check_mode: str = "quick"):
    """Lưu lịch sử kiểm tra vào MongoDB."""
    try:
        db = get_db()
        data = {
            "url": url,
            "risk_score": float(risk_score),
            "ml_score": float(ml_score),
            "verdict": verdict,
            "checked_at": str(datetime.now()),
            "check_mode": check_mode
        }
        db["url_checks"].insert_one(data)
    except Exception as e:
        print(f"MongoDB Error log_check: {e}")


def submit_report(url: str, report_type: str, description: str = "") -> bool:
    """Gửi báo cáo cộng đồng. Returns True nếu thành công."""
    try:
        if report_type not in REPORT_TYPES:
            report_type = 'phishing'
        db = get_db()
        data = {
            "url": url,
            "report_type": report_type,
            "description": description,
            "reported_at": str(datetime.now()),
            "status": "pending"
        }
        db["community_reports"].insert_one(data)
        return True
    except Exception as e:
        print(f"MongoDB Error submit_report: {e}")
        return False


def get_url_report_count(url: str) -> int:
    """Đếm số lần URL bị report."""
    try:
        db = get_db()
        return db["community_reports"].count_documents({"url": url})
    except Exception:
        return 0


def get_recent_checks(limit: int = 20) -> list:
    """Lấy N lần kiểm tra gần nhất."""
    try:
        db = get_db()
        cursor = db["url_checks"].find({}, {"_id": 0}).sort("_id", -1).limit(limit)
        return list(cursor)
    except Exception:
        return []


def get_recent_reports(limit: int = 20) -> list:
    """Lấy N báo cáo gần nhất."""
    try:
        db = get_db()
        cursor = db["community_reports"].find({}, {"_id": 0}).sort("_id", -1).limit(limit)
        return list(cursor)
    except Exception:
        return []


def get_stats() -> dict:
    """Thống kê tổng quan từ MongoDB."""
    try:
        db = get_db()
        total_checks = db["url_checks"].estimated_document_count()
        total_reports = db["community_reports"].estimated_document_count()
        dangerous = db["url_checks"].count_documents({"risk_score": {"$gte": 70}})
        today_str = str(date.today())
        today_checks = db["url_checks"].count_documents({"checked_at": {"$regex": f"^{today_str}"}})
        
        return {
            'total_checks': total_checks,
            'total_reports': total_reports,
            'dangerous_detected': dangerous,
            'today_checks': today_checks,
        }
    except Exception as e:
        print(f"MongoDB Error get_stats: {e}")
        return {'total_checks': 0, 'total_reports': 0,
                'dangerous_detected': 0, 'today_checks': 0}


def clear_checks():
    """Xóa toàn bộ lịch sử kiểm tra."""
    try:
        db = get_db()
        db["url_checks"].delete_many({})
    except Exception:
        pass


if __name__ == "__main__":
    print("✅ Testing MongoDB connection...")
    try:
        db = get_db()
        db.command('ping')
        print("✅ Ping MongoDB successful!")
        print(f"   Stats: {get_stats()}")
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
