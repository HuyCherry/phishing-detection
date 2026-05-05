"""
database.py — MongoDB CRUD for PhishGuardAI.
Singleton MongoClient to prevent memory leaks.
"""
import os
import sys
import logging
from datetime import datetime, date
from pathlib import Path
from typing import Optional

from pymongo import MongoClient
from pymongo.database import Database

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import REPORT_TYPES

logger = logging.getLogger(__name__)

# ─── Singleton MongoClient ───────────────────────────────────────────────────
_client: Optional[MongoClient] = None


def get_db() -> Database:
    """Return the MongoDB database, reusing a single client connection."""
    global _client
    if _client is None:
        uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        logger.info("MongoClient initialized: %s", uri)
    db_name = os.getenv("MONGO_DB_NAME", "phishing_db")
    return _client[db_name]


# ─── CRUD Operations ────────────────────────────────────────────────────────

def log_check(
    url: str,
    risk_score: float,
    ml_score: float,
    verdict: str = "",
    check_mode: str = "quick",
) -> None:
    """Save a URL scan result to MongoDB."""
    try:
        db = get_db()
        data = {
            "url": url,
            "risk_score": float(risk_score),
            "ml_score": float(ml_score),
            "verdict": verdict,
            "checked_at": str(datetime.now()),
            "check_mode": check_mode,
        }
        db["url_checks"].insert_one(data)
    except Exception:
        logger.exception("Failed to log check for %s", url)


def submit_report(
    url: str, report_type: str, description: str = ""
) -> bool:
    """Submit a community report. Returns True on success."""
    try:
        if report_type not in REPORT_TYPES:
            report_type = "phishing"
        db = get_db()
        data = {
            "url": url,
            "report_type": report_type,
            "description": description,
            "reported_at": str(datetime.now()),
            "status": "pending",
        }
        db["community_reports"].insert_one(data)
        return True
    except Exception:
        logger.exception("Failed to submit report for %s", url)
        return False


def get_url_report_count(url: str) -> int:
    """Count how many times a URL has been reported."""
    try:
        db = get_db()
        return db["community_reports"].count_documents({"url": url})
    except Exception:
        logger.exception("Failed to count reports for %s", url)
        return 0


def get_recent_checks(limit: int = 20) -> list[dict]:
    """Return the N most recent URL checks."""
    try:
        db = get_db()
        cursor = (
            db["url_checks"]
            .find({}, {"_id": 0})
            .sort("_id", -1)
            .limit(limit)
        )
        return list(cursor)
    except Exception:
        logger.exception("Failed to fetch recent checks")
        return []


def get_recent_reports(limit: int = 20) -> list[dict]:
    """Return the N most recent community reports."""
    try:
        db = get_db()
        cursor = (
            db["community_reports"]
            .find({}, {"_id": 0})
            .sort("_id", -1)
            .limit(limit)
        )
        return list(cursor)
    except Exception:
        logger.exception("Failed to fetch recent reports")
        return []


def get_stats() -> dict:
    """Return aggregate statistics from MongoDB."""
    try:
        db = get_db()
        total_checks = db["url_checks"].estimated_document_count()
        total_reports = db["community_reports"].estimated_document_count()
        dangerous = db["url_checks"].count_documents(
            {"risk_score": {"$gte": 70}}
        )
        today_str = str(date.today())
        today_checks = db["url_checks"].count_documents(
            {"checked_at": {"$regex": f"^{today_str}"}}
        )
        return {
            "total_checks": total_checks,
            "total_reports": total_reports,
            "dangerous_detected": dangerous,
            "today_checks": today_checks,
        }
    except Exception:
        logger.exception("Failed to get stats")
        return {
            "total_checks": 0,
            "total_reports": 0,
            "dangerous_detected": 0,
            "today_checks": 0,
        }


def clear_checks() -> None:
    """Delete all URL check history."""
    try:
        db = get_db()
        db["url_checks"].delete_many({})
    except Exception:
        logger.exception("Failed to clear checks")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Testing MongoDB connection...")
    try:
        db = get_db()
        db.command("ping")
        print("Ping MongoDB successful!")
        print(f"   Stats: {get_stats()}")
    except Exception as e:
        print(f"Failed to connect to MongoDB: {e}")
