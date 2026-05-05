"""
main.py — FastAPI application for PhishGuardAI.

Run with:
    uvicorn api.main:app --reload --port 8000
"""
import os
import sys
import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# ─── Setup paths ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
load_dotenv(BASE_DIR / ".env")

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ─── Import routers & dependencies ───────────────────────────────────────────
from api.dependencies import limiter
from api.routers import url, report, stats, html, email_route

# ─── Create FastAPI app ──────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuardAI API",
    description=(
        "API for detecting phishing URLs, emails, and HTML content. "
        "Powered by ensemble ML (RF + XGBoost + LightGBM) and threat intelligence."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── Rate limiter ────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS ────────────────────────────────────────────────────────────────────
extension_id = os.getenv("EXTENSION_ID", "")
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:8501",    # Streamlit
    "http://127.0.0.1:8501",
]
if extension_id:
    allowed_origins.append(f"chrome-extension://{extension_id}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Register routers ───────────────────────────────────────────────────────
app.include_router(url.router)
app.include_router(report.router)
app.include_router(stats.router)
app.include_router(html.router)
app.include_router(email_route.router)


@app.get("/", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "PhishGuardAI API",
        "version": "1.0.0",
    }


@app.get("/health", tags=["Health"])
async def health() -> dict:
    """Detailed health check."""
    from config import MODEL_PATH
    return {
        "status": "ok",
        "model_loaded": MODEL_PATH.exists(),
        "endpoints": [
            "POST /v1/check-url",
            "POST /v1/check-html",
            "POST /v1/check-email",
            "POST /v1/report",
            "GET  /v1/stats",
        ],
    }
