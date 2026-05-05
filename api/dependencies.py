"""
dependencies.py — FastAPI dependency injection for PhishGuardAI.

Provides:
- Rate limiter (slowapi)
- Optional API key header validation
"""
import os
import logging
from typing import Optional

from fastapi import Header, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# ─── Rate Limiter ────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── Default rate limit from env ─────────────────────────────────────────────
DEFAULT_RATE_LIMIT = os.getenv("API_RATE_LIMIT", "60/minute")


async def verify_api_key(
    x_api_key: Optional[str] = Header(default=None),
) -> Optional[str]:
    """Validate API key if API_SECRET_KEY is configured.

    If API_SECRET_KEY is not set in env, authentication is disabled
    (open access mode for development).
    """
    secret = os.getenv("API_SECRET_KEY", "")
    if not secret:
        # No auth configured — open access
        return None
    if x_api_key != secret:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key
