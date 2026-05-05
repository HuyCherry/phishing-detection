"""
stats.py — FastAPI router for system statistics.

GET /v1/stats
"""
import logging

from fastapi import APIRouter, Depends, Request

from api.schemas import StatsResponse
from api.dependencies import limiter, DEFAULT_RATE_LIMIT, verify_api_key
from utils.database import get_stats

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["Statistics"])


@router.get("/stats", response_model=StatsResponse)
@limiter.limit(DEFAULT_RATE_LIMIT)
async def system_stats(
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> StatsResponse:
    """Return aggregate system statistics."""
    stats = get_stats()
    return StatsResponse(**stats)
