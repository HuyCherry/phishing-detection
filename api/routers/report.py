"""
report.py — FastAPI router for community reports.

POST /v1/report
"""
import logging

from fastapi import APIRouter, Depends, Request

from api.schemas import ReportRequest, ReportResponse
from api.dependencies import limiter, DEFAULT_RATE_LIMIT, verify_api_key
from utils.database import submit_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["Community Reports"])


@router.post("/report", response_model=ReportResponse)
@limiter.limit(DEFAULT_RATE_LIMIT)
async def create_report(
    request: Request,
    body: ReportRequest,
    _api_key: str = Depends(verify_api_key),
) -> ReportResponse:
    """Submit a community phishing report."""
    success = submit_report(body.url, body.report_type, body.description)
    if success:
        return ReportResponse(success=True, message="Report submitted successfully")
    return ReportResponse(success=False, message="Failed to submit report")
