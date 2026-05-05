"""
email_route.py — FastAPI router for email phishing analysis.

POST /v1/check-email
"""
import logging

from fastapi import APIRouter, Depends, Request

from api.schemas import CheckEmailRequest, CheckEmailResponse
from api.dependencies import limiter, DEFAULT_RATE_LIMIT, verify_api_key
from utils.email_analyzer import analyze_email

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["Email Analysis"])


@router.post("/check-email", response_model=CheckEmailResponse)
@limiter.limit(DEFAULT_RATE_LIMIT)
async def check_email(
    request: Request,
    body: CheckEmailRequest,
    _api_key: str = Depends(verify_api_key),
) -> CheckEmailResponse:
    """Analyze a raw email (RFC 2822) for phishing indicators."""
    result = analyze_email(body.raw_email)
    return CheckEmailResponse(**{
        k: v for k, v in result.items()
        if k in CheckEmailResponse.model_fields
    })
