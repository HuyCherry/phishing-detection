"""
html.py — FastAPI router for HTML content analysis.

POST /v1/check-html
"""
import logging

from fastapi import APIRouter, Depends, Request

from api.schemas import CheckHtmlRequest, CheckHtmlResponse
from api.dependencies import limiter, DEFAULT_RATE_LIMIT, verify_api_key
from utils.html_analyzer import analyze_html

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["HTML Analysis"])


@router.post("/check-html", response_model=CheckHtmlResponse)
@limiter.limit(DEFAULT_RATE_LIMIT)
async def check_html(
    request: Request,
    body: CheckHtmlRequest,
    _api_key: str = Depends(verify_api_key),
) -> CheckHtmlResponse:
    """Analyze raw HTML content for phishing indicators."""
    result = analyze_html(body.html_content, body.source_url)
    return CheckHtmlResponse(**{
        k: v for k, v in result.items()
        if k in CheckHtmlResponse.model_fields
    })
