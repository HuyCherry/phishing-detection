"""
Pydantic schemas for PhishGuardAI API.
"""
from pydantic import BaseModel, Field
from typing import Optional


class CheckUrlRequest(BaseModel):
    """Request body for URL checking endpoint."""
    url: str = Field(..., min_length=1, description="URL to analyze")
    mode: str = Field(
        default="quick",
        pattern="^(quick|full)$",
        description="Scan mode: 'quick' (no APIs) or 'full' (with APIs)",
    )


class CheckUrlResponse(BaseModel):
    """Response body for URL checking endpoint."""
    url: str
    risk_score: float = Field(..., ge=0, le=100)
    verdict: str
    ml_score: float
    ssl_valid: int
    ssl_issuer: str = "unknown"
    domain_age_days: int = -1
    domain_is_new: int = 0
    registrar: str = "unknown"
    has_punycode: int = 0
    is_lookalike: int = 0
    lookalike_brand: str = ""
    vt_positives: int = 0
    vt_total: int = 0
    vt_is_malicious: int = 0
    gsb_is_dangerous: int = 0
    gsb_threat_type: str = "none"
    urlhaus_is_malicious: int = 0
    urlhaus_threat: str = "none"
    is_official: int = 0
    is_subdomain_spoof: int = 0
    html_risk_score: float = 0.0
    flags: list[str] = []
    checked_at: str = ""


class CheckHtmlRequest(BaseModel):
    """Request body for HTML analysis endpoint."""
    html_content: str = Field(..., min_length=1, description="Raw HTML to analyze")
    source_url: str = Field(default="", description="URL this HTML was fetched from")


class CheckHtmlResponse(BaseModel):
    """Response body for HTML analysis endpoint."""
    form_action_suspicious: int = 0
    has_hidden_inputs: int = 0
    has_password_field: int = 0
    external_resources_count: int = 0
    meta_refresh_redirect: int = 0
    brand_keywords_found: list[str] = []
    cloaked_content: int = 0
    iframe_external: int = 0
    html_risk_score: float = 0.0
    html_flags: list[str] = []


class CheckEmailRequest(BaseModel):
    """Request body for email analysis endpoint."""
    raw_email: str = Field(..., min_length=1, description="Raw email content (RFC 2822)")


class CheckEmailResponse(BaseModel):
    """Response body for email analysis endpoint."""
    spf_pass: int = 0
    dkim_pass: int = 0
    dmarc_pass: int = 0
    display_name_spoof: int = 0
    spoofed_brand: str = ""
    sender_domain: str = ""
    sender_email: str = ""
    reply_to_mismatch: int = 0
    urls_found: list[str] = []
    url_count: int = 0
    email_risk_score: float = 0.0
    email_flags: list[str] = []


class ReportRequest(BaseModel):
    """Request body for community report submission."""
    url: str = Field(..., min_length=1)
    report_type: str = Field(default="phishing")
    description: str = Field(default="")


class ReportResponse(BaseModel):
    """Response body for community report submission."""
    success: bool
    message: str


class StatsResponse(BaseModel):
    """Response body for system statistics."""
    total_checks: int = 0
    dangerous_detected: int = 0
    total_reports: int = 0
    today_checks: int = 0
