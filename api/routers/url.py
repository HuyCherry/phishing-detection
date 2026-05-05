"""
url.py — FastAPI router for URL phishing detection.

POST /v1/check-url
"""
import os
import sys
import logging
import pickle
from datetime import datetime
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, Depends, Request

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import (
    MODEL_PATH, RISK_DANGEROUS, RISK_SUSPICIOUS,
    WEIGHT_VT_MALICIOUS, WEIGHT_GSB_DANGEROUS, WEIGHT_URLHAUS_MALICIOUS,
    WEIGHT_LOOKALIKE, WEIGHT_DOMAIN_NEW, WEIGHT_SSL_INVALID,
    WEIGHT_SUBDOMAIN_SPOOF,
)
from utils.advanced_features import (
    extract_lexical_features, check_ssl, check_domain_age,
    check_homograph, check_virustotal, check_google_safe_browsing,
    check_urlhaus,
)
from utils.legit_domain_checker import check_legitimate_domain, extract_domain
from utils.html_analyzer import fetch_and_analyze
from utils.database import log_check
from api.schemas import CheckUrlRequest, CheckUrlResponse
from api.dependencies import limiter, DEFAULT_RATE_LIMIT, verify_api_key

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["URL Detection"])

# ─── Load model once ─────────────────────────────────────────────────────────
_model = None
_feature_names: list[str] = []


def _load_model() -> tuple:
    """Load the ML ensemble model (lazy singleton)."""
    global _model, _feature_names
    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        _model = data["model"]
        _feature_names = data["feature_names"]
        logger.info("ML model loaded: %d features", len(_feature_names))
    return _model, _feature_names


@router.post("/check-url", response_model=CheckUrlResponse)
@limiter.limit(DEFAULT_RATE_LIMIT)
async def check_url(
    request: Request,
    body: CheckUrlRequest,
    _api_key: str = Depends(verify_api_key),
) -> CheckUrlResponse:
    """Analyze a URL for phishing indicators.

    - mode='quick': lexical + SSL + WHOIS + homograph (no paid APIs)
    - mode='full': adds VirusTotal, Google Safe Browsing, URLhaus, HTML analysis
    """
    url = body.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    domain = extract_domain(url)
    use_apis = body.mode == "full"

    # ── Feature extraction ───────────────────────────────────────────────
    lexical = extract_lexical_features(url)
    ssl_info = check_ssl(domain)
    age_info = check_domain_age(domain)
    homo_info = check_homograph(domain)
    legit_info = check_legitimate_domain(url)

    # ── API checks (full mode only) ──────────────────────────────────────
    vt_info = {"vt_positives": 0, "vt_total": 0, "vt_is_malicious": 0}
    gsb_info = {"gsb_is_dangerous": 0, "gsb_threat_type": "none"}
    uh_info = {"urlhaus_is_malicious": 0, "urlhaus_threat": "none"}
    html_risk_score = 0.0

    if use_apis:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        gsb_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
        vt_info = check_virustotal(url, vt_key)
        gsb_info = check_google_safe_browsing(url, gsb_key)
        uh_info = check_urlhaus(url)

        # HTML content analysis
        try:
            html_result = fetch_and_analyze(url, timeout=10)
            html_risk_score = html_result.get("html_risk_score", 0.0)
        except Exception:
            logger.debug("HTML analysis failed for %s", url, exc_info=True)

    # ── ML Prediction ────────────────────────────────────────────────────
    model, feature_names = _load_model()
    ordered = {k: lexical.get(k, 0) for k in feature_names}
    x_pred = pd.DataFrame([ordered])
    prob = model.predict_proba(x_pred)[0]
    ml_score = round(prob[1] * 100, 1)

    # ── Risk score (additive, capped at 100) ─────────────────────────────
    risk = ml_score
    if vt_info.get("vt_is_malicious"):
        risk += WEIGHT_VT_MALICIOUS
    if gsb_info.get("gsb_is_dangerous"):
        risk += WEIGHT_GSB_DANGEROUS
    if uh_info.get("urlhaus_is_malicious"):
        risk += WEIGHT_URLHAUS_MALICIOUS
    if homo_info.get("is_lookalike"):
        risk += WEIGHT_LOOKALIKE
    if age_info.get("domain_is_new"):
        risk += WEIGHT_DOMAIN_NEW
    if ssl_info.get("ssl_valid") == 0:
        risk += WEIGHT_SSL_INVALID
    if legit_info.get("is_subdomain_spoof"):
        risk += WEIGHT_SUBDOMAIN_SPOOF
    risk = min(risk, 100)

    # Whitelist bonus
    if legit_info.get("is_exact_match"):
        risk = min(risk, 20)
    risk = round(risk, 1)

    # ── Verdict ──────────────────────────────────────────────────────────
    if risk >= RISK_DANGEROUS:
        verdict = "DANGEROUS"
    elif risk >= RISK_SUSPICIOUS:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # ── Build flags ──────────────────────────────────────────────────────
    flags: list[str] = []
    if vt_info.get("vt_is_malicious"):
        flags.append(f"VirusTotal: {vt_info['vt_positives']} engines flagged")
    if gsb_info.get("gsb_is_dangerous"):
        flags.append(f"Google Safe Browsing: {gsb_info['gsb_threat_type']}")
    if uh_info.get("urlhaus_is_malicious"):
        flags.append(f"URLhaus: {uh_info['urlhaus_threat']}")
    if homo_info.get("is_lookalike"):
        flags.append(f"Lookalike domain: {homo_info['lookalike_brand']}")
    if age_info.get("domain_is_new"):
        flags.append(f"New domain: {age_info['domain_age_days']} days")
    if ssl_info.get("ssl_valid") == 0:
        flags.append("Invalid SSL certificate")
    if legit_info.get("is_subdomain_spoof"):
        flags.append("Subdomain spoofing detected")
    if lexical.get("IpAddress"):
        flags.append("IP address used instead of domain")
    if lexical.get("SuspiciousTLD"):
        flags.append("Suspicious TLD")
    if html_risk_score > 30:
        flags.append(f"HTML content risk: {html_risk_score}")

    # ── Save to DB ───────────────────────────────────────────────────────
    check_mode = "full" if use_apis else "quick"
    log_check(url, risk, ml_score, verdict, check_mode)

    return CheckUrlResponse(
        url=url,
        risk_score=risk,
        verdict=verdict,
        ml_score=ml_score,
        ssl_valid=ssl_info.get("ssl_valid", 0),
        ssl_issuer=ssl_info.get("ssl_issuer", "unknown"),
        domain_age_days=age_info.get("domain_age_days", -1),
        domain_is_new=age_info.get("domain_is_new", 0),
        registrar=age_info.get("registrar", "unknown"),
        has_punycode=homo_info.get("has_punycode", 0),
        is_lookalike=homo_info.get("is_lookalike", 0),
        lookalike_brand=homo_info.get("lookalike_brand", ""),
        vt_positives=vt_info.get("vt_positives", 0),
        vt_total=vt_info.get("vt_total", 0),
        vt_is_malicious=vt_info.get("vt_is_malicious", 0),
        gsb_is_dangerous=gsb_info.get("gsb_is_dangerous", 0),
        gsb_threat_type=gsb_info.get("gsb_threat_type", "none"),
        urlhaus_is_malicious=uh_info.get("urlhaus_is_malicious", 0),
        urlhaus_threat=uh_info.get("urlhaus_threat", "none"),
        is_official=legit_info.get("is_exact_match", 0),
        is_subdomain_spoof=legit_info.get("is_subdomain_spoof", 0),
        html_risk_score=html_risk_score,
        flags=flags,
        checked_at=str(datetime.now()),
    )
