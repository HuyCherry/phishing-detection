"""
html_analyzer.py — Analyze HTML content for phishing indicators.

Detects suspicious patterns in HTML pages such as:
- Login forms posting to external domains
- Hidden inputs / password fields
- Meta refresh redirects
- Brand impersonation in content
- External iframes
- Cloaked (hidden) sensitive content
"""
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import TOP_BRANDS, SENSITIVE_WORDS

logger = logging.getLogger(__name__)

# ─── Signal weights ──────────────────────────────────────────────────────────
SIGNALS = {
    "form_action_external": 30,
    "meta_redirect": 25,
    "cloaked_content": 20,
    "brand_impersonation": 20,
    "iframe_external": 15,
    "password_field": 10,
    "hidden_inputs": 10,
}

# Vietnamese brand keywords for content matching
_VN_BRAND_KEYWORDS = [
    "vietcombank", "techcombank", "mbbank", "tpbank", "vpbank",
    "agribank", "bidv", "vietinbank", "acb", "sacombank",
    "momo", "zalopay", "vnpay", "shopee", "lazada", "tiki",
]


def _extract_domain(url: str) -> str:
    """Extract domain from a URL string, safely."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname or ""
    except Exception:
        return ""


def _get_root_domain(domain: str) -> str:
    """Extract root domain (e.g., 'sub.example.com' -> 'example.com')."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def analyze_html(
    html_content: str, source_url: str = ""
) -> dict:
    """Analyze HTML content for phishing indicators.

    Args:
        html_content: Raw HTML string to analyze.
        source_url: The URL this HTML was fetched from (for domain comparison).

    Returns:
        Flat dict with detection results and html_risk_score (0-100).
    """
    default = {
        "form_action_suspicious": 0,
        "has_hidden_inputs": 0,
        "has_password_field": 0,
        "external_resources_count": 0,
        "meta_refresh_redirect": 0,
        "brand_keywords_found": [],
        "cloaked_content": 0,
        "iframe_external": 0,
        "html_risk_score": 0.0,
        "html_flags": [],
    }

    if not html_content or not html_content.strip():
        return default

    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            logger.exception("Failed to parse HTML")
            return default

    source_domain = _extract_domain(source_url)
    source_root = _get_root_domain(source_domain) if source_domain else ""

    flags: list[str] = []
    result = default.copy()
    result["html_flags"] = flags

    # ── 1. Form action analysis ──────────────────────────────────────────
    try:
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            if action and action.startswith("http"):
                action_domain = _extract_domain(action)
                action_root = _get_root_domain(action_domain)
                if source_root and action_root != source_root:
                    result["form_action_suspicious"] = 1
                    flags.append(
                        f"Form POST to external domain: {action_domain}"
                    )
                    break
    except Exception:
        logger.debug("Error analyzing forms", exc_info=True)

    # ── 2. Hidden inputs ─────────────────────────────────────────────────
    try:
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        if len(hidden_inputs) >= 3:
            result["has_hidden_inputs"] = 1
            flags.append(f"{len(hidden_inputs)} hidden input fields found")
    except Exception:
        logger.debug("Error analyzing hidden inputs", exc_info=True)

    # ── 3. Password field ────────────────────────────────────────────────
    try:
        password_fields = soup.find_all("input", {"type": "password"})
        if password_fields:
            result["has_password_field"] = 1
            flags.append("Password input field detected")
    except Exception:
        logger.debug("Error analyzing password fields", exc_info=True)

    # ── 4. External resources (img, script src) ──────────────────────────
    try:
        external_count = 0
        for tag in soup.find_all(["img", "script", "link"], src=True):
            src = tag.get("src", "") or tag.get("href", "")
            if src and src.startswith("http"):
                src_domain = _extract_domain(src)
                src_root = _get_root_domain(src_domain)
                if source_root and src_root != source_root:
                    external_count += 1
        result["external_resources_count"] = external_count
    except Exception:
        logger.debug("Error analyzing external resources", exc_info=True)

    # ── 5. Meta refresh redirect ─────────────────────────────────────────
    try:
        meta_tags = soup.find_all("meta", attrs={"http-equiv": True})
        for meta in meta_tags:
            if meta.get("http-equiv", "").lower() == "refresh":
                content = meta.get("content", "")
                if "url=" in content.lower():
                    result["meta_refresh_redirect"] = 1
                    redirect_url = re.search(
                        r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE
                    )
                    target = redirect_url.group(1) if redirect_url else "unknown"
                    flags.append(f"Meta refresh redirect to: {target}")
                    break
    except Exception:
        logger.debug("Error analyzing meta redirects", exc_info=True)

    # ── 6. Brand impersonation ───────────────────────────────────────────
    try:
        page_text = soup.get_text(separator=" ").lower()
        title_tag = soup.find("title")
        title_text = title_tag.get_text().lower() if title_tag else ""
        full_text = f"{title_text} {page_text}"

        found_brands: list[str] = []
        all_brands = list(set(TOP_BRANDS + _VN_BRAND_KEYWORDS))
        for brand in all_brands:
            if brand in full_text:
                # Check if source domain actually belongs to this brand
                if source_root and brand not in source_root:
                    found_brands.append(brand)

        if found_brands:
            result["brand_keywords_found"] = found_brands[:5]
            flags.append(
                f"Brand keywords in content: {', '.join(found_brands[:5])}"
            )
    except Exception:
        logger.debug("Error analyzing brand impersonation", exc_info=True)

    # ── 7. Cloaked content (display:none with sensitive text) ─────────────
    try:
        hidden_elements = soup.find_all(
            style=re.compile(r"display\s*:\s*none", re.IGNORECASE)
        )
        for el in hidden_elements:
            el_text = el.get_text().lower()
            for word in SENSITIVE_WORDS[:20]:
                if word in el_text:
                    result["cloaked_content"] = 1
                    flags.append(f"Hidden text contains sensitive word: {word}")
                    break
            if result["cloaked_content"]:
                break
    except Exception:
        logger.debug("Error analyzing cloaked content", exc_info=True)

    # ── 8. External iframes ──────────────────────────────────────────────
    try:
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            src = iframe.get("src", "")
            if src and src.startswith("http"):
                iframe_domain = _extract_domain(src)
                iframe_root = _get_root_domain(iframe_domain)
                if source_root and iframe_root != source_root:
                    result["iframe_external"] = 1
                    flags.append(f"External iframe: {iframe_domain}")
                    break
    except Exception:
        logger.debug("Error analyzing iframes", exc_info=True)

    # ── Calculate risk score ─────────────────────────────────────────────
    score = 0.0
    if result["form_action_suspicious"]:
        score += SIGNALS["form_action_external"]
    if result["meta_refresh_redirect"]:
        score += SIGNALS["meta_redirect"]
    if result["cloaked_content"]:
        score += SIGNALS["cloaked_content"]
    if result["brand_keywords_found"]:
        score += SIGNALS["brand_impersonation"]
    if result["iframe_external"]:
        score += SIGNALS["iframe_external"]
    if result["has_password_field"]:
        score += SIGNALS["password_field"]
    if result["has_hidden_inputs"]:
        score += SIGNALS["hidden_inputs"]

    result["html_risk_score"] = min(score, 100.0)

    return result


def fetch_and_analyze(url: str, timeout: int = 10) -> dict:
    """Fetch a URL and analyze its HTML content.

    Args:
        url: The URL to fetch and analyze.
        timeout: HTTP request timeout in seconds.

    Returns:
        Analysis result dict from analyze_html().
    """
    try:
        import requests

        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
            allow_redirects=True,
            verify=False,
        )
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            logger.info("Non-HTML content type: %s", content_type)
            return analyze_html("", url)
        return analyze_html(resp.text, url)
    except Exception:
        logger.exception("Failed to fetch %s for HTML analysis", url)
        return analyze_html("", url)
