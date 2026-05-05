"""
email_analyzer.py — Analyze raw emails for phishing indicators.

Detects:
- SPF/DKIM/DMARC validation
- Display name spoofing (e.g., "Vietcombank" <evil@gmail.com>)
- Reply-To mismatch
- URL extraction from email body
- HTML body analysis (delegates to html_analyzer)
"""
import email
import email.policy
import logging
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import TOP_BRANDS
from utils.html_analyzer import analyze_html

logger = logging.getLogger(__name__)

# ─── Brand names for display-name spoofing detection ─────────────────────────
_SPOOF_BRANDS = list(set(TOP_BRANDS + [
    "vietcombank", "techcombank", "mbbank", "tpbank", "vpbank",
    "agribank", "bidv", "vietinbank", "momo", "zalopay",
    "paypal", "apple", "microsoft", "google", "facebook",
]))

# ─── URL regex ───────────────────────────────────────────────────────────────
_URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+', re.IGNORECASE
)


def _extract_sender_parts(from_header: str) -> tuple[str, str]:
    """Extract display name and email address from From header.

    Returns:
        (display_name, email_address) tuple.
    """
    match = re.match(
        r'^"?([^"<]*)"?\s*<([^>]+)>', from_header.strip()
    )
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    # Bare email address
    addr = from_header.strip().strip("<>").lower()
    return "", addr


def _get_domain(email_addr: str) -> str:
    """Extract domain part from email address."""
    if "@" in email_addr:
        return email_addr.split("@", 1)[1]
    return ""


def _check_display_name_spoof(
    display_name: str, sender_domain: str
) -> tuple[bool, str]:
    """Check if display name impersonates a known brand.

    Returns:
        (is_spoofed, matched_brand) tuple.
    """
    name_lower = display_name.lower()
    for brand in _SPOOF_BRANDS:
        if brand in name_lower:
            # If the brand is NOT in the actual sender domain, it's spoofing
            if brand not in sender_domain:
                return True, brand
    return False, ""


def _check_spf(msg: email.message.EmailMessage) -> bool:
    """Check SPF result from Authentication-Results header."""
    auth = msg.get("Authentication-Results", "")
    return "spf=pass" in auth.lower()


def _check_dkim(msg: email.message.EmailMessage) -> bool:
    """Check DKIM result from Authentication-Results header."""
    auth = msg.get("Authentication-Results", "")
    return "dkim=pass" in auth.lower()


def _check_dmarc(msg: email.message.EmailMessage) -> bool:
    """Check DMARC result from Authentication-Results header."""
    auth = msg.get("Authentication-Results", "")
    return "dmarc=pass" in auth.lower()


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from a text string."""
    return list(set(_URL_PATTERN.findall(text)))


def _get_body_parts(
    msg: email.message.EmailMessage,
) -> tuple[str, str]:
    """Extract plain text and HTML body from email message.

    Returns:
        (text_body, html_body) tuple.
    """
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if content_type == "text/plain" and not text_body:
                text_body = decoded
            elif content_type == "text/html" and not html_body:
                html_body = decoded
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    html_body = decoded
                else:
                    text_body = decoded
        except Exception:
            logger.debug("Error decoding email body", exc_info=True)

    return text_body, html_body


def analyze_email(raw_email: str) -> dict:
    """Analyze a raw email (RFC 2822) for phishing indicators.

    Args:
        raw_email: Full raw email content as string.

    Returns:
        Flat dict with detection results and email_risk_score (0-100).
    """
    default = {
        "spf_pass": 0,
        "dkim_pass": 0,
        "dmarc_pass": 0,
        "display_name_spoof": 0,
        "spoofed_brand": "",
        "sender_domain": "",
        "sender_email": "",
        "reply_to_mismatch": 0,
        "urls_found": [],
        "url_count": 0,
        "html_risk": {},
        "email_risk_score": 0.0,
        "email_flags": [],
    }

    if not raw_email or not raw_email.strip():
        return default

    try:
        msg = email.message_from_string(
            raw_email, policy=email.policy.default
        )
    except Exception:
        logger.exception("Failed to parse email")
        return default

    result = default.copy()
    flags: list[str] = []
    result["email_flags"] = flags
    score = 0.0

    # ── 1. Parse sender info ─────────────────────────────────────────────
    from_header = msg.get("From", "")
    display_name, sender_email = _extract_sender_parts(from_header)
    sender_domain = _get_domain(sender_email)

    result["sender_email"] = sender_email
    result["sender_domain"] = sender_domain

    # ── 2. SPF / DKIM / DMARC ────────────────────────────────────────────
    spf = _check_spf(msg)
    dkim = _check_dkim(msg)
    dmarc = _check_dmarc(msg)

    result["spf_pass"] = 1 if spf else 0
    result["dkim_pass"] = 1 if dkim else 0
    result["dmarc_pass"] = 1 if dmarc else 0

    if not spf:
        score += 15
        flags.append("SPF check failed")
    if not dkim:
        score += 15
        flags.append("DKIM check failed")
    if not dmarc:
        score += 10
        flags.append("DMARC check failed")

    # ── 3. Display name spoofing ─────────────────────────────────────────
    is_spoofed, spoofed_brand = _check_display_name_spoof(
        display_name, sender_domain
    )
    if is_spoofed:
        result["display_name_spoof"] = 1
        result["spoofed_brand"] = spoofed_brand
        score += 25
        flags.append(
            f'Display name spoofing: "{display_name}" impersonates {spoofed_brand}'
        )

    # ── 4. Reply-To mismatch ─────────────────────────────────────────────
    reply_to = msg.get("Reply-To", "")
    if reply_to:
        _, reply_email = _extract_sender_parts(reply_to)
        reply_domain = _get_domain(reply_email)
        if reply_domain and reply_domain != sender_domain:
            result["reply_to_mismatch"] = 1
            score += 15
            flags.append(
                f"Reply-To domain ({reply_domain}) differs from sender ({sender_domain})"
            )

    # ── 5. Extract URLs ──────────────────────────────────────────────────
    text_body, html_body = _get_body_parts(msg)
    all_text = f"{text_body} {html_body}"
    urls = _extract_urls_from_text(all_text)
    result["urls_found"] = urls[:20]  # cap at 20
    result["url_count"] = len(urls)

    if len(urls) > 10:
        score += 5
        flags.append(f"High URL count: {len(urls)} URLs found in email")

    # ── 6. HTML body analysis ────────────────────────────────────────────
    if html_body:
        html_result = analyze_html(html_body, source_url=sender_domain)
        result["html_risk"] = html_result
        # Add HTML risk to email risk (weighted at 50%)
        score += html_result.get("html_risk_score", 0) * 0.5
        if html_result.get("html_flags"):
            for hf in html_result["html_flags"]:
                flags.append(f"[HTML] {hf}")

    result["email_risk_score"] = min(round(score, 1), 100.0)

    return result
