"""
legit_domain_checker.py — Kiểm tra domain hợp lệ VN (8-point verification).

Phát hiện subdomain spoofing: vietcombank.com.vn.evil.com
Xác minh domain chính thức: vietcombank.com.vn → SAFE
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import (
    VN_OFFICIAL_BANKS, VN_OFFICIAL_GOV, SOCIAL_MEDIA_OFFICIAL,
    ALL_OFFICIAL_DOMAINS, TOP_BRANDS,
)


def _get_root_domain(domain: str) -> str:
    """Lấy root domain (2-3 phần cuối tùy .com.vn / .gov.vn)."""
    parts = domain.lower().strip('.').split('.')
    # Handle .com.vn, .gov.vn, .org.vn etc.
    if len(parts) >= 3 and parts[-1] == 'vn' and parts[-2] in ('com', 'gov', 'org', 'edu', 'net'):
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def _extract_domain(url: str) -> str:
    """Tách domain từ URL."""
    try:
        if not url.startswith('http'):
            url = 'https://' + url
        parsed = urlparse(url)
        return parsed.hostname.lower() if parsed.hostname else url.lower()
    except Exception:
        return url.lower().split('/')[0]


def check_legitimate_domain(url: str) -> dict:
    """
    8-point verification cho domain chính thức.

    Returns:
        dict với các key:
        - is_official_bank: 0/1
        - is_official_gov: 0/1
        - is_social_media: 0/1
        - is_exact_match: 0/1
        - is_subdomain_spoof: 0/1
        - brand_in_subdomain: 0/1
        - uses_official_https: 0/1
        - legitimacy_score: 0-100
    """
    default = {
        'is_official_bank': 0,
        'is_official_gov': 0,
        'is_social_media': 0,
        'is_exact_match': 0,
        'is_subdomain_spoof': 0,
        'brand_in_subdomain': 0,
        'uses_official_https': 0,
        'legitimacy_score': 0,
    }

    try:
        full_domain = _extract_domain(url)
        root_domain = _get_root_domain(full_domain)
        is_https = url.lower().startswith('https')

        # ── Check 1: Exact match with official bank ──────────────────────
        is_bank = 0
        for bank in VN_OFFICIAL_BANKS:
            if root_domain == bank or full_domain == bank or full_domain == 'www.' + bank:
                is_bank = 1
                break

        # ── Check 2: Exact match with official gov ───────────────────────
        is_gov = 0
        for gov in VN_OFFICIAL_GOV:
            if root_domain == gov or full_domain.endswith('.' + gov) or full_domain == gov:
                is_gov = 1
                break

        # ── Check 3: Social media official ───────────────────────────────
        is_social = 0
        for sm in SOCIAL_MEDIA_OFFICIAL:
            if root_domain == sm or full_domain == sm or full_domain == 'www.' + sm:
                is_social = 1
                break
            # Allow m.facebook.com, l.facebook.com etc.
            if full_domain.endswith('.' + sm):
                is_social = 1
                break

        # ── Check 4: Exact match any whitelist ───────────────────────────
        is_exact = 0
        for official in ALL_OFFICIAL_DOMAINS:
            if root_domain == official or full_domain == official or full_domain == 'www.' + official:
                is_exact = 1
                break
            if full_domain.endswith('.' + official):
                is_exact = 1
                break

        # ── Check 5: Subdomain spoofing detection ────────────────────────
        is_spoof = 0
        if not is_exact:
            # Check if any brand name appears in the full domain
            # but root domain is NOT official
            for brand in TOP_BRANDS:
                if brand in full_domain:
                    # Brand found in domain but not an official domain → spoof
                    is_spoof = 1
                    break
            # Check for official domains used as subdomains
            # e.g., vietcombank.com.vn.evil.com
            for official in ALL_OFFICIAL_DOMAINS:
                official_no_dots = official.replace('.', '')
                if official_no_dots in full_domain.replace('.', '') and root_domain != official:
                    # Check more carefully
                    if official in full_domain and not full_domain.endswith(official):
                        is_spoof = 1
                        break

        # ── Check 6: Brand in subdomain only ─────────────────────────────
        brand_in_sub = 0
        if not is_exact:
            parts = full_domain.split('.')
            subdomains = parts[:-2] if len(parts) > 2 else []
            sub_text = '.'.join(subdomains)
            for brand in TOP_BRANDS:
                if brand in sub_text and brand not in root_domain:
                    brand_in_sub = 1
                    break

        # ── Check 7: Uses HTTPS ──────────────────────────────────────────
        uses_https = 1 if (is_https and is_exact) else 0

        # ── Check 8: Legitimacy score ────────────────────────────────────
        score = 0
        if is_exact:
            score += 60
        if is_bank or is_gov:
            score += 20
        if is_social:
            score += 15
        if uses_https:
            score += 10
        if is_spoof:
            score = max(score - 50, 0)
        if brand_in_sub:
            score = max(score - 30, 0)
        score = min(score, 100)

        return {
            'is_official_bank': is_bank,
            'is_official_gov': is_gov,
            'is_social_media': is_social,
            'is_exact_match': is_exact,
            'is_subdomain_spoof': is_spoof,
            'brand_in_subdomain': brand_in_sub,
            'uses_official_https': uses_https,
            'legitimacy_score': score,
        }

    except Exception:
        return default


# ─── Quick test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        ("https://www.vietcombank.com.vn", True),
        ("https://vietcombank.com.vn.login-secure.xyz", False),
        ("https://www.facebook.com", True),
        ("https://faceb00k-login.tk", False),
        ("https://www.youtube.com", True),
        ("https://youtube-verify.xyz", False),
        ("https://github.com", True),
    ]
    for url, expect_safe in tests:
        r = check_legitimate_domain(url)
        safe = r['is_exact_match'] == 1
        icon = "✅" if safe == expect_safe else "❌"
        print(f"{icon} {url}")
        print(f"   exact={r['is_exact_match']} bank={r['is_official_bank']} "
              f"spoof={r['is_subdomain_spoof']} score={r['legitimacy_score']}")
