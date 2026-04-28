"""
advanced_features.py — Trích xuất đặc trưng nâng cao cho hệ thống phát hiện URL phishing.

Bao gồm:
  [1] extract_lexical_features  — 25 features thuần string
  [2] check_ssl                 — Kiểm tra chứng chỉ SSL
  [3] check_domain_age          — Kiểm tra tuổi domain (WHOIS)
  [4] check_homograph           — Phát hiện domain giả mạo
  [5] check_virustotal          — Truy vấn VirusTotal API
  [6] check_google_safe_browsing— Truy vấn Google Safe Browsing API
  [7] check_urlhaus             — Truy vấn URLhaus (abuse.ch)
  [8] get_all_features          — Gộp tất cả thành 1 dict phẳng
"""

import os
import re
import ssl
import math
import time
import socket
import datetime
import requests
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

SENSITIVE_WORDS = [
    'login', 'bank', 'secure', 'verify', 'update', 'account', 'signin',
    'password', 'confirm', 'paypal', 'wallet', 'free', 'lucky', 'prize',
    'winner', 'urgent', 'alert', 'suspend',
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.click', '.download', '.work', '.party',
]

TOP_BRANDS = [
    'google', 'facebook', 'youtube', 'instagram', 'tiktok',
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix',
    'twitter', 'linkedin', 'github', 'bankofamerica', 'chase',
]

TRUSTED_CAS = [
    'digicert', 'comodo', 'globalsign', 'entrust', 'godaddy',
    'sectigo', 'thawte', 'geotrust', 'rapidssl', 'symantec',
    'buypass', 'certum', 'ssl.com', 'usertrust',
]


# ═══════════════════════════════════════════════════════════════════════════════
# [1] extract_lexical_features
# ═══════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(text: str) -> float:
    """Tính Shannon entropy của chuỗi."""
    if not text:
        return 0.0
    length = len(text)
    return -sum(
        (text.count(c) / length) * math.log2(text.count(c) / length)
        for c in set(text)
        if text.count(c) > 0
    )


def extract_lexical_features(url: str) -> dict:
    """
    Trích xuất 25 features thuần string từ URL (không cần network).

    Returns:
        dict với 25 keys: UrlLength, NumDots, NumDash, NumDashInHostname,
        AtSymbol, TildeSymbol, NumUnderscore, NumPercent, NumAmpersand,
        NumHash, NumNumericChars, NoHttps, IpAddress, SubdomainLevel,
        HostnameLength, PathLength, QueryLength, DoubleSlashInPath,
        NumSensitiveWords, NumQueryComponents, DomainInPaths,
        HttpsInHostname, SuspiciousTLD, RandomString, UrlEntropy
    """
    features = {}
    try:
        url_lower = url.lower()

        # Tách domain và path
        if '//' in url:
            after_scheme = url.split('//', 1)[1]
            parts = after_scheme.split('/', 1)
            domain = parts[0]
            path = parts[1] if len(parts) > 1 else ""
        else:
            domain = url
            path = ""

        # Tách query string
        query = url.split('?', 1)[1] if '?' in url else ""

        features['UrlLength']           = len(url)
        features['NumDots']             = url.count('.')
        features['NumDash']             = url.count('-')
        features['NumDashInHostname']   = domain.count('-')
        features['AtSymbol']            = 1 if '@' in url else 0
        features['TildeSymbol']         = 1 if '~' in url else 0
        features['NumUnderscore']       = url.count('_')
        features['NumPercent']          = url.count('%')
        features['NumAmpersand']        = url.count('&')
        features['NumHash']             = url.count('#')
        features['NumNumericChars']     = sum(c.isdigit() for c in url)
        features['NoHttps']             = 0 if url_lower.startswith('https') else 1
        features['IpAddress']           = 1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0
        features['SubdomainLevel']      = domain.count('.')
        features['HostnameLength']      = len(domain)
        features['PathLength']          = len(path)
        features['QueryLength']         = len(query)
        features['DoubleSlashInPath']   = 1 if '//' in path else 0
        features['NumSensitiveWords']   = sum(1 for w in SENSITIVE_WORDS if w in url_lower)
        features['NumQueryComponents']  = query.count('&') + 1 if query else 0
        features['DomainInPaths']       = 1 if re.search(r'[a-z0-9-]+\.[a-z]{2,}', path) else 0
        features['HttpsInHostname']     = 1 if 'https' in domain.lower() else 0
        features['SuspiciousTLD']       = 1 if any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
        features['UrlEntropy']          = _shannon_entropy(url)
        features['RandomString']        = 1 if features['UrlEntropy'] > 4.2 else 0

    except Exception:
        # Trả về tất cả 0 nếu có lỗi bất kỳ
        for key in [
            'UrlLength', 'NumDots', 'NumDash', 'NumDashInHostname',
            'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent',
            'NumAmpersand', 'NumHash', 'NumNumericChars', 'NoHttps',
            'IpAddress', 'SubdomainLevel', 'HostnameLength', 'PathLength',
            'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords',
            'NumQueryComponents', 'DomainInPaths', 'HttpsInHostname',
            'SuspiciousTLD', 'RandomString', 'UrlEntropy',
        ]:
            features[key] = 0

    return features


# ═══════════════════════════════════════════════════════════════════════════════
# [2] check_ssl
# ═══════════════════════════════════════════════════════════════════════════════

def check_ssl(domain: str) -> dict:
    """
    Kiểm tra chứng chỉ SSL bằng ssl + socket (stdlib).

    Returns:
        dict: ssl_valid, ssl_days_remaining, ssl_issuer, ssl_is_trusted_ca
    """
    default = {
        'ssl_valid': 0,
        'ssl_days_remaining': 0,
        'ssl_issuer': 'unknown',
        'ssl_is_trusted_ca': 0,
    }
    try:
        # Loại bỏ port nếu có
        host = domain.split(':')[0]

        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        # Ngày hết hạn
        not_after_str = cert.get('notAfter', '')
        not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.datetime.utcnow()).days

        # Issuer
        issuer_parts = dict(x[0] for x in cert.get('issuer', ()))
        issuer_org = issuer_parts.get('organizationName', 'unknown')

        # Trusted CA check
        issuer_lower = issuer_org.lower()
        is_trusted = 1 if any(ca in issuer_lower for ca in TRUSTED_CAS) else 0
        # Let's Encrypt và self-signed → không trusted
        if "let's encrypt" in issuer_lower or 'self' in issuer_lower:
            is_trusted = 0

        return {
            'ssl_valid': 1,
            'ssl_days_remaining': max(days_remaining, 0),
            'ssl_issuer': issuer_org,
            'ssl_is_trusted_ca': is_trusted,
        }

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [3] check_domain_age
# ═══════════════════════════════════════════════════════════════════════════════

def check_domain_age(domain: str) -> dict:
    """
    Kiểm tra tuổi domain bằng python-whois.

    Returns:
        dict: domain_age_days, domain_is_new, registrar
    """
    default = {
        'domain_age_days': -1,
        'domain_is_new': 0,
        'registrar': 'unknown',
    }
    try:
        import whois

        # Loại bỏ port nếu có
        host = domain.split(':')[0]

        # Timeout thủ công bằng socket
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)
        try:
            w = whois.whois(host)
        finally:
            socket.setdefaulttimeout(old_timeout)

        # Xử lý creation_date (có thể là list)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return default

        if isinstance(creation_date, str):
            creation_date = datetime.datetime.strptime(creation_date, '%Y-%m-%d')

        age_days = (datetime.datetime.utcnow() - creation_date).days
        registrar = w.registrar if w.registrar else 'unknown'

        return {
            'domain_age_days': age_days,
            'domain_is_new': 1 if age_days < 90 else 0,
            'registrar': str(registrar),
        }

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [4] check_homograph
# ═══════════════════════════════════════════════════════════════════════════════

def check_homograph(domain: str) -> dict:
    """
    Phát hiện domain giả mạo: Punycode + Levenshtein look-alike.

    Returns:
        dict: has_punycode, is_lookalike, lookalike_brand
    """
    default = {
        'has_punycode': 0,
        'is_lookalike': 0,
        'lookalike_brand': '',
    }
    try:
        host = domain.split(':')[0].lower()

        # Punycode detection
        has_punycode = 1 if 'xn--' in host else 0

        # Lấy phần domain chính (bỏ TLD)
        parts = host.split('.')
        # Lấy tên domain chính (phần trước TLD cuối cùng)
        if len(parts) >= 2:
            main_domain = parts[-2]
        else:
            main_domain = parts[0]

        # Levenshtein distance
        try:
            from Levenshtein import distance as lev_distance
        except ImportError:
            # Fallback: simple implementation
            def lev_distance(s1, s2):
                if len(s1) < len(s2):
                    return lev_distance(s2, s1)
                if len(s2) == 0:
                    return len(s1)
                prev_row = range(len(s2) + 1)
                for i, c1 in enumerate(s1):
                    curr_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = prev_row[j + 1] + 1
                        deletions = curr_row[j] + 1
                        substitutions = prev_row[j] + (c1 != c2)
                        curr_row.append(min(insertions, deletions, substitutions))
                    prev_row = curr_row
                return prev_row[-1]

        min_dist = float('inf')
        closest_brand = ''
        for brand in TOP_BRANDS:
            d = lev_distance(main_domain, brand)
            if d < min_dist:
                min_dist = d
                closest_brand = brand

        is_lookalike = 1 if 0 < min_dist <= 2 else 0
        lookalike_brand = closest_brand if is_lookalike else ''

        return {
            'has_punycode': has_punycode,
            'is_lookalike': is_lookalike,
            'lookalike_brand': lookalike_brand,
        }

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [5] check_virustotal
# ═══════════════════════════════════════════════════════════════════════════════

def check_virustotal(url: str, api_key: str) -> dict:
    """
    Truy vấn VirusTotal v2 API.

    Returns:
        dict: vt_positives, vt_total, vt_is_malicious
    """
    default = {
        'vt_positives': 0,
        'vt_total': 0,
        'vt_is_malicious': 0,
    }
    if not api_key or api_key == 'your_key_here':
        return default

    try:
        resp = requests.get(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params={'apikey': api_key, 'resource': url},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        positives = data.get('positives', 0)
        total = data.get('total', 0)

        return {
            'vt_positives': positives,
            'vt_total': total,
            'vt_is_malicious': 1 if positives >= 3 else 0,
        }

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [6] check_google_safe_browsing
# ═══════════════════════════════════════════════════════════════════════════════

def check_google_safe_browsing(url: str, api_key: str) -> dict:
    """
    Truy vấn Google Safe Browsing v4 API.

    Returns:
        dict: gsb_is_dangerous, gsb_threat_type
    """
    default = {
        'gsb_is_dangerous': 0,
        'gsb_threat_type': 'none',
    }
    if not api_key or api_key == 'your_key_here':
        return default

    try:
        endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        body = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        resp = requests.post(endpoint, json=body, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        matches = data.get('matches', [])
        if matches:
            threat_type = matches[0].get('threatType', 'unknown')
            return {
                'gsb_is_dangerous': 1,
                'gsb_threat_type': threat_type,
            }

        return default

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [7] check_urlhaus
# ═══════════════════════════════════════════════════════════════════════════════

def check_urlhaus(url: str) -> dict:
    """
    Truy vấn URLhaus (abuse.ch) — không cần API key.

    Returns:
        dict: urlhaus_is_malicious, urlhaus_threat
    """
    default = {
        'urlhaus_is_malicious': 0,
        'urlhaus_threat': 'none',
    }
    try:
        resp = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get('query_status', '')
        if query_status == 'is_malicious':
            threat = data.get('threat', 'unknown')
            return {
                'urlhaus_is_malicious': 1,
                'urlhaus_threat': threat,
            }

        return default

    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# [8] get_all_features
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_features(url: str, use_apis: bool = True) -> dict:
    """
    Gọi TẤT CẢ hàm trên, merge dict, trả về 1 dict phẳng duy nhất.

    Args:
        url: URL cần phân tích.
        use_apis: Nếu False, chỉ chạy lexical + ssl + domain_age + homograph.

    Returns:
        dict chứa tất cả features.
    """
    all_features = {}

    # Tách domain từ URL
    try:
        if '//' in url:
            domain = url.split('//', 1)[1].split('/', 1)[0]
        else:
            domain = url.split('/', 1)[0]
        # Loại bỏ port
        domain = domain.split(':')[0]
    except Exception:
        domain = url

    # ── Lexical features (luôn chạy) ──────────────────────────────────────
    t0 = time.time()
    lexical = extract_lexical_features(url)
    all_features.update(lexical)
    print(f"  [1/7] Lexical features    : {time.time()-t0:.2f}s  ({len(lexical)} features)")

    # ── SSL check ─────────────────────────────────────────────────────────
    t0 = time.time()
    ssl_info = check_ssl(domain)
    all_features.update(ssl_info)
    print(f"  [2/7] SSL check           : {time.time()-t0:.2f}s  (valid={ssl_info['ssl_valid']})")

    # ── Domain age ────────────────────────────────────────────────────────
    t0 = time.time()
    age_info = check_domain_age(domain)
    all_features.update(age_info)
    print(f"  [3/7] Domain age          : {time.time()-t0:.2f}s  (age={age_info['domain_age_days']}d)")

    # ── Homograph ─────────────────────────────────────────────────────────
    t0 = time.time()
    homo_info = check_homograph(domain)
    all_features.update(homo_info)
    print(f"  [4/7] Homograph check     : {time.time()-t0:.2f}s  (lookalike={homo_info['is_lookalike']})")

    if use_apis:
        vt_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
        gsb_key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

        # ── VirusTotal ────────────────────────────────────────────────────
        t0 = time.time()
        vt_info = check_virustotal(url, vt_key)
        all_features.update(vt_info)
        print(f"  [5/7] VirusTotal          : {time.time()-t0:.2f}s  (positives={vt_info['vt_positives']})")

        # ── Google Safe Browsing ──────────────────────────────────────────
        t0 = time.time()
        gsb_info = check_google_safe_browsing(url, gsb_key)
        all_features.update(gsb_info)
        print(f"  [6/7] Google Safe Browsing: {time.time()-t0:.2f}s  (dangerous={gsb_info['gsb_is_dangerous']})")

        # ── URLhaus ───────────────────────────────────────────────────────
        t0 = time.time()
        uh_info = check_urlhaus(url)
        all_features.update(uh_info)
        print(f"  [7/7] URLhaus             : {time.time()-t0:.2f}s  (malicious={uh_info['urlhaus_is_malicious']})")
    else:
        # Đặt giá trị mặc định cho API features
        all_features.update({
            'vt_positives': 0, 'vt_total': 0, 'vt_is_malicious': 0,
            'gsb_is_dangerous': 0, 'gsb_threat_type': 'none',
            'urlhaus_is_malicious': 0, 'urlhaus_threat': 'none',
        })
        print("  [5-7] API checks          : SKIPPED (use_apis=False)")

    return all_features
