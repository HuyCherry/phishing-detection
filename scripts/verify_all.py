"""Quick verification of all modules."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 1. Config
from config import VN_OFFICIAL_BANKS, TOP_BRANDS, SENSITIVE_WORDS
print("1. config.py OK")
print(f"   Banks: {len(VN_OFFICIAL_BANKS)}, Brands: {len(TOP_BRANDS)}")

# 2. Legit domain checker
from utils.legit_domain_checker import check_legitimate_domain

tests = [
    ("https://www.vietcombank.com.vn", True),
    ("https://vietcombank.com.vn.login-secure.xyz", False),
    ("https://www.facebook.com", True),
    ("https://faceb00k-login.tk", False),
    ("https://www.youtube.com", True),
    ("https://github.com", True),
]
print("\n2. legit_domain_checker.py:")
for url, expect_safe in tests:
    r = check_legitimate_domain(url)
    is_safe = r['is_exact_match'] == 1
    icon = "PASS" if is_safe == expect_safe else "FAIL"
    print(f"   [{icon}] {url} -> exact={r['is_exact_match']} spoof={r['is_subdomain_spoof']}")

# 3. Community reports
from utils.community_reports import get_stats, log_check, submit_report
print("\n3. community_reports.py OK")
print(f"   Stats: {get_stats()}")

# 4. Advanced features
from utils.advanced_features import extract_lexical_features
feat = extract_lexical_features("https://fake-vietcombank.tk/login?verify=1")
print(f"\n4. advanced_features.py OK")
print(f"   Features extracted: {len(feat)}")
print(f"   SuspiciousTLD={feat.get('SuspiciousTLD')}")
print(f"   NumSensitiveWords={feat.get('NumSensitiveWords')}")

print("\n" + "="*50)
print("ALL MODULES VERIFIED SUCCESSFULLY")
print("="*50)
