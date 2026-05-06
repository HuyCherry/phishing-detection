"""
config.py — Centralized configuration cho hệ thống phát hiện URL phishing.
Load từ .env bằng python-dotenv.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# ─── Base paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
DB_PATH = DATA_DIR / "history.db"
REPORTS_DB_PATH = DATA_DIR / "reports.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ─── Load .env ───────────────────────────────────────────────────────────────
load_dotenv(BASE_DIR / ".env")

# ─── API Keys ────────────────────────────────────────────────────────────────
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

# ─── Thresholds ──────────────────────────────────────────────────────────────
RISK_DANGEROUS = 70
RISK_SUSPICIOUS = 40
DOMAIN_NEW_DAYS = 90
URL_ENTROPY_THRESHOLD = 4.2

# ─── Sensitive Words (VN + quốc tế) ─────────────────────────────────────────
SENSITIVE_WORDS = [
    'login', 'bank', 'secure', 'verify', 'update', 'account', 'signin',
    'password', 'confirm', 'paypal', 'wallet', 'free', 'lucky', 'prize',
    'winner', 'urgent', 'alert', 'suspend', 'action', 'click',
    'authorize', 'validate', 'activate', 'unlock', 'expire',
    'nganhang', 'taikhoan', 'xacnhan', 'capnhat', 'dangnhap', 'matkhau',
    'vietcombank', 'techcombank', 'mbbank', 'tpbank', 'vpbank', 'agribank',
    'momo', 'zalopay', 'vnpay', 'shopee', 'lazada', 'tiki',
]

# ─── Suspicious TLDs ────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.click', '.download', '.work', '.party', '.loan',
    '.win', '.bid', '.stream', '.racing', '.date',
    '.zip', '.pw', '.ninja', '.space', '.cyou', '.cc', '.ws',
]

# ─── Top Brands (homograph detection) ───────────────────────────────────────
TOP_BRANDS = [
    'google', 'facebook', 'youtube', 'instagram', 'tiktok', 'twitter',
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix',
    'linkedin', 'github', 'whatsapp', 'telegram', 'discord',
    'vietcombank', 'techcombank', 'mbbank', 'tpbank', 'vpbank', 'agribank',
    'bidv', 'vietinbank', 'acb', 'sacombank',
    'shopee', 'lazada', 'tiki', 'momo', 'zalopay',
]

# ─── Trusted CAs ────────────────────────────────────────────────────────────
TRUSTED_CAS = [
    'digicert', 'comodo', 'globalsign', 'entrust', 'godaddy',
    'sectigo', 'thawte', 'geotrust', 'rapidssl', 'symantec',
    'buypass', 'certum', 'ssl.com', 'usertrust', 'google',
    'amazon', 'apple', 'microsoft', 'cloudflare',
]

# ─── Official Domains — VN Banks ────────────────────────────────────────────
VN_OFFICIAL_BANKS = [
    'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn',
    'tpbank.vn', 'vpbank.com.vn', 'agribank.com.vn',
    'bidv.com.vn', 'vietinbank.vn', 'acb.com.vn', 'sacombank.com',
    'msb.com.vn', 'hdbank.com.vn', 'lpbank.com.vn',
    'ocb.com.vn', 'eximbank.com.vn', 'seabank.com.vn',
    'vib.com.vn', 'shb.com.vn', 'namabank.com.vn',
]

# ─── Official Domains — VN Government ───────────────────────────────────────
VN_OFFICIAL_GOV = [
    'gov.vn', 'mof.gov.vn', 'moit.gov.vn', 'mic.gov.vn',
    'gdt.gov.vn', 'customs.gov.vn', 'most.gov.vn',
    'chinhphu.vn', 'dichvucong.gov.vn', 'ncsc.gov.vn',
]

# ─── Official Domains — Social Media & Big Tech ─────────────────────────────
SOCIAL_MEDIA_OFFICIAL = [
    # Social media
    'facebook.com', 'instagram.com', 'youtube.com', 'tiktok.com',
    'twitter.com', 'x.com', 'linkedin.com', 'zalo.me',
    'reddit.com', 'pinterest.com', 'tumblr.com', 'snapchat.com',
    'threads.net', 'mastodon.social',
    # Big Tech
    'google.com', 'gmail.com', 'github.com', 'gitlab.com',
    'apple.com', 'microsoft.com', 'amazon.com', 'aws.amazon.com',
    'paypal.com', 'netflix.com', 'whatsapp.com',
    # Major sites
    'wikipedia.org', 'wikimedia.org', 'stackoverflow.com',
    'medium.com', 'notion.so', 'figma.com', 'canva.com',
    'spotify.com', 'twitch.tv', 'zoom.us',
    'dropbox.com', 'slack.com', 'trello.com',
    'cloudflare.com', 'vercel.app', 'netlify.com',
    'openai.com', 'chatgpt.com',
    # Vietnamese popular
    'vnexpress.net', 'tuoitre.vn', 'thanhnien.vn',
    'dantri.com.vn', 'kenh14.vn', 'tinhte.vn',
    'fpt.com.vn', 'viettel.vn', 'vnpt.vn',
    'sendo.vn', 'thegioididong.com', 'dienmayxanh.com',
    'cellphones.com.vn', 'phongvu.vn',
]

# ─── Combined whitelist ─────────────────────────────────────────────────────
ALL_OFFICIAL_DOMAINS = VN_OFFICIAL_BANKS + VN_OFFICIAL_GOV + SOCIAL_MEDIA_OFFICIAL

# ─── Risk Score Weights ─────────────────────────────────────────────────────
WEIGHT_VT_MALICIOUS = 30
WEIGHT_GSB_DANGEROUS = 25
WEIGHT_URLHAUS_MALICIOUS = 20
WEIGHT_LOOKALIKE = 15
WEIGHT_DOMAIN_NEW = 10
WEIGHT_SSL_INVALID = 10
WEIGHT_SUBDOMAIN_SPOOF = 20

# ─── Community Reports ──────────────────────────────────────────────────────
REPORT_TYPES = ['phishing', 'scam', 'malware', 'false_positive']
