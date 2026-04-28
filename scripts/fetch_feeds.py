"""
fetch_feeds.py — Tải dữ liệu phishing/benign từ các nguồn mở.
"""
import sys
import zipfile
import requests
import pandas as pd
from io import BytesIO
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from config import DATA_DIR


def fetch_openphish():
    print("[1/3] Fetching OpenPhish feed...")
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=30)
        resp.raise_for_status()
        urls = [u.strip() for u in resp.text.strip().split('\n') if u.strip()]
        df = pd.DataFrame({
            'url': urls, 'label': 1,
            'source': 'openphish', 'fetched_at': str(pd.Timestamp.now()),
        })
        df.to_csv(DATA_DIR / "openphish_feed.csv", index=False)
        print(f"      -> Saved {len(df)} phishing URLs")
        return len(df)
    except Exception as e:
        print(f"      -> ERROR: {e}")
        return 0


def fetch_phishtank():
    print("[2/3] Fetching PhishTank feed...")
    try:
        headers = {'User-Agent': 'phishing-detector/1.0'}
        resp = requests.get(
            "http://data.phishtank.com/data/online-valid.csv",
            headers=headers, timeout=30,
        )
        resp.raise_for_status()
        df_raw = pd.read_csv(BytesIO(resp.content))
        df = df_raw[['url']].copy()
        df['label'] = 1
        df['source'] = 'phishtank'
        df['fetched_at'] = str(pd.Timestamp.now())
        df.to_csv(DATA_DIR / "phishtank_feed.csv", index=False)
        print(f"      -> Saved {len(df)} phishing URLs")
        return len(df)
    except Exception as e:
        print(f"      -> ERROR: {e}")
        return 0


def fetch_tranco(limit=5000):
    print("[3/3] Fetching Tranco top-1m (benign)...")
    try:
        resp = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=30)
        resp.raise_for_status()
        with zipfile.ZipFile(BytesIO(resp.content)) as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as f:
                df_raw = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=limit)
        df = pd.DataFrame({
            'url': 'https://' + df_raw['domain'], 'label': 0,
            'source': 'tranco', 'fetched_at': str(pd.Timestamp.now()),
        })
        df.to_csv(DATA_DIR / "tranco_benign.csv", index=False)
        print(f"      -> Saved {len(df)} benign domains")
        return len(df)
    except Exception as e:
        print(f"      -> ERROR: {e}")
        return 0


if __name__ == "__main__":
    print("=" * 50)
    print("FEED FETCH - START")
    print("=" * 50)
    phishing = fetch_openphish() + fetch_phishtank()
    benign = fetch_tranco()
    print("\n" + "=" * 50)
    print(f"SUMMARY: {phishing} phishing + {benign} benign")
    print("=" * 50)
