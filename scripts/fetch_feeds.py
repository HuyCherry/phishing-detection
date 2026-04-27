import os
import zipfile
import requests
import pandas as pd
from io import BytesIO
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

def fetch_openphish():
    print("Fetching OpenPhish feed...")
    url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        urls = response.text.strip().split('\n')
        # Filter empty lines
        urls = [u for u in urls if u]
        df = pd.DataFrame({'url': urls})
        df['label'] = 1
        df['source'] = 'openphish'
        df['fetched_at'] = pd.Timestamp.now()
        out_path = DATA_DIR / "openphish_feed.csv"
        df.to_csv(out_path, index=False)
        print(f" -> Saved {len(df)} URLs to openphish_feed.csv")
        return len(df)
    except Exception as e:
        print(f" -> Error fetching OpenPhish: {e}")
        return 0

def fetch_phishtank():
    print("Fetching PhishTank feed...")
    url = "http://data.phishtank.com/data/online-valid.csv"
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        df = pd.read_csv(BytesIO(response.content))
        df = df[['url']].copy()
        df['label'] = 1
        df['source'] = 'phishtank'
        df['fetched_at'] = pd.Timestamp.now()
        out_path = DATA_DIR / "phishtank_feed.csv"
        df.to_csv(out_path, index=False)
        print(f" -> Saved {len(df)} URLs to phishtank_feed.csv")
        return len(df)
    except Exception as e:
        print(f" -> Error fetching PhishTank: {e}")
        return 0

def fetch_tranco():
    print("Fetching Tranco top-1m feed...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                df = pd.read_csv(f, header=None, names=['rank', 'domain'], nrows=5000)
                df['url'] = 'http://' + df['domain']
                df = df[['url']].copy()
                df['label'] = 0
                df['source'] = 'tranco'
                df['fetched_at'] = pd.Timestamp.now()
                out_path = DATA_DIR / "tranco_benign.csv"
                df.to_csv(out_path, index=False)
                print(f" -> Saved {len(df)} domains to tranco_benign.csv")
                return len(df)
    except Exception as e:
        print(f" -> Error fetching Tranco: {e}")
        return 0

if __name__ == "__main__":
    print("=== STARTING FEED FETCH ===")
    phishing_count = 0
    phishing_count += fetch_openphish()
    phishing_count += fetch_phishtank()
    
    benign_count = fetch_tranco()
    
    print("\n=== SUMMARY ===")
    print(f"Total Phishing URLs: {phishing_count}")
    print(f"Total Benign URLs  : {benign_count}")
    print("Done.")
