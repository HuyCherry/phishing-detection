import os
import re
import json
import math
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

SENSITIVE_WORDS = ['login', 'bank', 'secure', 'verify', 'update', 'account', 'signin', 'password', 'confirm', 'paypal', 'wallet', 'free', 'lucky', 'prize', 'winner', 'urgent', 'alert', 'suspend']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.work', '.party']

def url_entropy(url):
    if not url: return 0
    return -sum((url.count(c)/len(url)) * math.log2(url.count(c)/len(url)) for c in set(url) if url.count(c) > 0)

def extract_features(url):
    features = {}
    try:
        url_lower = url.lower()
        if '//' in url:
            parts = url.split('//')[1].split('/')
            domain = parts[0]
            path = '/'.join(parts[1:]) if len(parts) > 1 else ""
        else:
            domain = url
            path = ""

        query = url.split('?')[1] if '?' in url else ""

        features['UrlLength'] = len(url)
        features['NumDots'] = url.count('.')
        features['NumDash'] = url.count('-')
        features['NumDashInHostname'] = domain.count('-')
        features['AtSymbol'] = 1 if '@' in url else 0
        features['TildeSymbol'] = 1 if '~' in url else 0
        features['NumUnderscore'] = url.count('_')
        features['NumPercent'] = url.count('%')
        features['NumAmpersand'] = url.count('&')
        features['NumHash'] = url.count('#')
        features['NumNumericChars'] = sum(c.isdigit() for c in url)
        features['NoHttps'] = 0 if url_lower.startswith('https') else 1
        features['IpAddress'] = 1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0
        features['SubdomainLevel'] = domain.count('.')
        features['HostnameLength'] = len(domain)
        features['PathLength'] = len(path)
        features['QueryLength'] = len(query)
        features['DoubleSlashInPath'] = 1 if '//' in path else 0
        features['NumSensitiveWords'] = sum(1 for w in SENSITIVE_WORDS if w in url_lower)
        features['NumQueryComponents'] = query.count('&') + 1 if query else 0
        features['DomainInPaths'] = 1 if re.search(r'[a-z0-9-]+\.[a-z]{2,}', path) else 0
        features['HttpsInHostname'] = 1 if 'https' in domain else 0
        features['SuspiciousTLD'] = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
        features['UrlEntropy'] = url_entropy(url)
        features['RandomString'] = 1 if features['UrlEntropy'] > 4.2 else 0
    except Exception:
        for k in ['UrlLength', 'NumDots', 'NumDash', 'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 
                  'NumUnderscore', 'NumPercent', 'NumAmpersand', 'NumHash', 'NumNumericChars', 
                  'NoHttps', 'IpAddress', 'SubdomainLevel', 'HostnameLength', 'PathLength', 
                  'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords', 'NumQueryComponents', 
                  'DomainInPaths', 'HttpsInHostname', 'SuspiciousTLD', 'RandomString', 'UrlEntropy']:
            features[k] = 0
            
    return features

if __name__ == "__main__":
    print("=== STARTING DATASET BUILD ===")
    dfs = []
    
    for f in ["openphish_feed.csv", "phishtank_feed.csv", "tranco_benign.csv"]:
        file_path = DATA_DIR / f
        if file_path.exists():
            print(f"Loading {f}...")
            dfs.append(pd.read_csv(file_path))
        else:
            print(f"Warning: {f} not found, skipping.")
            
    if not dfs:
        print("No feed files found. Run fetch_feeds.py first.")
        exit(1)
        
    df = pd.concat(dfs, ignore_index=True)
    initial_len = len(df)
    df = df.drop_duplicates(subset=['url'], keep='first')
    dedup_len = len(df)
    print(f"Deduplicated from {initial_len} to {dedup_len} URLs")
    
    print("Extracting features from URLs...")
    features_list = df['url'].apply(lambda x: extract_features(str(x)))
    features_df = pd.DataFrame(features_list.tolist())
    
    final_df = features_df.copy()
    final_df['CLASS_LABEL'] = df['label'].values
    
    out_path = DATA_DIR / "dataset_from_feeds.csv"
    final_df.to_csv(out_path, index=False)
    print(f"Saved dataset with {len(final_df)} rows and {len(final_df.columns)} columns to {out_path.name}")
    
    log_data = {
        "built_at": str(pd.Timestamp.now()),
        "total": len(final_df),
        "phishing": int(sum(final_df['CLASS_LABEL'] == 1)),
        "benign": int(sum(final_df['CLASS_LABEL'] == 0)),
        "features": list(features_df.columns)
    }
    
    with open(DATA_DIR / "dataset_log.json", "w") as f:
        json.dump(log_data, f, indent=4)
        
    print("=== DATASET BUILD COMPLETE ===")
