"""
build_dataset.py — Load feeds, dedup, extract lexical features, save dataset.
"""
import sys
import json
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from config import DATA_DIR
from utils.advanced_features import extract_lexical_features


if __name__ == "__main__":
    print("=" * 50)
    print("BUILD DATASET - START")
    print("=" * 50)

    dfs = []
    for fname in ["openphish_feed.csv", "phishtank_feed.csv", "tranco_benign.csv"]:
        fpath = DATA_DIR / fname
        if fpath.exists():
            print(f"  Loading {fname}...")
            dfs.append(pd.read_csv(fpath))
        else:
            print(f"  WARNING: {fname} not found, skipping.")

    if not dfs:
        print("ERROR: No feed files found. Run fetch_feeds.py first.")
        sys.exit(1)

    df = pd.concat(dfs, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates(subset=['url'], keep='first')
    df = df.dropna(subset=['url'])
    after = len(df)
    print(f"  Deduplicated: {before} -> {after} URLs")

    print("  Extracting lexical features...")
    feat_list = []
    for i, url in enumerate(df['url']):
        feat_list.append(extract_lexical_features(str(url)))
        if (i + 1) % 1000 == 0:
            print(f"    Processed {i+1}/{after} URLs...")

    feat_df = pd.DataFrame(feat_list)
    final = feat_df.copy()
    final['CLASS_LABEL'] = df['label'].values

    out_path = DATA_DIR / "dataset_from_feeds.csv"
    final.to_csv(out_path, index=False)
    print(f"  Saved {len(final)} rows x {len(final.columns)} cols to {out_path.name}")

    log = {
        "built_at": str(pd.Timestamp.now()),
        "total": len(final),
        "phishing": int((final['CLASS_LABEL'] == 1).sum()),
        "benign": int((final['CLASS_LABEL'] == 0).sum()),
        "features": list(feat_df.columns),
    }
    with open(DATA_DIR / "dataset_log.json", "w") as f:
        json.dump(log, f, indent=4)

    print("=" * 50)
    print("BUILD DATASET - COMPLETE")
    print("=" * 50)
