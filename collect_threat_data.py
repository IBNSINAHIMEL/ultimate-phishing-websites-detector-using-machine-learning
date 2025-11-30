"""
collect_threat_data.py
----------------------
Improved dataset collection and balancing for phishing website detection.
Generates a balanced dataset suitable for ML + CNN ensemble training.

Author: IbnSina (AI-Based Phishing & Scam Detection Thesis)
"""

import os
import pandas as pd
import requests
import random
from datetime import datetime
from sklearn.utils import resample

# ==============================
# CONFIGURATION
# ==============================

# ✅ Your data directory
DATA_DIR = r"C:\Users\ibnsi\Downloads\Real-Time-Detection-of-Phishing-Scam-Fraudulent-and-Legitimate-Websites-Using-Machine-Learning-main\PhishingDetector\data"

PHISHING_FILE = os.path.join(DATA_DIR, "phishing_urls.csv")
LEGIT_FILE = os.path.join(DATA_DIR, "legitimate_urls.csv")
FINAL_DATASET = os.path.join(DATA_DIR, "balanced_dataset.csv")

PHISHING_SOURCES = [
    "https://openphish.com/feed.txt",
    "https://phishunt.io/feed.txt",
    "https://phishstats.info/phish_score.csv",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
]

TRANCO_LIST = "https://tranco-list.eu/top-1m.csv.zip"
MAJESTIC_LIST = "https://downloads.majestic.com/majestic_million.csv"

TARGET_PHISH_COUNT = 50000
TARGET_LEGIT_COUNT = 50000

os.makedirs(DATA_DIR, exist_ok=True)


# ==============================
# 1️⃣ Collect Phishing URLs
# ==============================
def collect_phishing_urls():
    print("🔍 Collecting phishing URLs...")
    phishing_urls = set()

    for source in PHISHING_SOURCES:
        try:
            r = requests.get(source, timeout=15)
            if r.status_code == 200:
                lines = r.text.splitlines()
                for line in lines:
                    if "http" in line:
                        phishing_urls.add(line.strip())
        except Exception as e:
            print(f"⚠️ Failed {source}: {e}")

    phishing_list = list(phishing_urls)
    random.shuffle(phishing_list)
    phishing_list = phishing_list[:TARGET_PHISH_COUNT]

    df = pd.DataFrame(phishing_list, columns=["url"])
    df["label"] = 1  # 1 = phishing
    print(f"✅ Collected {len(df)} phishing URLs")
    return df


# ==============================
# 2️⃣ Collect Legitimate URLs
# ==============================
def collect_legitimate_urls():
    print("🌐 Collecting legitimate URLs...")
    legit_urls = set()

    # Try Tranco list
    try:
        df_tranco = pd.read_csv(TRANCO_LIST)
        legit_urls.update("https://" + df_tranco.iloc[:, 1].astype(str))
    except Exception as e:
        print(f"⚠️ Tranco list failed: {e}")

    # Try Majestic Million as backup
    if len(legit_urls) < TARGET_LEGIT_COUNT:
        try:
            df_maj = pd.read_csv(MAJESTIC_LIST)
            legit_urls.update("https://" + df_maj["Domain"].astype(str))
        except Exception as e:
            print(f"⚠️ Majestic list failed: {e}")

    legit_list = list(legit_urls)
    random.shuffle(legit_list)
    legit_list = legit_list[:TARGET_LEGIT_COUNT]

    df = pd.DataFrame(legit_list, columns=["url"])
    df["label"] = 0  # 0 = legitimate
    print(f"✅ Collected {len(df)} legitimate URLs")
    return df


# ==============================
# 3️⃣ Merge and Balance Dataset
# ==============================
def balance_dataset(phish_df, legit_df):
    print("⚖️ Balancing dataset...")

    phish_n = len(phish_df)
    legit_n = len(legit_df)
    min_n = min(phish_n, legit_n)

    if phish_n > min_n:
        phish_df = resample(phish_df, replace=False, n_samples=min_n, random_state=42)
    elif legit_n > min_n:
        legit_df = resample(legit_df, replace=False, n_samples=min_n, random_state=42)

    balanced = pd.concat([phish_df, legit_df]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"✅ Balanced dataset: {len(balanced)} samples ({min_n} per class)")
    return balanced


# ==============================
# 4️⃣ Main Execution
# ==============================
if __name__ == "__main__":
    print("🚀 Starting Threat Data Collection at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    phish_df = collect_phishing_urls()
    legit_df = collect_legitimate_urls()

    df_balanced = balance_dataset(phish_df, legit_df)

    df_balanced.drop_duplicates(subset=["url"], inplace=True)
    df_balanced.to_csv(FINAL_DATASET, index=False)

    print("\n🎯 Final Dataset Summary:")
    print(df_balanced["label"].value_counts())
    print(f"📁 Saved balanced dataset to: {FINAL_DATASET}")
