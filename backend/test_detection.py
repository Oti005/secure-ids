import requests
import pandas as pd
import numpy as np
import random

# ── Login ──────────────────────────────────────────────────────
session = requests.Session()
login_response = session.post('http://127.0.0.1:5000/api/login', json={
    'username': 'admin',
    'password': 'admin123'
})
print(f"Login: {login_response.json()}")

# ── Clear existing logs ────────────────────────────────────────
clear_response = session.post(
    'http://127.0.0.1:5000/api/clear-logs',
    headers={'X-User': 'admin'}
)
print(f"Logs cleared: {clear_response.status_code}")

# ── Dataset files with day labels ─────────────────────────────
datasets = [
    {'file': 'dataset/Monday-WorkingHours.pcap_ISCX.csv', 'day': 'Monday', 'skip': 0},
    {'file': 'dataset/Tuesday-WorkingHours.pcap_ISCX.csv', 'day': 'Tuesday', 'skip': 50000},
    {'file': 'dataset/Wednesday-workingHours.pcap_ISCX.csv', 'day': 'Wednesday', 'skip': 100000},
    {'file': 'dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 'day': 'Thursday', 'skip': 10000},
    {'file': 'dataset/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 'day': 'Thursday', 'skip': 0},
    {'file': 'dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv', 'day': 'Friday', 'skip': 0},
    {'file': 'dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', 'day': 'Friday', 'skip': 50000},
]

# ── Simulated source IPs ───────────────────────────────────────
def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

# ── Process each dataset ───────────────────────────────────────
total_sent = 0

for dataset in datasets:
    print(f"\n[INFO] Loading {dataset['day']} — {dataset['file']}...")

    try:
        if dataset['skip'] > 0:
            df = pd.read_csv(dataset['file'], skiprows=range(1, dataset['skip']), nrows=50)
        else:
            df = pd.read_csv(dataset['file'], nrows=50)

        df.columns = df.columns.str.strip()
        df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], errors='ignore')
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        df = df.reset_index(drop=True)

        print(f"[INFO] Loaded {len(df)} records — sending {min(100, len(df))}...")

        sent = 0
        for i in range(min(50, len(df))):
            record = df.iloc[i].to_dict()
            record = {k: float(v) if isinstance(v, (np.floating, np.integer)) else v
                      for k, v in record.items()}

            response = session.post(
                'http://127.0.0.1:5000/api/analyze',
                json={
                    'features': record,
                    'traffic_id': f'{dataset["day"]}_record_{i+1}',
                    'day': dataset['day'],
                    'source_ip': random_ip()
                },
                headers={'X-User': 'admin'}
            )

            if response.status_code != 200:
                print(f"  ❌ Record {i+1}: Status {response.status_code} — {response.text}")
                continue

            result = response.json()
            sent += 1
            total_sent += 1

            if result.get('prediction') == 'ATTACK':
                print(f"  ⚠️  Record {i+1}: ATTACK — Confidence: {result.get('confidence')}% — IP: {result.get('source_ip')}")
            else:
                print(f"  ✅ Record {i+1}: NORMAL — Confidence: {result.get('confidence')}%")

        print(f"[INFO] {dataset['day']} complete — {sent} records sent")

    except Exception as e:
        print(f"[ERROR] {dataset['file']}: {e}")

print(f"\n[DONE] Total records sent: {total_sent}")