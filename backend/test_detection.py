import requests
import pandas as pd
import numpy as np
import random
import json
import os

BASE_URL = "http://localhost:5000"

# Read password from admin_config.json (syncs with UI password changes)
config_path = os.path.join(os.path.dirname(__file__), 'admin_config.json')
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
    USERNAME = config.get('username', 'admin')
    PASSWORD = config.get('password', 'admin123')
    print(f"[INFO] Using credentials from admin_config.json: {USERNAME}")
except:
    USERNAME, PASSWORD = 'admin', 'admin123'
    print("[INFO] Using default credentials")

session = requests.Session()
login_response = session.post(f"{BASE_URL}/api/login", json={'username': USERNAME, 'password': PASSWORD})
print(f"Login: {login_response.json()}")

clear_response = session.post(f"{BASE_URL}/api/clear-logs")
print(f"Logs cleared: {clear_response.status_code}")

datasets = [
    {'file': 'dataset/Monday-WorkingHours.pcap_ISCX.csv', 'day': 'Monday', 'skip': 0},
    {'file': 'dataset/Tuesday-WorkingHours.pcap_ISCX.csv', 'day': 'Tuesday', 'skip': 50000},
    {'file': 'dataset/Wednesday-workingHours.pcap_ISCX.csv', 'day': 'Wednesday', 'skip': 100000},
    {'file': 'dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', 'day': 'Thursday', 'skip': 10000},
    {'file': 'dataset/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv', 'day': 'Thursday', 'skip': 0},
    {'file': 'dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv', 'day': 'Friday', 'skip': 0},
    {'file': 'dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', 'day': 'Friday', 'skip': 50000},
]

ATTACK_TYPE_MAP = {
    'BENIGN': 'Normal', 'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS',
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 'Heartbleed': 'Heartbleed',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force',
    'Web Attack \xe2\x80\x93 Brute Force': 'Web Attack',
    'Web Attack – Brute Force': 'Web Attack',
    'Web Attack \xe2\x80\x93 XSS': 'Web Attack',
    'Web Attack – XSS': 'Web Attack',
    'Web Attack \xe2\x80\x93 Sql Injection': 'Web Attack',
    'Web Attack – Sql Injection': 'Web Attack',
    'Infiltration': 'Infiltration', 'Bot': 'Bot',
    'PortScan': 'Port Scan', 'DDoS': 'DDoS'
}

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"

total_sent = 0

for dataset in datasets:
    print(f"\n[INFO] Loading {dataset['day']} — {dataset['file']}...")
    try:
        if dataset['skip'] > 0:
            df = pd.read_csv(dataset['file'], skiprows=range(1, dataset['skip']), nrows=50)
        else:
            df = pd.read_csv(dataset['file'], nrows=50)

        df.columns = df.columns.str.strip()

        labels = df['Label'].str.strip() if 'Label' in df.columns else None
        dest_ports = df['Destination Port'] if 'Destination Port' in df.columns else None

        df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'Destination Port'], errors='ignore')
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        df = df.reset_index(drop=True)

        if labels is not None: labels = labels.reset_index(drop=True)
        if dest_ports is not None: dest_ports = dest_ports.reset_index(drop=True)

        print(f"[INFO] Loaded {len(df)} records — sending {min(50, len(df))}...")

        sent = 0
        for i in range(min(50, len(df))):
            record = df.iloc[i].to_dict()
            record = {k: float(v) if isinstance(v, (np.floating, np.integer)) else v for k, v in record.items()}

            raw_label = labels.iloc[i] if labels is not None else 'Unknown'
            attack_type = ATTACK_TYPE_MAP.get(raw_label, raw_label)
            dest_port = str(int(dest_ports.iloc[i])) if dest_ports is not None else 'N/A'

            response = session.post(
                f"{BASE_URL}/api/analyze",
                json={
                    'features': record,
                    'traffic_id': f'{dataset["day"]}_record_{i+1}',
                    'day': dataset['day'],
                    'source_ip': random_ip(),
                    'attack_type': attack_type,
                    'destination_port': dest_port
                }
            )

            if response.status_code != 200:
                print(f"   Record {i+1}: {response.status_code} — {response.text[:100]}")
                continue

            result = response.json()
            sent += 1
            total_sent += 1

            if result.get('prediction') == 'ATTACK':
                print(f"    {i+1}: {result.get('attack_type')} — {result.get('confidence')}% — Port: {dest_port}")
            else:
                print(f"   {i+1}: NORMAL — {result.get('confidence')}%")

        print(f"[INFO] {dataset['day']} complete — {sent} records sent")
    except Exception as e:
        print(f"[ERROR] {dataset['file']}: {e}")

print(f"\n[DONE] Total records sent: {total_sent}")