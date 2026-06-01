import requests
import pandas as pd
import numpy as np

# Login first
session = requests.Session()
login_response = session.post('http://127.0.0.1:5000/api/login', json={
    'username': 'admin',
    'password': 'admin123'
})
print(f"Login: {login_response.json()}")

# Load normal traffic from Monday
print("[INFO] Loading normal traffic...")
monday = pd.read_csv('dataset/Monday-WorkingHours.pcap_ISCX.csv', nrows=50)
monday.columns = monday.columns.str.strip()
monday = monday.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], errors='ignore')

# Load attack traffic from Wednesday
print("[INFO] Loading attack traffic...")
wednesday = pd.read_csv('dataset/Wednesday-workingHours.pcap_ISCX.csv', skiprows=range(1, 100000), nrows=50)
wednesday.columns = wednesday.columns.str.strip()
wednesday = wednesday.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], errors='ignore')

# Combine and shuffle
df = pd.concat([monday, wednesday], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df = df.reset_index(drop=True)

print(f"[INFO] Total records: {len(df)} — sending 20 mixed records...")

# Send 20 mixed records
for i in range(20):
    record = df.iloc[i].to_dict()
    record = {k: float(v) if isinstance(v, (np.floating, np.integer)) else v
              for k, v in record.items()}

    response = session.post(
        'http://127.0.0.1:5000/api/analyze',
        json={'features': record, 'traffic_id': f'record_{i+1}'},
        headers={'X-User': 'admin'}
    )
    print(f"Record {i+1}: {response.json()}")