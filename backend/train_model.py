import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder
import pickle
import os
import json

print("[INFO] Loading all datasets...")

dataset_files = [
    'dataset/Monday-WorkingHours.pcap_ISCX.csv',
    'dataset/Tuesday-WorkingHours.pcap_ISCX.csv',
    'dataset/Wednesday-workingHours.pcap_ISCX.csv',
    'dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'dataset/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
]

dfs = []
for file in dataset_files:
    try:
        df_temp = pd.read_csv(file)
        print(f"  Loaded {file}: {len(df_temp)} rows")
        dfs.append(df_temp)
    except Exception as e:
        print(f"  [SKIP] {file}: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"[INFO] Total records loaded: {len(df)}")

df.columns = df.columns.str.strip()

print("[INFO] Label distribution:")
print(df['Label'].value_counts())

df['Label'] = df['Label'].apply(lambda x: 'NORMAL' if str(x).strip() == 'BENIGN' else 'ATTACK')

# Droping non-feature columns including Destination Port (stored separately)
df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Destination Port'], errors='ignore')

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

le = LabelEncoder()
df['Label'] = le.fit_transform(df['Label'])

X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
print(f"[INFO] Training samples: {len(X_train)} | Test samples: {len(X_test)}")

print("[INFO] Training Random Forest model (this may take several minutes)...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("[INFO] Training complete!")

y_pred = model.predict(X_test)
print("\n[RESULTS]")
print(f"Accuracy  : {accuracy_score(y_test, y_pred) * 100:.2f}%")
print(f"Precision : {precision_score(y_test, y_pred) * 100:.2f}%")
print(f"Recall    : {recall_score(y_test, y_pred) * 100:.2f}%")
print(f"F1 Score  : {f1_score(y_test, y_pred) * 100:.2f}%")
print("\n[CLASSIFICATION REPORT]")
print(classification_report(y_test, y_pred, target_names=le.classes_))

os.makedirs("model", exist_ok=True)
with open("model/ids_model.pkl", "wb") as f:
    pickle.dump(model, f)
with open("model/label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)
with open("model/feature_columns.json", "w") as f:
    json.dump(list(X_train.columns), f)

print("\n[INFO] Model saved. Run test_detection.py to populate the database.")