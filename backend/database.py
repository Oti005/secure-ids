import sqlite3
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'ids_database.db')
ADMIN_CONFIG = os.path.join(BASE_DIR, 'admin_config.json')

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        traffic_id TEXT,
        prediction TEXT,
        confidence REAL,
        day TEXT,
        source_ip TEXT,
        attack_type TEXT DEFAULT 'Unknown',
        destination_port TEXT DEFAULT 'N/A',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        reason TEXT,
        confidence REAL,
        day TEXT,
        attack_type TEXT DEFAULT 'Unknown',
        destination_port TEXT DEFAULT 'N/A',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Migrations
    for col in [
        ("logs", "attack_type", "TEXT DEFAULT 'Unknown'"),
        ("logs", "destination_port", "TEXT DEFAULT 'N/A'"),
        ("blocked_ips", "attack_type", "TEXT DEFAULT 'Unknown'"),
        ("blocked_ips", "destination_port", "TEXT DEFAULT 'N/A'"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE {col[0]} ADD COLUMN {col[1]} {col[2]}")
        except: pass

    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
        print("[INFO] Default admin user created")

    conn.commit()
    conn.close()

    # Create admin_config.json if it doesn't exist
    if not os.path.exists(ADMIN_CONFIG):
        with open(ADMIN_CONFIG, 'w') as f:
            json.dump({"username": "admin", "password": "admin123"}, f)

    print("[INFO] Database initialized successfully..")

def log_prediction(traffic_id, prediction, confidence, day='Unknown', source_ip='N/A', attack_type='Unknown', destination_port='N/A'):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (traffic_id, prediction, confidence, day, source_ip, attack_type, destination_port) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (traffic_id, prediction, confidence, day, source_ip, attack_type, destination_port)
    )
    if prediction == 'ATTACK' and confidence >= 90:
        cursor.execute("SELECT * FROM blocked_ips WHERE source_ip = ?", (source_ip,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO blocked_ips (source_ip, reason, confidence, day, attack_type, destination_port) VALUES (?, ?, ?, ?, ?, ?)",
                (source_ip, f'Auto-blocked: {attack_type} attack detected', confidence, day, attack_type, destination_port)
            )
    conn.commit()
    conn.close()

def get_logs(limit=1000, day=None):
    conn = get_db()
    cursor = conn.cursor()
    if day and day.upper() != 'ALL':
        cursor.execute("SELECT * FROM logs WHERE day = ? ORDER BY timestamp DESC LIMIT ?", (day, limit))
    else:
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

def get_stats(day=None):
    conn = get_db()
    cursor = conn.cursor()
    if day and day.upper() != 'ALL':
        cursor.execute("SELECT COUNT(*) as total FROM logs WHERE day = ?", (day,))
        total = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as attacks FROM logs WHERE prediction = 'ATTACK' AND day = ?", (day,))
        attacks = cursor.fetchone()['attacks']
        cursor.execute("SELECT COUNT(*) as normal FROM logs WHERE prediction = 'NORMAL' AND day = ?", (day,))
        normal = cursor.fetchone()['normal']
    else:
        cursor.execute("SELECT COUNT(*) as total FROM logs")
        total = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as attacks FROM logs WHERE prediction = 'ATTACK'")
        attacks = cursor.fetchone()['attacks']
        cursor.execute("SELECT COUNT(*) as normal FROM logs WHERE prediction = 'NORMAL'")
        normal = cursor.fetchone()['normal']
    conn.close()
    return {'total_analyzed': total, 'attacks_detected': attacks, 'normal_traffic': normal}

def get_blocked_ips(day=None):
    conn = get_db()
    cursor = conn.cursor()
    if day and day.upper() != 'ALL':
        cursor.execute("SELECT * FROM blocked_ips WHERE day = ? ORDER BY timestamp DESC", (day,))
    else:
        cursor.execute("SELECT * FROM blocked_ips ORDER BY timestamp DESC")
    ips = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return ips

def get_days():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT day FROM logs ORDER BY day")
    days = [row['day'] for row in cursor.fetchall()]
    conn.close()
    return days

def delete_log(log_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()

def update_password(username, new_password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()
    # Sync to admin_config.json so test_detection.py picks it up
    try:
        with open(ADMIN_CONFIG, 'w') as f:
            json.dump({"username": username, "password": new_password}, f)
    except: pass

def clear_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    print("[INFO] Logs cleared")