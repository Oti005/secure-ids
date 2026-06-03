import sqlite3
import os

#DATABASE = 'ids_database.db'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'ids_database.db')

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_id TEXT,
            prediction TEXT,
            confidence REAL,
            day TEXT,
            source_ip TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create blocked IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            reason TEXT,
            confidence REAL,
            day TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create default admin user
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ('admin', 'admin123')
        )
        print("[INFO] Default admin user created — username: admin, password: admin123")

    conn.commit()
    conn.close()
    print("[INFO] Database initialized successfully..")

def log_prediction(traffic_id, prediction, confidence, day='Unknown', source_ip='N/A'):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (traffic_id, prediction, confidence, day, source_ip) VALUES (?, ?, ?, ?, ?)",
        (traffic_id, prediction, confidence, day, source_ip)
    )
    # Auto block IP if attack detected with high confidence
    if prediction == 'ATTACK' and confidence >= 90:
        cursor.execute("SELECT * FROM blocked_ips WHERE source_ip = ?", (source_ip,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO blocked_ips (source_ip, reason, confidence, day) VALUES (?, ?, ?, ?)",
                (source_ip, 'Auto-blocked: High confidence attack detected', confidence, day)
            )
    conn.commit()
    conn.close()

def get_logs(limit=1000, day=None):
    conn = get_db()
    cursor = conn.cursor()
    if day and day.upper() != 'ALL':
        cursor.execute(
            "SELECT * FROM logs WHERE day = ? ORDER BY timestamp DESC LIMIT ?",
            (day, limit)
        )
    else:
        cursor.execute(
            "SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
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
    return {
        'total_analyzed': total,
        'attacks_detected': attacks,
        'normal_traffic': normal
    }

def get_blocked_ips():
    conn = get_db()
    cursor = conn.cursor()
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

def clear_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    print("[INFO] Logs cleared successfully")