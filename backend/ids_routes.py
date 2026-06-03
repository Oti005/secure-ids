import pickle
import numpy as np
import pandas as pd
import os
import json
from flask import Blueprint, request, jsonify, session
from database import (
    log_prediction, get_logs, get_stats,
    get_blocked_ips, get_days, clear_logs
)

ids_bp = Blueprint('ids', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load model
with open(os.path.join(BASE_DIR, 'model', 'ids_model.pkl'), 'rb') as f:
    model = pickle.load(f)

with open(os.path.join(BASE_DIR, 'model', 'label_encoder.pkl'), 'rb') as f:
    le = pickle.load(f)

with open(os.path.join(BASE_DIR, 'model', 'feature_columns.json'), 'r') as f:
    feature_columns = json.load(f)

print("[INFO] ML model loaded successfully")


# SINGLE AUTH SYSTEM ONLY
def is_authenticated():
    return 'user' in session


def get_severity(confidence):
    if confidence >= 90:
        return 'HIGH'
    elif confidence >= 70:
        return 'MEDIUM'
    return 'LOW'


# ---------------- ANALYZE ----------------
@ids_bp.route('/api/analyze', methods=['POST'])
def analyze():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    features = data.get('features')

    if not features:
        return jsonify({'success': False, 'message': 'No features provided'}), 400

    input_df = pd.DataFrame([features])
    input_df = input_df.reindex(columns=feature_columns, fill_value=0)

    prediction_encoded = model.predict(input_df)[0]
    confidence = round(max(model.predict_proba(input_df)[0]) * 100, 2)
    prediction = le.inverse_transform([prediction_encoded])[0]

    log_prediction(
        data.get('traffic_id', 'N/A'),
        prediction,
        confidence,
        data.get('day', 'Unknown'),
        data.get('source_ip', 'N/A')
    )

    return jsonify({
        'success': True,
        'prediction': prediction,
        'confidence': confidence,
        'severity': get_severity(confidence)
    }), 200


# ---------------- ALERTS ----------------
@ids_bp.route('/api/alerts', methods=['GET'])
def alerts():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    day = request.args.get('day', 'All')

    logs = get_logs(limit=1000, day=day)
    attacks = [l for l in logs if l['prediction'] == 'ATTACK']

    for a in attacks:
        a['severity'] = get_severity(a['confidence'])

    return jsonify({'success': True, 'alerts': attacks}), 200


# ---------------- LOGS ----------------
@ids_bp.route('/api/logs', methods=['GET'])
def logs():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    day = request.args.get('day', 'All')
    logs = get_logs(limit=1000, day=day)

    for l in logs:
        l['severity'] = get_severity(l['confidence'])

    return jsonify({'success': True, 'logs': logs}), 200


# ---------------- DASHBOARD ----------------
@ids_bp.route('/api/dashboard', methods=['GET'])
def dashboard():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    day = request.args.get('day', 'All')

    stats = get_stats(day=day)
    recent_logs = get_logs(limit=10, day=day)

    for r in recent_logs:
        r['severity'] = get_severity(r['confidence'])

    return jsonify({
        'success': True,
        'stats': stats,
        'recent_logs': recent_logs
    }), 200


# ---------------- BLOCKED IPS ----------------
@ids_bp.route('/api/blocked-ips', methods=['GET'])
def blocked_ips():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    return jsonify({'success': True, 'blocked_ips': get_blocked_ips()}), 200


# ---------------- DAYS ----------------
@ids_bp.route('/api/days', methods=['GET'])
def days():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    return jsonify({'success': True, 'days': get_days()}), 200


# ---------------- CLEAR LOGS ----------------
@ids_bp.route('/api/clear-logs', methods=['POST'])
def clear_logs_api():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    clear_logs()
    return jsonify({'success': True, 'message': 'Logs cleared'}), 200


@ids_bp.route('/api/stats-by-day', methods=['GET'])
def stats_by_day():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT day,
            SUM(CASE WHEN prediction = 'ATTACK' THEN 1 ELSE 0 END) as attacks,
            SUM(CASE WHEN prediction = 'NORMAL' THEN 1 ELSE 0 END) as normal
        FROM logs
        GROUP BY day
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': rows}), 200


@ids_bp.route('/api/blocked-ips/<int:ip_id>', methods=['DELETE'])
def delete_blocked_ip(ip_id):
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE id = ?", (ip_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'IP unblocked successfully'}), 200