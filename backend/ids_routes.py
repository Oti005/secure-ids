import pickle
import numpy as np
import pandas as pd
import os
import json
from flask import Blueprint, request, jsonify, session
from database import log_prediction, get_logs, get_stats

ids_bp = Blueprint('ids', __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load model and label encoder
with open(os.path.join(BASE_DIR, 'model', 'ids_model.pkl'), 'rb') as f:
    model = pickle.load(f)

with open(os.path.join(BASE_DIR, 'model', 'label_encoder.pkl'), 'rb') as f:
    le = pickle.load(f)

# Load feature columns
with open(os.path.join(BASE_DIR, 'model', 'feature_columns.json'), 'r') as f:
    feature_columns = json.load(f)

print("[INFO] ML model loaded successfully")

@ids_bp.route('/api/analyze', methods=['POST'])
def analyze():
    if 'user' not in session:
        user = request.headers.get('X-User')
        if not user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    features = data.get('features')
    traffic_id = data.get('traffic_id', 'N/A')

    if not features:
        return jsonify({'success': False, 'message': 'No features provided'}), 400

    input_df = pd.DataFrame([features])
    input_df = input_df.reindex(columns=feature_columns, fill_value=0)
    prediction_encoded = model.predict(input_df)[0]
    confidence = round(max(model.predict_proba(input_df)[0]) * 100, 2)
    prediction = le.inverse_transform([prediction_encoded])[0]

    log_prediction(traffic_id, prediction, confidence)

    return jsonify({
        'success': True,
        'traffic_id': traffic_id,
        'prediction': prediction,
        'confidence': confidence
    }), 200

@ids_bp.route('/api/alerts', methods=['GET'])
def alerts():
    if 'user' not in session:
        user = request.headers.get('X-User')
        if not user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    logs = get_logs(limit=100)
    attacks = [log for log in logs if log['prediction'] == 'ATTACK']
    return jsonify({'success': True, 'alerts': attacks}), 200

@ids_bp.route('/api/logs', methods=['GET'])
def logs():
    if 'user' not in session:
        user = request.headers.get('X-User')
        if not user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    all_logs = get_logs(limit=100)
    return jsonify({'success': True, 'logs': all_logs}), 200

@ids_bp.route('/api/dashboard', methods=['GET'])
def dashboard():
    if 'user' not in session:
        user = request.headers.get('X-User')
        if not user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    stats = get_stats()
    recent_logs = get_logs(limit=10)
    return jsonify({
        'success': True,
        'stats': stats,
        'recent_logs': recent_logs
    }), 200