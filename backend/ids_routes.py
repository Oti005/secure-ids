import pickle
import numpy as np
import pandas as pd
import os
import json
import smtplib
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import Blueprint, request, jsonify, session
from database import (
    log_prediction, get_logs, get_stats,
    get_blocked_ips, get_days, clear_logs,
    delete_log, update_password, get_db
)

ids_bp = Blueprint('ids', __name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, 'model', 'ids_model.pkl'), 'rb') as f:
    model = pickle.load(f)
with open(os.path.join(BASE_DIR, 'model', 'label_encoder.pkl'), 'rb') as f:
    le = pickle.load(f)
with open(os.path.join(BASE_DIR, 'model', 'feature_columns.json'), 'r') as f:
    feature_columns = json.load(f)

print("[INFO] ML model loaded successfully")

def is_authenticated():
    return 'user' in session

def get_severity(confidence):
    if confidence >= 90: return 'HIGH'
    elif confidence >= 70: return 'MEDIUM'
    return 'LOW'

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
    confidence = round(float(max(model.predict_proba(input_df)[0])) * 100, 2)
    prediction = le.inverse_transform([prediction_encoded])[0]
    attack_type = data.get('attack_type', 'Unknown')
    destination_port = data.get('destination_port', 'N/A')

    log_prediction(
        data.get('traffic_id', 'N/A'),
        prediction, confidence,
        data.get('day', 'Unknown'),
        data.get('source_ip', 'N/A'),
        attack_type,
        destination_port
    )
    return jsonify({
        'success': True,
        'prediction': prediction,
        'confidence': confidence,
        'severity': get_severity(confidence),
        'attack_type': attack_type
    }), 200

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

@ids_bp.route('/api/logs', methods=['GET'])
def logs():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    day = request.args.get('day', 'All')
    all_logs = get_logs(limit=1000, day=day)
    for l in all_logs:
        l['severity'] = get_severity(l['confidence'])
    return jsonify({'success': True, 'logs': all_logs}), 200

@ids_bp.route('/api/logs/<int:log_id>', methods=['DELETE'])
def delete_log_route(log_id):
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    delete_log(log_id)
    return jsonify({'success': True, 'message': 'Log deleted'}), 200

@ids_bp.route('/api/dashboard', methods=['GET'])
def dashboard():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    day = request.args.get('day', 'All')
    stats = get_stats(day=day)
    recent_logs = get_logs(limit=10, day=day)
    for r in recent_logs:
        r['severity'] = get_severity(r['confidence'])
    return jsonify({'success': True, 'stats': stats, 'recent_logs': recent_logs}), 200

@ids_bp.route('/api/blocked-ips', methods=['GET'])
def blocked_ips():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    day = request.args.get('day', 'All')
    return jsonify({'success': True, 'blocked_ips': get_blocked_ips(day=day)}), 200

@ids_bp.route('/api/blocked-ips/<int:ip_id>', methods=['DELETE'])
def delete_blocked_ip(ip_id):
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE id = ?", (ip_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'IP record deleted'}), 200

@ids_bp.route('/api/days', methods=['GET'])
def days():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    return jsonify({'success': True, 'days': get_days()}), 200

@ids_bp.route('/api/stats-by-day', methods=['GET'])
def stats_by_day():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT day,
            SUM(CASE WHEN prediction = 'ATTACK' THEN 1 ELSE 0 END) as attacks,
            SUM(CASE WHEN prediction = 'NORMAL' THEN 1 ELSE 0 END) as normal
        FROM logs GROUP BY day
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': rows}), 200

@ids_bp.route('/api/stats-by-attack-type', methods=['GET'])
def stats_by_attack_type():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT attack_type, COUNT(*) as count
        FROM logs
        WHERE prediction = 'ATTACK'
        GROUP BY attack_type
        ORDER BY count DESC
    ''')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': rows}), 200

@ids_bp.route('/api/update-password', methods=['POST'])
def update_password_route():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    username = session.get('user')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, current_password))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
    update_password(username, new_password)
    return jsonify({'success': True, 'message': 'Password updated successfully'}), 200

@ids_bp.route('/api/generate-report', methods=['POST'])
def generate_report():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json()
    email_to = data.get('email')
    day = data.get('day', 'All')
    if not email_to:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    # Check email config
    try:
        from email_config import SMTP_EMAIL, SMTP_PASSWORD
        if 'your-gmail' in SMTP_EMAIL or 'your-app-password' in SMTP_PASSWORD:
            return jsonify({'success': False, 'message': 'Email not configured. Please fill in backend/email_config.py with your Gmail credentials.'}), 500
    except ImportError:
        return jsonify({'success': False, 'message': 'email_config.py not found in backend folder.'}), 500

    logs = get_logs(limit=10000, day=day)
    stats = get_stats(day=day)

    try:
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.units import inch
        from datetime import datetime

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        elements = []
        styles = getSampleStyleSheet()

        elements.append(Paragraph("Optech IDS — Security Report", styles['Title']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Filter: {day}", styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))

        summary_data = [
            ['Total Analyzed', 'Attacks Detected', 'Normal Traffic', 'Attack Rate'],
            [
                str(stats['total_analyzed']),
                str(stats['attacks_detected']),
                str(stats['normal_traffic']),
                f"{((stats['attacks_detected'] / stats['total_analyzed']) * 100):.1f}%" if stats['total_analyzed'] > 0 else '0%'
            ]
        ]
        summary_table = Table(summary_data, colWidths=[2*inch]*4)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("Detailed Logs", styles['Heading2']))

        table_data = [['ID', 'Traffic ID', 'Prediction', 'Attack Type', 'Severity', 'Confidence', 'Source IP', 'Dest Port', 'Day', 'Timestamp']]
        for log in logs:
            table_data.append([
                str(log['id']),
                str(log.get('traffic_id', '')),
                str(log.get('prediction', '')),
                str(log.get('attack_type', 'Unknown')),
                get_severity(log['confidence']),
                f"{log.get('confidence', 0)}%",
                str(log.get('source_ip', 'N/A')),
                str(log.get('destination_port', 'N/A')),
                str(log.get('day', '')),
                str(log.get('timestamp', ''))
            ])

        logs_table = Table(table_data, colWidths=[0.4*inch, 1.1*inch, 0.8*inch, 1.0*inch, 0.6*inch, 0.7*inch, 1.1*inch, 0.7*inch, 0.7*inch, 1.4*inch])
        logs_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 6.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
        ]))
        elements.append(logs_table)
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
    except Exception as e:
        return jsonify({'success': False, 'message': f'PDF generation failed: {str(e)}'}), 500

    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = email_to
        msg['Subject'] = f"Optech IDS Security Report — {day}"
        body = f"Please find attached the Optech IDS security report.\n\nFilter: {day}\nTotal Analyzed: {stats['total_analyzed']}\nAttacks Detected: {stats['attacks_detected']}\nNormal Traffic: {stats['normal_traffic']}"
        msg.attach(MIMEText(body, 'plain'))
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(pdf_bytes)
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename="optech_ids_report_{day}.pdf"')
        msg.attach(attachment)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return jsonify({'success': True, 'message': f'Report sent successfully to {email_to}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Email sending failed: {str(e)}'}), 500

@ids_bp.route('/api/clear-logs', methods=['POST'])
def clear_logs_api():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    clear_logs()
    return jsonify({'success': True, 'message': 'Logs cleared'}), 200