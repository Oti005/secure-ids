from flask import Blueprint, request, jsonify, session
from database import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data= request.get_json()
    username= data.get('username')
    password= data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400
    
    conn= get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )
    user=cursor.fetchone()
    conn.close()

    if user:
        session['user']=username
        session.modified = True
        return jsonify({"success": True,"message":"Login successful", "username":username}),200
    else:
        return jsonify({'success': False,'message':'Invalid username or password'}),401

@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'success': True, 'message': 'Logged out successfully'}),200

@auth_bp.route('/api/check-session', methods=['GET'])
def check_session():
    if 'user' in session:
        return jsonify({'logged_in': True, 'username': session['user']}),200
    else:
        return jsonify({'logged_in': False}),401

