from flask import Blueprint, request, jsonify, session
from database import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        session['user'] = username

        print("LOGIN SESSION:", dict(session))

        return jsonify({
            "success": True,
            "username": username
        }), 200

    return jsonify({
        "success": False,
        "message": "Invalid credentials"
    }), 401


@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'success': True, 'message': 'Logged out'}), 200


@auth_bp.route('/api/check-session', methods=['GET'])
def check_session():
    if 'user' in session:
        return jsonify({
            'logged_in': True,
            'username': session['user']
        }), 200

    return jsonify({'logged_in': False}), 401

@auth_bp.route('/api/debug-session', methods=['GET'])
def debug_session():
    return jsonify({
        "session": dict(session),
        "user": session.get("user")
    })