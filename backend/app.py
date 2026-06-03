from flask import Flask
from flask_cors import CORS
from database import init_db
from auth import auth_bp
from ids_routes import ids_bp

app = Flask(__name__)

#  Session secret
app.secret_key = 'secure-ids-secret-key'

#  Session configuration
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_DOMAIN'] = None

#  IMPORTANT: CORS for cookies
CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:3000"],
    allow_headers=["Content-Type"],
    methods=["GET", "POST", "OPTIONS"]
)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(ids_bp)

# Initialize DB
init_db()

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='127.0.0.1')