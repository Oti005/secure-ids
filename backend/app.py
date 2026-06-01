from flask import Flask
from flask_cors import CORS
from database import init_db
from auth import auth_bp
from ids_routes import ids_bp

app =Flask(__name__) #creates the  flask aplication instace 
app.secret_key = 'secure-ids-secret-key'#this is used for securely signing the session cookie, in a production environment this should be a strong, random value and kept secret to prevent attackers from tampering with the session data

app.config['SESSION_COOKIE_SAMESITE']='Lax' #this setting helps protect against Cross-Site Request Forgery (CSRF) attacks by restricting how cookies are sent with cross-site requests. 'Lax' allows cookies to be sent with top-level navigations and GET requests, but not with other types of cross-site requests, providing a balance between security and usability.
app.config['SESSION_COOKIE_SECURE']=False
app.config['SESSION_COOKIE_HTTPONLY']=False

CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "http://localhost:3000"}}, allow_headers=['Content-Type', 'X-User'], methods=['GET', 'POST', 'OPTIONS'], expose_headers=['Set-Cookie']) #this enables Cross-Origin Resource Sharing (CORS) for the Flask app, allowing it to accept requests from different origins (like a frontend running on a different port), supports_credentials=True allows cookies to be included in cross-origin requests which is necessary for maintaining user sessions

#Register blueprints
#A blueprint is flask way of organizing routes into separate files 
#register_blueprints connects those separate route files back to the main app 
app.register_blueprint(auth_bp)
app.register_blueprint(ids_bp)

#initialize database
init_db()

if __name__ == '__main__': #means only run the server if this file is executed directly, not when it's imported by another file
    app.run(debug=True, port=5000, host='127.0.0.1') #the server runs at http://localhost:5000
