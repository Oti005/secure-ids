import sqlite3
import os

DATABASE = 'ids_database.db' #this is the name of the SQLite database file that will be created in the project directory

def get_db():
    conn = sqlite3.connect(DATABASE) #this creates a connection to the SQLite database file, if the file doesn't exist it will be created
    conn.row_factory = sqlite3.Row #this allows us to access the columns of the database rows by name instead of by index, which makes the code easier to read and maintain
    return conn

def init_db():
    conn = get_db() #this gets a connection to the database
    cursor = conn.cursor()#this creates a cursor object which allows us to execute SQL commands against the database

    #create users table 
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
    ''') #this SQL command creates a table called "users" with columns for id, username, password, and created_at. The id is an auto-incrementing primary key, username is unique and cannot be null, password cannot be null, and created_at defaults to the current timestamp when a new user is created

    #create logs table
    cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   traffic_id TEXT,
                   prediction TEXT,
                   confidence REAL,
                   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
    ''') #this SQL command creates a table called "logs" with columns for id, traffic_id, prediction, confidence, and timestamp. The id is an auto-incrementing primary key, traffic_id is a text field that can store an identifier for the network traffic record, prediction is a text field that can store the model's prediction (e.g., NORMAL or ATTACK), confidence is a real number that can store the model's confidence score for the prediction, and timestamp defaults to the current timestamp when a new log entry is created

    #create a default admin user if none exists 
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?,?)",
            ('admin', 'admin123') #this inserts a default admin user with the username "admin" and password "admin123" into the users table if it doesn't already exist. In a production environment, you would want to use a stronger password and consider hashing the password for security
        )
        print("[INFO] Default admin user created - username: admin, password: admin123")

    conn.commit()#this commits the changes to the database, saving the new tables and any new data that was inserted
    conn.close()#this saves the changes to the database and closes the connection to free up resources
    print("[INFO] Database initialized successfully..")

def log_prediction(traffic_id, prediction, confidence):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (traffic_id, prediction, confidence) VALUES (?, ?, ?)",
        (traffic_id, prediction, confidence) #this inserts a new log entry into the logs table with the provided traffic_id, prediction, and confidence values. This function can be called whenever the model makes a prediction to keep a record of the predictions and their confidence scores for later analysis or auditing
    )
    conn.commit()
    conn.close()

def get_logs(limit=100):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?",
                   (limit,)#this retrieves the most recent log entries from the logs table, ordered by timestamp in descending order, and limits the number of entries returned to the specified limit (default is 100). This function can be used to display the prediction logs in the admin dashboard or for analysis purposes
                   )
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

def get_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM logs") #this retrieves the total number of log entries in the logs table, which can be used to show how many predictions have been made by the model
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as attacks FROM logs WHERE prediction = 'ATTACK'") #this retrieves the number of log entries where the prediction was 'ATTACK', which can be used to show how many attacks have been detected by the model
    attacks = cursor.fetchone()['attacks']

    cursor.execute("SELECT COUNT(*) as normal FROM logs WHERE prediction = 'NORMAL'")
    normal = cursor.fetchone()['normal']

    conn.close()
    return {
        'total_analyzed': total,
        'attacks_detected': attacks,
        'noraml_traffic': normal
    }
