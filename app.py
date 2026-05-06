import os
import sqlite3
import hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from dlp_core import hash_data, check_hash_in_db, get_fuzzy_hash, check_fuzzy_hash_in_db

app = Flask(__name__)
app.secret_key = 'super_secret_dlp_key_for_demo'
# Set the filenames for our databases
DATABASE = 'database.db'
USER_DB = 'user_pass_cred.db'          # Database for regular users
ADMIN_DB = 'admin_user_pass.db'        # Database for admin credentials

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        # Create sensitive_hashes table with both exact and fuzzy hash columns
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sensitive_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_name TEXT NOT NULL,
                hash_value TEXT NOT NULL UNIQUE,
                fuzzy_hash_value TEXT NOT NULL,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create logs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL,
                hash_checked TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

# Initialize DB on startup
if not os.path.exists(DATABASE):
    init_db()
else:
    # Just to be safe, try to init_db in case tables are missing
    init_db()

# --- Authentication Database Setup ---
def init_auth_dbs():
    
    # 1. Setup Admin Database
    admin_conn = sqlite3.connect(ADMIN_DB)
    # Create the table for admin users
    admin_conn.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Check if we have an admin user, if not, add the default one
    cursor = admin_conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM admins')
    if cursor.fetchone()[0] == 0:
        # Hash the default password 'atif123' using SHA-256 for security
        default_hash = hashlib.sha256(b'atif123').hexdigest()
        # Insert the default admin 'atif'
        admin_conn.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', ('atif', default_hash))
    
    admin_conn.commit()
    admin_conn.close()

    # 2. Setup Regular User Database
    user_conn = sqlite3.connect(USER_DB)
    # Create the table for regular users
    user_conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    user_conn.commit()
    user_conn.close()

# Call the function to make sure our auth databases are ready
init_auth_dbs()

# --- Custom Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access is required to view this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    if request.method == 'POST':
        data_to_hash = b""
        data_name = "Unknown data"
        
        # Check if text was provided
        if 'text_data' in request.form and request.form['text_data'].strip():
            data_to_hash = request.form['text_data'].encode('utf-8')
            data_name = "Text Message"
        # Otherwise check if a file was uploaded
        elif 'file_data' in request.files:
            file = request.files['file_data']
            if file.filename != '':
                data_to_hash = file.read()
                data_name = file.filename
        
        if not data_to_hash:
            flash('Please provide either text or a file.', 'danger')
            return redirect(url_for('register'))

        # Generate exact hash and fuzzy hash
        generated_hash = hash_data(data_to_hash)
        fuzzy_hash = get_fuzzy_hash(data_to_hash)
        
        # Store both hashes in the same row in DB
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO sensitive_hashes (data_name, hash_value, fuzzy_hash_value) VALUES (?, ?, ?)', 
                         (data_name, generated_hash, fuzzy_hash))
            conn.commit()
            
            flash(f'Data registered successfully! Hash: {generated_hash[:10]}...', 'success')
        except sqlite3.IntegrityError:
            flash('This data is already registered.', 'warning')
        finally:
            conn.close()
            
        return redirect(url_for('register'))
        
    return render_template('register.html')

@app.route('/simulate', methods=['GET', 'POST'])
@login_required
def simulate():
    if request.method == 'POST':
        data_to_hash = b""
        action_type = "Unknown"
        
        # Check if text was provided
        if 'text_data' in request.form and request.form['text_data'].strip():
            data_to_hash = request.form['text_data'].encode('utf-8')
            action_type = "Text Message"
        # Otherwise check if a file was uploaded
        elif 'file_data' in request.files:
            file = request.files['file_data']
            if file.filename != '':
                data_to_hash = file.read()
                action_type = "File Upload"
        
        if not data_to_hash:
            flash('Please provide either a message or a file to simulate.', 'warning')
            return redirect(url_for('simulate'))

        # Generate exact hash and fuzzy hash of incoming data
        checked_hash = hash_data(data_to_hash)
        fuzzy_hash = get_fuzzy_hash(data_to_hash)
        
        # Check against DB
        is_blocked = False
        blocked_reason = ""
        
        # First check exact match
        if check_hash_in_db(checked_hash):
            is_blocked = True
            blocked_reason = "(Exact Hash Match)"
        # If no exact match, try fuzzy match
        elif check_fuzzy_hash_in_db(fuzzy_hash):
            is_blocked = True
            blocked_reason = "(Fuzzy Hash Match - 70%+ Similarity)"
        
        status = "Blocked" if is_blocked else "Allowed"
            
        # Log the attempt
        hash_preview = checked_hash[:10] + "..."
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO logs (action_type, status, hash_checked) VALUES (?, ?, ?)',
                       (action_type, status, hash_preview))
        conn.commit()
        conn.close()
        
        if is_blocked:
            flash(f'🚨 ALERT: Sensitive data leak detected and blocked! {blocked_reason}', 'danger')
        else:
            flash('✅ Data passed inspection. Transaction allowed.', 'success')
            
        return redirect(url_for('simulate'))
        
    return render_template('simulate.html')

@app.route('/send_email', methods=['GET', 'POST'])
@login_required
def send_email():
    if request.method == 'POST':
        recipient = request.form.get('recipient')
        subject = request.form.get('subject')
        
        text_data = b""
        file_data = b""
        action_type = "Email Sent"
        
        if 'text_data' in request.form and request.form['text_data'].strip():
            text_data = request.form['text_data'].encode('utf-8')
            
        if 'file_data' in request.files:
            file = request.files['file_data']
            if file.filename != '':
                file_data = file.read()
                
        if not text_data and not file_data:
            flash('Please provide an email message or an attachment.', 'warning')
            return redirect(url_for('send_email'))
        
        is_blocked = False
        blocked_reason = ""
        hash_preview = ""
        
        # Check text hash
        if text_data:
            text_hash = hash_data(text_data)
            text_fuzzy = get_fuzzy_hash(text_data)
            
            if check_hash_in_db(text_hash):
                is_blocked = True
                blocked_reason = "Email Message Text (Exact Match)"
                hash_preview = text_hash[:10] + "..."
            elif check_fuzzy_hash_in_db(text_fuzzy):
                is_blocked = True
                blocked_reason = "Email Message Text (Fuzzy Match >= 70%)"
                hash_preview = text_hash[:10] + "..."
                
        # Check file hash
        if not is_blocked and file_data:
            file_hash = hash_data(file_data)
            file_fuzzy = get_fuzzy_hash(file_data)
            
            if check_hash_in_db(file_hash):
                is_blocked = True
                blocked_reason = "Email Attachment (Exact Match)"
                hash_preview = file_hash[:10] + "..."
            elif check_fuzzy_hash_in_db(file_fuzzy):
                is_blocked = True
                blocked_reason = "Email Attachment (Fuzzy Match >= 70%)"
                hash_preview = file_hash[:10] + "..."
                
        status = "Blocked" if is_blocked else "Allowed"
        
        # We will use the preview of whichever hash got blocked, or just the text hash if allowed
        if not hash_preview:
            hash_preview = hash_data(text_data)[:10] + "..." if text_data else hash_data(file_data)[:10] + "..."
            
        # Log the attempt
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO logs (action_type, status, hash_checked) VALUES (?, ?, ?)',
                       (action_type, status, hash_preview))
        conn.commit()
        conn.close()
        
        if is_blocked:
            flash(f'🚨 ERROR: This {blocked_reason.lower()} is restricted to send to someone. (DLP Blocked)', 'danger')
        else:
            flash(f'✅ Email successfully sent to {recipient}!', 'success')
            
        return redirect(url_for('send_email'))
        
    return render_template('send_email.html')

@app.route('/logs')
@login_required
@admin_required
def logs():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('logs.html', logs=logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the username and password entered by the user
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Hash the entered password so we can compare it safely
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        # Connect to the admin database to check the credentials first
        conn_admin = sqlite3.connect(ADMIN_DB)
        conn_admin.row_factory = sqlite3.Row
        cursor = conn_admin.cursor()
        
        # Look for an admin with the matching username and hashed password
        cursor.execute('SELECT * FROM admins WHERE username = ? AND password_hash = ?', (username, password_hash))
        admin_user = cursor.fetchone()
        conn_admin.close()
        
        if admin_user:
            session['logged_in'] = True
            session['is_admin'] = True
            session['username'] = username
            flash('Logged in as Admin successfully.', 'success')
            return redirect(url_for('admin'))
            
        # If not admin, check normal users
        conn_user = sqlite3.connect(USER_DB)
        conn_user.row_factory = sqlite3.Row
        cursor = conn_user.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
        normal_user = cursor.fetchone()
        conn_user.close()
        
        if normal_user:
            session['logged_in'] = True
            session['is_admin'] = False
            session['username'] = username
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))

        flash('Invalid credentials. Please try again.', 'danger')
            
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password.', 'warning')
            return redirect(url_for('signup'))
            
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        conn = sqlite3.connect(USER_DB)
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        finally:
            conn.close()
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@admin_required
def admin():
    conn = get_db_connection()
    hashes = conn.execute('SELECT * FROM sensitive_hashes ORDER BY date_added DESC').fetchall()
    conn.close()
    return render_template('admin.html', hashes=hashes)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
