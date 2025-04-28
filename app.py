import io
import pickle
import pickletools
import re
import subprocess
from flask import Flask, abort, render_template, request, redirect, send_from_directory, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
from markupsafe import escape  

app = Flask(__name__)
app.secret_key = 'your_secret_key_here' 


app.jinja_env.globals.update(hasattr=hasattr, getattr=getattr, type=type)


DB_PATH = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user

@app.route('/')
def home():
    return render_template('index.html', title='Home Page')

@app.route('/about')
def about():
    return render_template('about.html', title='About Us')

@app.route('/contact')
def contact():
    return render_template('contact.html', title='Contact Us')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        error = None
        if get_user_by_username(username):
            error = 'Username already exists.'
        elif get_user_by_email(email):
            error = 'Email already registered.'
        elif password != confirm_password:
            error = 'Passwords do not match.'

        if error is None:
            hashed_password = generate_password_hash(password)
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        flash(error, 'error')

    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        user = get_user_by_username(username)

        if user is None:
            error = 'Username does not exist.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('profile'))

        flash(error, 'error')

    return render_template('login.html', title='Login')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user is None:
        session.clear()
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    return render_template('profile.html', title='Profile', user=user)

@app.route('/message-board')
def message_board():
    conn = get_db_connection()
    messages = conn.execute('SELECT * FROM messages ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('message_board.html', title='Message Board', messages=messages)

@app.route('/post-message', methods=['POST'])
def post_message():
    if 'user_id' not in session:
        flash('Please log in to post messages.', 'error')
        return redirect(url_for('login'))

    content = request.form['content']

    if not content or content.strip() == '':
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('message_board'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (user_id, username, content, created_at) VALUES (?, ?, ?, ?)',
        (session['user_id'], session['username'], content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

    flash('Message posted successfully!', 'success')
    return redirect(url_for('message_board'))

@app.route('/delete-message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    message = conn.execute('SELECT * FROM messages WHERE id = ?', (message_id,)).fetchone()

    if message is None:
        conn.close()
        flash('Message not found.', 'error')
        return redirect(url_for('message_board'))

    if message['user_id'] != session['user_id']:
        conn.close()
        flash('You can only delete your own messages.', 'error')
        return redirect(url_for('message_board'))

    conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()

    flash('Message deleted successfully!', 'success')
    return redirect(url_for('message_board'))


@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = None
    target = None
    
    if request.method == 'POST':
        target = request.form.get('target')
        if target:
            try:
                import subprocess
                ping_process = subprocess.Popen(
                    f"ping -c 4 {target}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = ping_process.communicate()
                
                if ping_process.returncode == 0:
                    result = {
                        'success': True,
                        'output': stdout.decode('utf-8', errors='replace')
                    }
                else:
                    result = {
                        'success': False,
                        'output': stderr.decode('utf-8', errors='replace') or stdout.decode('utf-8', errors='replace')
                    }
            except Exception as e:
                result = {
                    'success': False,
                    'output': str(e)
                }
    
    return render_template('ping.html', title='Ping Tool', result=result, target=target)

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
ALLOWED_TYPES = (list, dict, tuple, str, int, float)
BLACKLIST_KEYWORDS = [
    b'posix', b'system', b'os', b'subprocess', b'builtins', b'eval', b'exec', b'__import__'
]

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    message = None
    status = None
    analysis_data = None

    if request.method == 'POST':
        file = request.files.get('file')

        if not file or file.filename == '':
            message = 'No file selected'
            status = 'error'
        elif not file.filename.endswith('.pkl'):
            message = 'Only .pkl files are allowed'
            status = 'error'
        else:
            try:
                file.seek(0, os.SEEK_END)
                file_length = file.tell()
                if file_length > MAX_FILE_SIZE:
                    raise ValueError('File is too large')
                file.seek(0)

                raw_data = file.read()
                disassembled = io.BytesIO()
                pickletools.dis(raw_data, out=disassembled)

                for keyword in BLACKLIST_KEYWORDS:
                    if keyword in raw_data:
                        raise ValueError(f'Blocked keyword "{keyword.decode()}" found in pickle content')

                uploads_dir = os.path.join('static', 'files')
                os.makedirs(uploads_dir, exist_ok=True)
                file_path = os.path.join(uploads_dir, file.filename)
                file.save(file_path)

                with open(file_path, 'rb') as pkl_file:
                    obj = pickle.load(pkl_file)

                if not isinstance(obj, ALLOWED_TYPES):
                    raise ValueError('Unsupported object type')

                analysis_data = obj
                message = f'File {file.filename} uploaded and data restored safely'
                status = 'success'

            except Exception as e:
                message = f'Error processing file: {str(e)}'
                status = 'error'

    return render_template('upload.html',
                           title='Restore Analysis Data (Safe)',
                           message=message,
                           status=status,
                           analysis_data=analysis_data)

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    if not filename:
        flash('No file specified', 'error')
        return redirect(url_for('downloads'))
        
    safe_dir = os.path.abspath('static/files')
    target_path = os.path.abspath(os.path.join(safe_dir, filename))
    if not target_path.startswith(safe_dir):
        abort(403)  
    return send_from_directory(safe_dir, filename)

@app.route('/downloads')
def downloads():

    safe_dir = os.path.abspath('static/files')
    
    if not os.path.exists(safe_dir):
        os.makedirs(safe_dir)
    
    files = []
    for filename in os.listdir(safe_dir):
        file_path = os.path.join(safe_dir, filename)
        if os.path.isfile(file_path):
            size_kb = round(os.path.getsize(file_path) / 1024, 2)
            files.append({
                'name': filename,
                'path': filename,
                'size': size_kb
            })
    
    return render_template('downloads.html', title='Downloads', files=files)

if __name__ == '__main__':
    app.run(debug=True)
