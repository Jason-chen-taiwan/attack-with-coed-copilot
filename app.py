from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Used for session management

# Database setup
DB_PATH = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Create messages table if it doesn't exist
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

# Initialize database tables
init_db()

# Helper functions
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
        
        # Form validation
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

# Message Board Routes
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

if __name__ == '__main__':
    app.run(debug=True)
