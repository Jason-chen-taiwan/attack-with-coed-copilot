import sqlite3
import os

# Database path
DB_PATH = 'users.db'

def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("Initializing database...")
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    print("Users table created or already exists.")
    
    # Check if messages table exists and create if not
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    if cursor.fetchone() is None:
        cursor.execute('''
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        print("Messages table created.")
    else:
        print("Messages table already exists.")
    
    conn.commit()
    conn.close()
    print("Database initialization complete.")

if __name__ == "__main__":
    initialize_database()
