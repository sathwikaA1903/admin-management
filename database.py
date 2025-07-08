import sqlite3
import os

# Delete the old database to ensure a fresh start
if os.path.exists('tracker.db'):
    os.remove('tracker.db')

conn = sqlite3.connect('tracker.db')
cursor = conn.cursor()

# Create department table
cursor.execute("""
CREATE TABLE IF NOT EXISTS department (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);
""")

# Create user table with department_id and role columns
cursor.execute("""
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email TEXT NOT NULL UNIQUE,
    department_id INTEGER,
    FOREIGN KEY (department_id) REFERENCES department(id)
);
""")

# Create task table
cursor.execute("""
CREATE TABLE IF NOT EXISTS task (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name TEXT NOT NULL,
    job_number TEXT NOT NULL,
    department_id INTEGER NOT NULL,
    job_description TEXT NOT NULL,
    edc DATE NOT NULL,
    due_date DATE NOT NULL,
    spoc TEXT NOT NULL,
    FOREIGN KEY (department_id) REFERENCES department(id)
);
""")

# Create document table
cursor.execute("""
CREATE TABLE IF NOT EXISTS document (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
""")

conn.commit()
conn.close()

print("Database and tables created successfully with fresh schema.")
