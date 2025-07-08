import sqlite3

conn = sqlite3.connect('tracker.db')
cursor = conn.cursor()
try:
    cursor.execute("ALTER TABLE user ADD COLUMN department_id INTEGER;")
    print("department_id column added successfully.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("department_id column already exists.")
    else:
        print("Error:", e)
conn.commit()
conn.close()
