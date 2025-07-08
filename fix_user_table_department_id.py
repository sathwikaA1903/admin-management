import sqlite3

DB_PATH = 'tracker.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Check if department_id exists
c.execute("PRAGMA table_info(user);")
columns = [row[1] for row in c.fetchall()]
if 'department_id' not in columns:
    print('Adding department_id column to user table...')
    c.execute("ALTER TABLE user ADD COLUMN department_id INTEGER;")
    conn.commit()
    print('department_id column added.')
else:
    print('department_id column already exists.')

conn.close()
