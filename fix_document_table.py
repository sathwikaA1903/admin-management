import sqlite3

conn = sqlite3.connect('tracker.db')
cursor = conn.cursor()

# Add filename column if it doesn't exist
try:
    cursor.execute('ALTER TABLE document ADD COLUMN filename TEXT')
    print('Added filename column.')
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e):
        print('filename column already exists.')
    else:
        print('Error:', e)

# Add filepath column if it doesn't exist
try:
    cursor.execute('ALTER TABLE document ADD COLUMN filepath TEXT')
    print('Added filepath column.')
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e):
        print('filepath column already exists.')
    else:
        print('Error:', e)

# Add uploader column if it doesn't exist
try:
    cursor.execute('ALTER TABLE document ADD COLUMN uploader TEXT')
    print('Added uploader column.')
except sqlite3.OperationalError as e:
    if 'duplicate column name' in str(e):
        print('uploader column already exists.')
    else:
        print('Error:', e)

conn.commit()
conn.close()
print('Document table schema fix complete.')
