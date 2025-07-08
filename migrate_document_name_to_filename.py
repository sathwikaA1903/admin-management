import sqlite3

conn = sqlite3.connect('tracker.db')
cursor = conn.cursor()

# Check if 'name' column exists
cursor.execute("PRAGMA table_info(document)")
columns = [col[1] for col in cursor.fetchall()]

if 'name' in columns and 'filename' not in columns:
    # Rename column 'name' to 'filename' (SQLite doesn't support direct rename; need to recreate table)
    cursor.execute("ALTER TABLE document RENAME TO document_old")
    cursor.execute('''
        CREATE TABLE document (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            uploader TEXT,
            uploaded_at TEXT,
            filepath TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO document (id, filename, uploader, uploaded_at, filepath)
        SELECT id, name, uploader, uploaded_at, filepath FROM document_old
    ''')
    cursor.execute("DROP TABLE document_old")
    print("Renamed 'name' column to 'filename' in document table.")
else:
    # If both 'name' and 'filename' exist, drop 'name' column by recreating the table
    if 'name' in columns and 'filename' in columns:
        cursor.execute("ALTER TABLE document RENAME TO document_old")
        cursor.execute('''
            CREATE TABLE document (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                uploader TEXT,
                uploaded_at TEXT,
                filepath TEXT
            )
        ''')
        cursor.execute('''
            INSERT INTO document (id, filename, uploader, uploaded_at, filepath)
            SELECT id, filename, uploader, uploaded_at, filepath FROM document_old
        ''')
        cursor.execute("DROP TABLE document_old")
        print("Dropped 'name' column from document table.")
    else:
        print("No migration needed. Either 'name' does not exist or 'filename' already present.")

conn.commit()
conn.close()
