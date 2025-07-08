import sqlite3

try:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(document);")
    columns = cursor.fetchall()
    if not columns:
        print("No columns found. The 'document' table may not exist.")
    else:
        print("Columns in 'document' table:")
        for col in columns:
            print(col)
    conn.close()
except Exception as e:
    print(f"Error: {e}")
