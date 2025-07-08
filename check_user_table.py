import sqlite3

conn = sqlite3.connect('tracker.db')
c = conn.cursor()
c.execute("PRAGMA table_info(user);")
print("user table columns:")
for row in c.fetchall():
    print(row)
conn.close()
