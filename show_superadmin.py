import sqlite3

con = sqlite3.connect('tracker.db')
cur = con.cursor()

cur.execute("SELECT id, username, email, role, password FROM user WHERE username = ?", ('superadmin',))
rows = cur.fetchall()

if not rows:
    print('No superadmin user found.')
else:
    for row in rows:
        print(f"ID: {row[0]}, Username: {row[1]}, Email: {row[2]}, Role: {row[3]}, Password Hash: {row[4]}")

con.close()
