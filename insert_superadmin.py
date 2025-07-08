import sqlite3
from werkzeug.security import generate_password_hash

# Connect to the database
con = sqlite3.connect(r'C:\Users\dell\Desktop\final\task progress tracking\tracker.db')
cur = con.cursor()

# Username and hashed password for superadmin
username = 'superadmin'
secure_password = 'S!perAdm1n_2025!'
hashed_password = generate_password_hash(secure_password)
role = 'superadmin'
email = 'superadmin@example.com'

# Insert superadmin if not exists, or update password/email if exists
cur.execute("SELECT * FROM user WHERE username = ?", (username,))
if not cur.fetchone():
    cur.execute("INSERT INTO user (username, password, role, email) VALUES (?, ?, ?, ?)", (username, hashed_password, role, email))
    print('Superadmin created with password:', secure_password)
else:
    cur.execute("UPDATE user SET password = ?, email = ? WHERE username = ?", (hashed_password, email, username))
    print('Superadmin password and email updated. New password:', secure_password)
con.commit()
con.close()
