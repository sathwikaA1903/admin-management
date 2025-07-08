import sqlite3
con = sqlite3.connect('tracker.db')
cur = con.cursor()
cur.execute("""
    INSERT INTO task (project_name, job_number, department_id, job_description, status, edc, due_date, spoc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
    'Demo Project', 'JN001', 1, 'Demo job description', 'New', '2025-07-10', '2025-07-05', 'Demo User'
))
con.commit()
con.close()
