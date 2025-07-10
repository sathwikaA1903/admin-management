from flask import Flask, render_template, redirect, url_for, request, flash, g, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import os

DATABASE = r'C:\Users\dell\Desktop\final\task progress tracking\tracker.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'tracker.db')

os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

# Set your Gmail credentials as environment variables or directly here
SENDER_EMAIL = "l323sathwika@gmail.com"
SENDER_PASSWORD = "amar tbda zkja artu"  # App Password from Gmail

# --- Database Helpers ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False, commit=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if commit:
        get_db().commit()
    return (rv[0] if rv else None) if one else rv

# --- Create Tables ---
def create_tables():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL DEFAULT 'user',
            department_id INTEGER,
            FOREIGN KEY (department_id) REFERENCES department(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS department (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS task (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            job_number TEXT NOT NULL,
            department_id INTEGER NOT NULL,
            job_description TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            edc DATE NOT NULL,
            due_date DATE NOT NULL,
            spoc TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES department(id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            reminder_text TEXT NOT NULL,
            reminder_date DATE NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS task_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES task(id)
        )
    """)
    db.commit()

# --- Seed Departments ---
@app.before_request
def seed_departments():
    departments = [
        'IT Department', 'Marketing Department', 'Graphic Designers',
        'Operations', 'Finance', 'HR', 'Sales',
        'Business Analyst', 'Executive Department'
    ]
    for name in departments:
        exists = query_db("SELECT id FROM department WHERE name = ?", [name], one=True)
        if not exists:
            query_db("INSERT INTO department (name) VALUES (?)", [name], commit=True)

# --- Routes ---
@app.route("/")
def index():
    return redirect(url_for('login'))

@app.route("/home")
def home():
    return render_template("home.html", theme=session.get('theme', 'light'))

@app.route('/dashboard')
def dashboard():
    from flask import session
    # --- User Info ---
    user_name = session.get('username', 'Demo User')
    user_initials = ''.join([part[0].upper() for part in user_name.split() if part]) or 'U'

    # --- Tasks Progress and Summary ---
    from flask import session
    department_id = session.get('department_id')
    if not department_id:
        # Look up department_id if not in session
        user = query_db("SELECT department_id FROM user WHERE username = ?", [user_name], one=True)
        department_id = user['department_id'] if user and user['department_id'] else None
        if department_id:
            session['department_id'] = department_id

    if department_id:
        tasks = query_db("SELECT status, spoc, due_date FROM task WHERE department_id = ?", [department_id])
    else:
        tasks = []
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t['status'] and t['status'].lower() == 'completed'])
    tasks_progress = int((completed_tasks / total_tasks) * 100) if total_tasks else 0

    # --- Summary Counts ---
    assigned_tasks = len([t for t in tasks if t['spoc'] == user_name])
    from datetime import datetime
    today = datetime.now().strftime('%Y-%m-%d')
    due_today = len([t for t in tasks if t['due_date'] == today])
    past_due = len([t for t in tasks if t['status'] and t['status'].lower() != 'completed' and t['due_date'] < today])
    closed_tasks = len([t for t in tasks if t['status'] and t['status'].lower() == 'closed'])
    new_tasks = len([t for t in tasks if t['status'] and t['status'].lower() == 'new'])

    return render_template(
        'dashboard.html',
        overall_progress=tasks_progress,
        user_initials=user_initials,
        user_name=user_name,
        total_tasks=total_tasks,
        assigned_tasks=assigned_tasks,
        due_today=due_today,
        past_due=past_due,
        closed_tasks=closed_tasks,
        new_tasks=new_tasks
    )

    # --- Notes Progress ---
    notes = query_db("SELECT content FROM note") if 'note' in get_table_names() else []
    total_notes = len(notes)
    done_notes = len([
        n for n in notes if (
            n['content'] and (
                'done' in n['content'].lower() or 'completed' in n['content'].lower()
            )
        )
    ])
    notes_progress = int((done_notes / total_notes) * 100) if total_notes else 0

    # --- Overall Progress ---
    progress_values = [tasks_progress, notes_progress]
    overall_progress = int(sum(progress_values) / len(progress_values)) if progress_values else 0

    return render_template(
        'dashboard.html',
        overall_progress=overall_progress,
        tasks_progress=tasks_progress,
        notes_progress=notes_progress,
        user_name=user_name,
        user_initials=user_initials
    )

# Helper to get table names (sqlite)
def get_table_names():
    db = get_db()
    cur = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [row[0] for row in cur.fetchall()]

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        user = query_db("SELECT * FROM user WHERE username = ?", [username], one=True)
        if user:
            flash('Username already exists')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password)
        query_db(
            "INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
            [username, hashed_pw, role], commit=True
        )
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html', theme=session.get('theme', 'light'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f'[DEBUG] Login attempt: username="{username}", password="{password}"')
        user = query_db("SELECT * FROM user WHERE username = ?", [username], one=True)
        print(f'[DEBUG] DB user: {user}')
        if user:
            print(f'[DEBUG] Stored hash: {user["password"]}')
            check_result = check_password_hash(user['password'], password)
            print(f'[DEBUG] check_password_hash result: {check_result}')
        else:
            print('[DEBUG] No such user in DB')
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            flash('Logged in successfully!')
            if user['role'] == 'superadmin':
                return redirect(url_for('superadmin_dashboard'))
            elif user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html', theme=session.get('theme', 'light'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    from flask import request, redirect, url_for, flash, render_template
    
    departments = query_db("SELECT * FROM department")

    # Handle POST (user or task creation)
    import os
    if request.method == 'POST':
        if 'add_user' in request.form:
            username = request.form.get('user_username', '').strip()
            password = request.form.get('user_password', '').strip()
            email = request.form.get('user_email', '').strip()
            department_id = request.form.get('user_department_id')
            db_path = os.path.abspath(DATABASE)
            print(f"[DEBUG] Using database file: {db_path}")
            flash(f"[DEBUG] Using database file: {db_path}", 'info')
            if not (username and password and email and department_id):
                flash('All user fields are required.', 'danger')
                return redirect(url_for('admin_dashboard'))
            if query_db("SELECT * FROM user WHERE username = ? OR email = ?", [username, email], one=True):
                flash('User username or email already exists!', 'danger')
                return redirect(url_for('admin_dashboard'))
            hashed_pw = generate_password_hash(password)
            try:
                query_db(
                    "INSERT INTO user (username, password, email, role, department_id) VALUES (?, ?, ?, ?, ?)",
                    [username, hashed_pw, email, 'user', department_id], commit=True
                )
                print(f"[DEBUG] User {username} inserted successfully.")
                flash(f"[DEBUG] User {username} inserted successfully.", 'info')
            except sqlite3.OperationalError as e:
                print(f"[DEBUG] Error creating user: {e}")
                flash(f'Error creating user: {e}', 'danger')
                if 'no column named department_id' in str(e):
                    flash('Database schema is outdated. Please add the department_id column to the user table. Contact your developer to run: ALTER TABLE user ADD COLUMN department_id INTEGER;', 'danger')
                # Still render dashboard even if error
                return redirect(url_for('admin_dashboard'))
            except Exception as e:
                print(f"[DEBUG] General error creating user: {e}")
                flash(f'General error creating user: {e}', 'danger')
                return redirect(url_for('admin_dashboard'))
            try:
                msg_body = f"""Hello,\n\nYou have been added as a User by the Admin.\n\nYour login credentials are:\nUsername: {username}\nPassword: {password}\n\nPlease login at https://kvr-admin-management.onrender.com/login\n\nRegards,\nTask Progress Tracker Team\n"""
                msg = MIMEText(msg_body)
                msg["Subject"] = "Your User Account Credentials"
                msg["From"] = SENDER_EMAIL
                msg["To"] = email
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(SENDER_EMAIL, SENDER_PASSWORD)
                    server.send_message(msg)
                flash('User created and credentials sent to email!', 'success')
            except Exception as e:
                flash(f'User created, but failed to send email: {e}', 'danger')
            return redirect(url_for('admin_dashboard'))
        elif 'project_name' in request.form:
            project_name = request.form.get('project_name', '').strip()
            job_number = request.form.get('job_number', '').strip()
            department_id = request.form.get('department_id')
            job_description = request.form.get('job_description', '').strip()
            edc = request.form.get('edc', '').strip()
            due_date = request.form.get('due_date', '').strip()
            spoc = request.form.get('spoc', '').strip()
            if not (project_name and job_number and department_id and job_description and edc and due_date and spoc):
                flash('All task fields are required.', 'danger')
                return redirect(url_for('admin_dashboard'))
            try:
                query_db(
                    """
                    INSERT INTO task
                    (project_name, job_number, department_id, job_description, edc, due_date, spoc)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [project_name, job_number, department_id, job_description, edc, due_date, spoc],
                    commit=True
                )
                flash('Task assigned successfully!')
            except Exception as e:
                flash(f'Error assigning task: {e}', 'danger')
            return redirect(url_for('admin_dashboard'))

    # Fetch tasks for display
    try:
        tasks = query_db("""
            SELECT task.*, department.name AS department_name
            FROM task
            JOIN department ON task.department_id = department.id
            ORDER BY task.id DESC
        """)
    except Exception as e:
        flash(f'Could not load tasks: {e}', 'danger')
        tasks = []
    # Fetch users for display
    try:
        users = query_db("""
            SELECT user.id, user.username, user.email, user.role, department.name AS department_name
            FROM user
            LEFT JOIN department ON user.department_id = department.id
            WHERE user.role = 'user'
            ORDER BY user.id DESC
        """)
    except Exception as e:
        # If the error is about department_id, fallback to a simpler query
        if 'no such column: user.department_id' in str(e):
            users = query_db("SELECT id, username, email, role FROM user WHERE role = 'user' ORDER BY id DESC")
        else:
            flash(f'Could not load users: {e}', 'danger')
            users = []
    return render_template('admin_dashboard.html', theme=session.get('theme', 'light'), departments=departments, tasks=tasks, users=users)

# --- User Management: Edit & Delete ---
from flask import abort

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    print('[DEBUG] session role:', session.get('role'))
    
    if 'role' not in session or session['role'] not in ('admin', 'superadmin'):
        abort(403)
    user = query_db("SELECT * FROM user WHERE id = ?", [user_id], one=True)
    departments = query_db("SELECT * FROM department")
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        department_id = request.form.get('department_id')
        role = request.form.get('role', 'user').strip()
        if not (username and email and role):
            flash('All fields except password are required.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        try:
            query_db("UPDATE user SET username=?, email=?, department_id=?, role=? WHERE id=?", [username, email, department_id, role, user_id], commit=True)
            flash('User updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating user: {e}', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user, departments=departments)

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    print('[DEBUG] session role:', session.get('role'))
    
    if 'role' not in session or session['role'] not in ('admin', 'superadmin'):
        abort(403)
    try:
        query_db("DELETE FROM user WHERE id = ?", [user_id], commit=True)
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {e}', 'danger')
    return redirect(url_for('admin_dashboard'))


# --- Superadmin Dashboard ---
@app.route('/superadmin/dashboard', methods=['GET', 'POST'])
def superadmin_dashboard():
    departments = query_db("SELECT * FROM department")
    admins = query_db("SELECT * FROM user WHERE role='admin'")
    tasks = query_db("""
        SELECT task.*, department.name AS department_name
        FROM task
        JOIN department ON task.department_id = department.id
        ORDER BY task.id DESC
    """)
    if request.method == 'POST':
        if 'create_admin' in request.form:
            username = request.form['admin_username']
            password = request.form['admin_password']
            email = request.form['admin_email']
            if query_db("SELECT * FROM user WHERE username = ? OR email = ?", [username, email], one=True):
                flash('Admin username or Gmail already exists!', 'danger')
            else:
                hashed_pw = generate_password_hash(password)
                query_db(
                    "INSERT INTO user (username, password, email, role) VALUES (?, ?, ?, ?)",
                    [username, hashed_pw, email, 'admin'], commit=True
                )
                # Send credentials to the new admin's Gmail
                try:
                    msg_body = f"""Hello,\n\nYou have been added as an Admin by the Superadmin.\n\nYour login credentials are:\nUsername: {username}\nPassword: {password}\n\nPlease login at https://kvr-admin-management.onrender.com/login\n\nRegards,\nTask Progress Tracker Team\n"""
                    msg = MIMEText(msg_body)
                    msg["Subject"] = "Your Admin Account Credentials"
                    msg["From"] = SENDER_EMAIL
                    msg["To"] = email
                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(SENDER_EMAIL, SENDER_PASSWORD)
                        server.send_message(msg)
                    flash('Admin created and credentials sent to Gmail!', 'success')
                except Exception as e:
                    flash(f'Admin created, but failed to send email: {e}', 'danger')
                return redirect(url_for('superadmin_dashboard'))
        else:
            project_name = request.form['project_name']
            job_number = request.form['job_number']
            department_id = request.form['department_id']
            job_description = request.form['job_description']
            status = request.form['status']
            edc = request.form['edc']
            due_date = request.form['due_date']
            spoc = request.form['spoc']
            query_db("""
                INSERT INTO task
                (project_name, job_number, department_id, job_description, status, edc, due_date, spoc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                project_name, job_number, department_id, job_description, status,
                edc, due_date, spoc
            ], commit=True)
            
          # Send credentials to the new admin's Gmail
            try:
                    msg_body = f"""Hello,

You have been added as an Admin by the Superadmin.

Your login credentials are:
Username: {username}
Password: {password}

Please login at https://kvr-admin-management.onrender.com/login

Regards,
Task Progress Tracker Team
"""
                    msg = MIMEText(msg_body)
                    msg["Subject"] = "Your Admin Account Credentials"
                    msg["From"] = SENDER_EMAIL
                    msg["To"] = email
                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(SENDER_EMAIL, SENDER_PASSWORD)
                        server.send_message(msg)
                    flash('Admin created and credentials sent to Gmail!', 'success')
            except Exception as e:
                    flash(f'Admin created, but failed to send email: {e}', 'danger')
            flash('Task assigned successfully!', 'success')
            return redirect(url_for('superadmin_dashboard'))
    return render_template('superadmin_dashboard.html', departments=departments, admins=admins,tasks=tasks)


@app.route('/superadmin/admin/delete/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    query_db("DELETE FROM user WHERE id=? AND role='admin'", [admin_id], commit=True)
    flash('Admin deleted successfully!', 'success')
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/admin/send_credentials/<int:admin_id>', methods=['POST'])
def send_admin_credentials(admin_id):
    admin = query_db("SELECT * FROM user WHERE id=? AND role='admin'", [admin_id], one=True)
    if not admin:
        flash('Admin not found!', 'danger')
        return redirect(url_for('superadmin_dashboard'))
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import Header
    try:
        sender_email = SENDER_EMAIL
        sender_password = SENDER_PASSWORD
        receiver_email = admin['email']
        username = admin['username']
        password = admin['password'] if 'password' in admin else 'Set by admin'
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = "Your Admin Account Credentials"
        body = f"""
        You have been added as an Admin by the Superadmin.\n\nUsername: {username}\nPassword: {password}\n\nPlease login at https://kvr-admin-management.onrender.com/login
        """
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        flash('Credentials sent to admin email!', 'success')
    except Exception as e:
        flash(f'Failed to send email: {e}', 'danger')
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/admin/edit/<int:admin_id>', methods=['GET', 'POST'])
def edit_admin(admin_id):
    admin = query_db("SELECT * FROM user WHERE id=? AND role='admin'", [admin_id], one=True)
    if not admin:
        flash('Admin not found!', 'danger')
        return redirect(url_for('superadmin_dashboard'))
    if request.method == 'POST':
        username = request.form['admin_username']
        email = request.form['admin_email']
        password = request.form['admin_password']
        # Check if username is taken by another admin
        existing = query_db("SELECT * FROM user WHERE username=? AND id!=?", [username,admin_id], one=True)
        if existing:
            flash('Username already taken by another admin!', 'danger')
            return redirect(url_for('edit_admin', admin_id=admin_id))
        
        # Check if email is taken by another admin
        existing_email = query_db("SELECT * FROM user WHERE email=? AND id!=?", [email, admin_id], one=True)
        if existing_email:
            flash('Email already taken by another admin!', 'danger')
            return redirect(url_for('edit_admin', admin_id=admin_id))
        # Update admin
        if password.strip():
            hashed_pw = generate_password_hash(password)
            query_db("UPDATE user SET username=?, password=? WHERE id=?", [username, hashed_pw, admin_id], commit=True)
        else:
            query_db("UPDATE user SET username=?, email=? WHERE id=?", [username, email, admin_id], commit=True)
        flash('Admin updated successfully!', 'success')
        return redirect(url_for('superadmin_dashboard'))
    return render_template('edit_admin.html', admin=admin)


@app.route('/admin/task/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    query_db("DELETE FROM task WHERE id = ?", [task_id], commit=True)
    flash('Task deleted successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/task/update/<int:task_id>', methods=['GET', 'POST'])
def update_task(task_id):
    task = query_db("SELECT * FROM task WHERE id = ?", [task_id], one=True)
    departments = query_db("SELECT * FROM department")
    if not task:
        flash('Task not found!')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        project_name = request.form['project_name']
        job_number = request.form['job_number']
        department_id = request.form['department_id']
        job_description = request.form['job_description']
        edc = request.form['edc']
        due_date = request.form['due_date']
        spoc = request.form['spoc']
        completion_percentage = request.form.get('completion_percentage', 0)
        query_db("""
            UPDATE task SET project_name=?, job_number=?, department_id=?, job_description=?, edc=?, due_date=?, spoc=?, completion_percentage=?
            WHERE id=?
        """, [
            project_name, job_number, department_id, job_description,
            edc, due_date, spoc, completion_percentage, task_id
        ], commit=True)
        flash('Task updated successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('update_task.html', task=task, departments=departments)

# --- Discussion ---
@app.route('/discussion', methods=['GET', 'POST'])
def discussion():
    if request.method == 'POST':
        title = request.form.get('new_topic')
        message = request.form.get('message')
        author = session.get('username', 'Anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        query_db("""
            CREATE TABLE IF NOT EXISTS discussion (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                author TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """, commit=True)
        query_db("INSERT INTO discussion (title, message, author, timestamp) VALUES (?, ?, ?, ?)",
                 [title, message, author, timestamp], commit=True)
        flash('Discussion posted!', 'success')
        return redirect(url_for('discussion'))
    query_db("""
        CREATE TABLE IF NOT EXISTS discussion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            author TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """, commit=True)
    discussions = query_db("SELECT * FROM discussion ORDER BY id DESC")
    total_discussions = len(discussions)
    resolved_discussions = len([
        d for d in discussions if (
            (d['title'] and 'resolved' in d['title'].lower()) or
            (d['message'] and 'resolved' in d['message'].lower())
        )
    ])
    discussion_progress = int((resolved_discussions / total_discussions) * 100) if total_discussions else 0
    return render_template('discussion.html', theme=session.get('theme', 'light'), discussions=discussions, discussion_progress=discussion_progress)

# --- Documents ---

from flask import send_file

@app.route('/download_document/<int:doc_id>')
def download_document(doc_id):
    doc = query_db("SELECT * FROM document WHERE id = ?", [doc_id], one=True)
    if not doc:
        flash('Document not found.', 'danger')
        return redirect(url_for('documents'))
    file_path = doc.get('filepath') if 'filepath' in doc else None
    if not file_path or not os.path.exists(file_path):
        flash('File is missing on server.', 'danger')
        return redirect(url_for('documents'))
    return send_file(file_path, as_attachment=True, download_name=doc['filename'])

@app.route('/documents', methods=['GET', 'POST'])
def documents():
    from flask import request, session, redirect, url_for, flash, render_template
    from datetime import datetime
    if request.method == 'POST':
        files = request.files.getlist('files')
        if files:
            uploader = session.get('username', 'Unknown')
            uploaded_at = datetime.now().strftime('%Y-%m-%d %H:%M')
            uploaded_files = []
            for file in files:
                if file.filename == '':
                    continue
                rel_path = file.filename.replace('\\', '/')
                # Check for duplicate by filename
                existing = query_db("SELECT id FROM document WHERE filename = ?", [rel_path], one=True)
                if existing:
                    flash(f"File '{rel_path}' already exists. Skipping.", 'documents')
                    continue
                save_path = os.path.join('uploads', rel_path)
                save_dir = os.path.dirname(save_path)
                os.makedirs(save_dir, exist_ok=True)
                file.save(save_path)
                query_db("INSERT INTO document (filename, uploader, uploaded_at) VALUES (?, ?, ?)", [rel_path, uploader, uploaded_at], commit=True)
                uploaded_files.append(rel_path)
            if uploaded_files:
                flash(f"Uploaded: {', '.join(uploaded_files)}", 'documents')
            else:
                flash('No files uploaded.', 'documents')
            return redirect(url_for('documents'))

    # Ensure document table exists (one-time safety check)
    query_db("""
        CREATE TABLE IF NOT EXISTS document (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            uploader TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
    """, commit=True)
    documents = query_db("SELECT * FROM document ORDER BY id DESC")
    total_documents = len(documents)
    documents_target = 10  # Demo target
    documents_progress = int((total_documents / documents_target) * 100) if documents_target else 0
    if documents_progress > 100:
        documents_progress = 100
    return render_template('documents.html', theme=session.get('theme', 'light'), documents=documents, documents_progress=documents_progress)



# --- Notes ---
@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if request.method == 'POST':
        content = request.form.get('note_content')
        author = session.get('username', 'Anonymous')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        query_db("""
            CREATE TABLE IF NOT EXISTS note (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                author TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """, commit=True)
        query_db("INSERT INTO note (content, author, timestamp) VALUES (?, ?, ?)",
                 [content, author, timestamp], commit=True)
        flash('Note added!', 'success')
        return redirect(url_for('notes'))
    query_db("""
        CREATE TABLE IF NOT EXISTS note (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """, commit=True)
    notes = query_db("SELECT * FROM note ORDER BY id DESC")
    total_notes = len(notes)
    done_notes = len([
        n for n in notes if (
            n['content'] and (
                'done' in n['content'].lower() or 'completed' in n['content'].lower()
            )
        )
    ])
    notes_progress = int((done_notes / total_notes) * 100) if total_notes else 0
    return render_template('notes.html', theme=session.get('theme', 'light'), notes=notes, notes_progress=notes_progress)

@app.route('/notes/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    query_db("DELETE FROM note WHERE id=?", [note_id], commit=True)
    flash('Note deleted!', 'success')
    return redirect(url_for('notes'))

# --- Reports ---
@app.route('/reports')
def reports():
    # Example: Show project/task stats
    reports = query_db("""
        SELECT project_name as project,
               COUNT(*) as total_tasks,
               SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) as completed,
               SUM(CASE WHEN status!='Completed' THEN 1 ELSE 0 END) as pending,
               ROUND(100.0 * SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) / COUNT(*), 2) as progress
        FROM task GROUP BY project_name
    """)
    return render_template('reports.html', theme=session.get('theme', 'light'), reports=reports)

@app.route('/reports/download')
def download_report():
    import csv
    from flask import Response
    reports = query_db("""
        SELECT project_name as project,
               COUNT(*) as total_tasks,
               SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) as completed,
               SUM(CASE WHEN status!='Completed' THEN 1 ELSE 0 END) as pending,
               ROUND(100.0 * SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) / COUNT(*), 2) as progress
        FROM task GROUP BY project_name
    """)
    def generate():
        data = [['Project', 'Tasks', 'Completed', 'Pending', 'Progress']]
        for r in reports:
            data.append([r['project'], r['total_tasks'], r['completed'], r['pending'], r['progress']])
        for row in data:
            yield ','.join(map(str, row)) + '\n'
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=report.csv'})

# --- Users ---
# User management is disabled. The /users route and user add/delete logic have been removed.

# User management is disabled. The /users/delete route has been removed.

# --- Tasks Page ---
@app.route('/tasks')
def tasks():
    filter = request.args.get('filter')
    today = datetime.now().strftime('%Y-%m-%d')
    department_id = session.get('department_id')
    user_name = session.get('username', 'Demo User')
    if not department_id:
        user = query_db("SELECT department_id FROM user WHERE username = ?", [user_name], one=True)
        department_id = user['department_id'] if user and user['department_id'] else None
        if department_id:
            session['department_id'] = department_id

    # Only show tasks for this department
    if department_id:
        if filter == 'assigned':
            tasks = query_db("SELECT task.*, department.name AS department_name FROM task JOIN department ON task.department_id = department.id WHERE task.department_id = ? ORDER BY task.id DESC", [department_id])
        elif filter == 'due_today':
            tasks = query_db("SELECT task.*, department.name AS department_name FROM task JOIN department ON task.department_id = department.id WHERE due_date = ? AND task.department_id = ? ORDER BY task.id DESC", [today, department_id])
        elif filter == 'past_due':
            tasks = query_db("SELECT task.*, department.name AS department_name FROM task JOIN department ON task.department_id = department.id WHERE due_date < ? AND (status IS NULL OR status != 'Completed') AND task.department_id = ? ORDER BY task.id DESC", [today, department_id])
        elif filter == 'completed':
            tasks = query_db("SELECT task.*, department.name AS department_name FROM task JOIN department ON task.department_id = department.id WHERE LOWER(task.status) = 'completed' AND task.department_id = ? ORDER BY task.id DESC", [department_id])
        else:
            tasks = query_db("SELECT task.*, department.name AS department_name FROM task JOIN department ON task.department_id = department.id WHERE task.department_id = ? ORDER BY task.id DESC", [department_id])
    else:
        tasks = []
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t['status'] and t['status'].lower() == 'completed'])
    tasks_progress = int((completed_tasks / total_tasks) * 100) if total_tasks else 0
    return render_template('tasks.html', theme=session.get('theme', 'light'), tasks=tasks, filter=filter, tasks_progress=tasks_progress)

# --- Settings ---
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    from flask import session
    # For demo: get user from session or default
    user = {'profile_name': session.get('username', 'Demo User'),
            'email': 'demo@example.com',
            'notifications': 'enabled',
            'theme': 'light'}
    if request.method == 'POST':
        # Save settings (not persisted in this demo)
        user['profile_name'] = request.form.get('profile_name')
        user['email'] = request.form.get('email')
        user['notifications'] = request.form.get('notifications')
        user['theme'] = request.form.get('theme')
        flash('Settings saved! (Demo only)', 'success')
    return render_template('settings.html', user=user, theme=session.get('theme', 'light'))

@app.route('/logout', methods=['POST'])
def logout():
    from flask import session
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Initialize Database ---
def ensure_task_status_column():
    db = get_db()
    cursor = db.execute("PRAGMA table_info(task)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'status' not in columns:
        db.execute("ALTER TABLE task ADD COLUMN status TEXT DEFAULT 'Pending'")
        db.commit()

from flask import jsonify

@app.route('/api/statistics')
def statistics_api():
    from flask import request, session
    import datetime
    stat_type = request.args.get('type', 'monthly')
    user_name = session.get('username', 'Demo User')
    department_id = session.get('department_id')
    if not department_id:
        user = query_db("SELECT department_id FROM user WHERE username = ?", [user_name], one=True)
        department_id = user['department_id'] if user and user['department_id'] else None
        if department_id:
            session['department_id'] = department_id

    now = datetime.datetime.now()
    if stat_type == 'monthly':
        start_date = now.replace(day=1).strftime('%Y-%m-%d')
    elif stat_type == 'weekly':
        start_date = (now - datetime.timedelta(days=now.weekday())).strftime('%Y-%m-%d')
    elif stat_type == 'mytask':
        # For demo, assume 'spoc' is the username
        if department_id:
            tasks = query_db("SELECT status FROM task WHERE department_id = ? AND spoc = ?", [department_id, user_name])
        else:
            tasks = []
        completed = len([t for t in tasks if t['status'] and t['status'].lower() == 'completed'])
        incomplete = len([t for t in tasks if not t['status'] or t['status'].lower() != 'completed'])
        return jsonify({'completed': completed, 'incomplete': incomplete})
    else:
        return jsonify({'error': 'Invalid type'}), 400

    # For monthly/weekly, filter by due_date
    if department_id:
        tasks = query_db("SELECT status FROM task WHERE department_id = ? AND due_date >= ?", [department_id, start_date])
    else:
        tasks = []
    completed = len([t for t in tasks if t['status'] and t['status'].lower() == 'completed'])
    incomplete = len([t for t in tasks if not t['status'] or t['status'].lower() != 'completed'])
    return jsonify({'completed': completed, 'incomplete': incomplete})

@app.route('/api/reminders/today')
def get_todays_reminders():
    from flask import session
    user_name = session.get('username', 'Demo User')
    today = datetime.now().strftime('%Y-%m-%d')
    reminders = query_db("SELECT reminder_text FROM reminders WHERE username = ? AND reminder_date = ?", [user_name, today])
    return jsonify({'reminders': [r['reminder_text'] for r in reminders]})

@app.route('/api/reminders/add', methods=['POST'])
def add_reminder():
    from flask import request, session
    data = request.get_json()
    user_name = session.get('username', 'Demo User')
    reminder_text = data.get('reminder_text')
    reminder_date = data.get('reminder_date')
    if not reminder_text or not reminder_date:
        return jsonify({'error': 'Missing reminder text or date'}), 400
    query_db("INSERT INTO reminders (username, reminder_text, reminder_date) VALUES (?, ?, ?)", [user_name, reminder_text, reminder_date], commit=True)
    return jsonify({'success': True})

import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/api/upload_task_file', methods=['POST'])
def upload_task_file():
    from flask import request, session
    import os
    from werkzeug.utils import secure_filename
    files = request.files.getlist('files')
    task_id = request.form.get('task_id')
    user_name = session.get('username', 'Demo User')
    if not files or not task_id:
        return {'error': 'Missing files or task_id'}, 400
    uploaded_files = []
    for file in files:
        if file.filename == '':
            continue
        # Use webkitRelativePath if present for folder structure, else filename
        rel_path = getattr(file, 'webkit_relative_path', None) or getattr(file, 'webkitRelativePath', None) or file.filename
        rel_path = rel_path.replace('\\', '/')  # Normalize Windows paths
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], rel_path)
        save_dir = os.path.dirname(save_path)
        os.makedirs(save_dir, exist_ok=True)
        file.save(save_path)
        query_db("INSERT INTO task_uploads (task_id, filename, filepath, uploaded_by) VALUES (?, ?, ?, ?)", [task_id, rel_path, save_path, user_name], commit=True)
        uploaded_files.append(rel_path)
    # Mark the task as completed if at least one file uploaded
    if uploaded_files:
        query_db("UPDATE task SET status = 'Completed' WHERE id = ?", [task_id], commit=True)
    return {'success': True, 'uploaded_files': uploaded_files}

if __name__ == "__main__":
    with app.app_context():
        create_tables()
        ensure_task_status_column()
    app.run(debug=True,port=8000)

