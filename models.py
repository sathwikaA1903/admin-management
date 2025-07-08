from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Add other user fields as needed

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    
    
#class Task(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    #project = db.Column(db.String(100), nullable=False)
    #task_name = db.Column(db.String(100), nullable=False)
    #allocated_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    #due_date = db.Column(db.Date, nullable=False)
    #status = db.Column(db.String(20), default='Pending')
    #user = db.relationship('User', backref='tasks')
    
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    job_number = db.Column(db.String(50), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    job_description = db.Column(db.Text, nullable=False)
    edc = db.Column(db.Date, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    spoc = db.Column(db.String(100), nullable=False)  # Single Point of Contact
    department = db.relationship('Department', backref='tasks')
