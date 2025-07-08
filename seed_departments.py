from app import app
from models import db, Department

with app.app_context():
    departments = [
        'IT Department',
        'Marketing Department',
        'Advertising Department',
        'Designing Department',
        'Testing Department'
    ]
    for name in departments:
        if not Department.query.filter_by(name=name).first():
            db.session.add(Department(name=name))
    db.session.commit()
    print("Departments added!")
