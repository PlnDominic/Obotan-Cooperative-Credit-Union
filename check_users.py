from app import app, db
from models import User

with app.app_context():
    # Query all users
    users = User.query.all()
    
    print("Existing Users:")
    print("-" * 50)
    for user in users:
        print(f"User ID: {user.user_id}")
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        print(f"Role: {user.role}")
        print(f"Is Active: {user.is_active}")
        print("-" * 50)
    
    if not users:
        print("No users found in the database.")
