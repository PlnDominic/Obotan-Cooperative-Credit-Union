from app import app, db, bcrypt
from models import User

def verify_admin():
    with app.app_context():
        # Find admin user
        admin = User.query.filter_by(user_id='ADM240224001').first()
        if admin:
            print("\nAdmin User Found:")
            print("----------------")
            print(f"User ID: {admin.user_id}")
            print(f"Username: {admin.username}")
            print(f"Full Name: {admin.full_name}")
            print(f"Email: {admin.email}")
            print(f"Role: {admin.role}")
            print(f"Password Hash: {admin.password_hash[:50]}...")  # Show first 50 chars of hash
            
            # Test password verification
            test_password = 'admin123'
            is_valid = admin.check_password(test_password)
            print(f"\nPassword Verification Test:")
            print(f"Test Password: {test_password}")
            print(f"Verification Result: {is_valid}")
        else:
            print("No admin user found with ID: ADM240224001")

if __name__ == '__main__':
    verify_admin()
