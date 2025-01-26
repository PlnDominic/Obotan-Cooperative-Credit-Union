from app import app, db, bcrypt
from models import User

def create_admin():
    with app.app_context():
        # Delete existing admin users
        existing_admins = User.query.filter_by(role='admin').all()
        for admin in existing_admins:
            db.session.delete(admin)
        
        # Create new admin user
        admin = User(
            user_id='ADM240226001',  # Updated user ID
            username='systemadmin',  # Changed username
            email='admin@obotan.com',
            full_name='System Administrator',
            phone_number='+233000000000',
            role='admin',
            is_active=True
        )
        
        # Set a strong password
        admin.set_password('Obotan2024!Admin')
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully')
        print(f'User ID: ADM240226001')
        print(f'Username: systemadmin')
        print(f'Password: Obotan2024!Admin')

if __name__ == '__main__':
    create_admin()
