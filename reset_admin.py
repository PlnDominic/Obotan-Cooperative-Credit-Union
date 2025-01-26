from app import app, db
from models import User

def reset_admin():
    with app.app_context():
        # Delete existing admin
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            db.session.delete(existing_admin)
            db.session.commit()
            print("Existing admin user deleted")

        # Create new admin user
        new_password = 'admin123'  # Simpler password for testing
        new_admin = User(
            user_id='ADM240224001',  # New admin ID
            username='admin',
            full_name='Bless Yao Agbemawle',
            email='agbemawlebless@gmail.com',
            phone_number='0241056416',
            role='admin'
        )
        
        # Set password using the model's method
        new_admin.set_password(new_password)
        
        # Add to database
        db.session.add(new_admin)
        db.session.commit()
        
        print('\nNew admin user created successfully')
        print('-----------------------------------')
        print(f'User ID: ADM240224001')
        print(f'Username: admin')
        print(f'Password: {new_password}')
        print('-----------------------------------')
        print('\nPlease save these credentials securely and change the password after first login.')

if __name__ == '__main__':
    reset_admin()
