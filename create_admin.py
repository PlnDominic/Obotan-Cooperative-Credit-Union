from app import app, db, User

def create_admin():
    with app.app_context():
        # Check if admin already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            print(f"Admin user already exists with user_id: {existing_admin.user_id}")
            return

        # Create new admin user
        admin = User(
            user_id='ADM240221001',
            username='admin',
            email='admin@obotan.com',
            phone_number='+233000000000',
            role='admin'
        )
        admin.set_password('admin123')
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully')
        print(f'User ID: ADM240221001')
        print(f'Password: admin123')

if __name__ == '__main__':
    create_admin()
