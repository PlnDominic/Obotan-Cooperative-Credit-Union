from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import User, db, bcrypt

# Create database engine
engine = create_engine('postgresql://postgres:1234@localhost/obotan')
Session = sessionmaker(bind=engine)
session = Session()

# Get admin user
admin = session.query(User).filter_by(role='admin').first()
if admin:
    # Set new password
    new_password = "Admin@2024"
    admin.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    session.commit()
    print(f"\nPassword reset successfully for admin user:")
    print(f"User ID: {admin.user_id}")
    print(f"Username: {admin.username}")
    print(f"New Password: {new_password}")

# Get teller user
teller = session.query(User).filter_by(role='teller').first()
if teller:
    # Set new password
    new_password = "Teller@2024"
    teller.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    session.commit()
    print(f"\nPassword reset successfully for teller user:")
    print(f"User ID: {teller.user_id}")
    print(f"Username: {teller.username}")
    print(f"New Password: {new_password}")

# Get mobile banker user
mobile_banker = session.query(User).filter_by(role='mobile_banker').first()
if mobile_banker:
    # Set new password
    new_password = "Mobile@2024"
    mobile_banker.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    session.commit()
    print(f"\nPassword reset successfully for mobile banker user:")
    print(f"User ID: {mobile_banker.user_id}")
    print(f"Username: {mobile_banker.username}")
    print(f"New Password: {new_password}")

session.close()
