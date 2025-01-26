from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import User, db

# Create database engine
engine = create_engine('postgresql://postgres:1234@localhost/obotan')
Session = sessionmaker(bind=engine)
session = Session()

# Get all users
users = session.query(User).all()

print("\nUser Details:")
print("-" * 50)
for user in users:
    print(f"User ID: {user.user_id}")
    print(f"Username: {user.username}")
    print(f"Email: {user.email}")
    print(f"Role: {user.role}")
    print("-" * 50)

session.close()
