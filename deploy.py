import os
import sys
import traceback
import psycopg2

# Ensure the project root is in the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()
load_dotenv('.env.local')

def test_database_connection():
    try:
        # Hardcode the Render PostgreSQL URL
        database_url = 'postgresql://obotan_user:DzPV4roNETYpZqCiP7OUyhZ2yt6iXXY2@dpg-cubb26qn91rc7392ehkg-a.oregon-postgres.render.com/obotan'
        
        print(f"Attempting to connect to: {database_url}")
        
        # Establish connection
        conn = psycopg2.connect(database_url, sslmode='require')
        cursor = conn.cursor()
        
        # Execute a simple query
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        
        print("Database connection successful!")
        print("Test query result:", result)
        
        cursor.close()
        conn.close()
        
        return True
    
    except Exception as e:
        print("Database connection error:")
        print(traceback.format_exc())
        return False

def check_users():
    try:
        from app import app, db
        from models import User
        
        with app.app_context():
            # Query all users
            users = User.query.all()
            
            if not users:
                print("No users found in the database.")
                return False
            
            print("Existing Users:")
            print("-" * 50)
            for user in users:
                print(f"User ID: {user.user_id}")
                print(f"Username: {user.username}")
                print(f"Email: {user.email}")
                print(f"Role: {user.role}")
                print(f"Is Active: {user.is_active}")
                print("-" * 50)
            
            return True
    
    except Exception as e:
        print("Error checking users:")
        print(traceback.format_exc())
        return False

def main():
    print("Starting deployment verification...")
    
    # Test database connection
    db_connection = test_database_connection()
    
    # Check users
    users_check = check_users()
    
    if db_connection and users_check:
        print("Deployment verification successful!")
        return 0
    else:
        print("Deployment verification failed.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
