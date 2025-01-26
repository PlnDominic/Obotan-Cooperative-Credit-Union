from app import app, db
from sqlalchemy import text

def update_schema():
    with app.app_context():
        # Drop existing tables
        db.session.execute(text('DROP TABLE IF EXISTS users CASCADE'))
        db.session.execute(text('DROP TABLE IF EXISTS "user" CASCADE'))
        
        # Create new users table with correct schema
        db.session.execute(text('''
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(20) UNIQUE NOT NULL,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                password_hash VARCHAR(500) NOT NULL,
                role VARCHAR(80) NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP WITHOUT TIME ZONE
            )
        '''))
        
        db.session.commit()
        print("Database schema updated successfully!")

if __name__ == '__main__':
    update_schema()
