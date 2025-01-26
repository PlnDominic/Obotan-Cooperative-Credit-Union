from app import app, db

def update_db():
    with app.app_context():
        # Drop and recreate all tables
        db.drop_all()
        db.create_all()
        print("Database schema updated successfully!")

if __name__ == '__main__':
    update_db()
