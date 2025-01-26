from app import app, db, User, WorkEntry, Role
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db():
    with app.app_context():
        # Drop all existing tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user
        admin = User(
            user_id='ADM' + datetime.now().strftime('%y%m%d%H%M') + '001',
            username='admin',
            email='admin@obotan.com',
            phone_number='+233000000000',
            role='admin',
            is_active=True
        )
        admin.set_password('admin123')
        
        # Create test teller
        teller = User(
            user_id='TLR' + datetime.now().strftime('%y%m%d%H%M') + '001',
            username='teller1',
            email='teller1@obotan.com',
            phone_number='+233111111111',
            role='bank_teller',
            is_active=True
        )
        teller.set_password('teller123')
        
        # Create test mobile banker
        mobile_banker = User(
            user_id='MBK' + datetime.now().strftime('%y%m%d%H%M') + '001',
            username='mobile1',
            email='mobile1@obotan.com',
            phone_number='+233222222222',
            role='mobile_banker',
            is_active=True
        )
        mobile_banker.set_password('mobile123')
        
        # Add users to session
        db.session.add(admin)
        db.session.add(teller)
        db.session.add(mobile_banker)
        
        # Commit the session to get user IDs
        db.session.commit()
        
        # Create some test transactions for teller
        test_entry1 = WorkEntry(
            user_id=teller.id,
            name='John Doe',
            account_number='ACC001',
            amount=1000.00,
            share_code='SHR001',
            share_deposit=200.00,
            savings_code='SAV001',
            savings_deposit=700.00,
            loan_code='LN001',
            principal=100.00,
            interest=10.00,
            mobile='+233333333333',
            share_balance=1200.00,
            savings_balance=2700.00,
            loan_balance=900.00
        )
        
        # Create some test transactions for mobile banker
        test_entry2 = WorkEntry(
            user_id=mobile_banker.id,
            name='Jane Smith',
            account_number='ACC002',
            amount=1500.00,
            share_code='SHR002',
            share_deposit=300.00,
            savings_code='SAV002',
            savings_deposit=1000.00,
            loan_code='LN002',
            principal=200.00,
            interest=20.00,
            mobile='+233444444444',
            share_balance=1800.00,
            savings_balance=3200.00,
            loan_balance=1800.00
        )
        
        # Add test entries
        db.session.add(test_entry1)
        db.session.add(test_entry2)
        
        # Commit all changes
        db.session.commit()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
