# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid
from sqlalchemy.dialects.postgresql import JSONB
import random
import string

db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.Column(JSONB, nullable=True)  # Store permissions as JSONB

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Match the table name in the database
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)  # Added full_name field
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(500), nullable=False)
    role = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    
    # Add relationship to WorkEntry
    work_entries = db.relationship('WorkEntry', backref='user', lazy=True, cascade='all, delete-orphan')

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        from app import bcrypt  # Import bcrypt from app
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        from app import bcrypt  # Import bcrypt from app
        return bcrypt.check_password_hash(self.password_hash, password)

    @staticmethod
    def generate_user_id(role):
        # Generate a unique user ID based on role and timestamp
        timestamp = datetime.now().strftime('%y%m%d%H%M')
        role_prefix = {
            'admin': 'ADM',
            'manager': 'MGR',
            'staff': 'STF',
            'user': 'USR'
        }
        prefix = role_prefix.get(role.lower(), 'USR')
        random_suffix = ''.join(random.choices(string.digits, k=4))
        return f"{prefix}{timestamp}{random_suffix}"

    def is_admin(self):
        return self.role.lower() == 'admin'

    def is_manager(self):
        return self.role.lower() == 'manager'

    def is_staff(self):
        return self.role.lower() == 'staff'

class WorkEntry(db.Model):
    __tablename__ = 'work_entries'
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    transaction_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    # Add user relationship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    payment_type = db.Column(db.String(20), nullable=False)  # Added payment type field
    cashbook = db.Column(db.String(50), nullable=True)  # Added cashbook field
    payee_name = db.Column(db.String(150), nullable=True)  # Added payee name field
    cheque_number = db.Column(db.String(50), nullable=True)  # Added cheque number field
    share_code = db.Column(db.String(50), nullable=True)
    share_deposit = db.Column(db.Float, nullable=True, default=0.0)
    share_withdrawal = db.Column(db.Float, nullable=True, default=0.0)
    savings_code = db.Column(db.String(50), nullable=True)
    savings_deposit = db.Column(db.Float, nullable=True, default=0.0)
    savings_withdrawal = db.Column(db.Float, nullable=True, default=0.0)
    loan_code = db.Column(db.String(50), nullable=True)
    principal = db.Column(db.Float, nullable=True, default=0.0)
    interest = db.Column(db.Float, nullable=True, default=0.0)
    mobile = db.Column(db.String(15), nullable=True)
    share_balance = db.Column(db.Float, nullable=True, default=0.0)
    savings_balance = db.Column(db.Float, nullable=True, default=0.0)
    loan_balance = db.Column(db.Float, nullable=True, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

class WorkSubmission(db.Model):
    __tablename__ = 'work_submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    customers_visited = db.Column(db.Integer, nullable=False)
    total_collections = db.Column(db.Float, nullable=False)
    new_accounts = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship
    user = db.relationship('User', backref=db.backref('work_submissions', lazy=True))

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    next_of_kin = db.Column(db.String(150), nullable=False)
    next_of_kin_phone = db.Column(db.String(20), nullable=False)
    initial_deposit = db.Column(db.Float, nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    id_type = db.Column(db.String(50), nullable=False)
    id_number = db.Column(db.String(50), nullable=False)
    passport_photo = db.Column(db.String(255), nullable=False)  # Path to stored passport photo
    id_front_photo = db.Column(db.String(255), nullable=False)  # Path to stored ID front photo
    id_back_photo = db.Column(db.String(255), nullable=False)   # Path to stored ID back photo
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='active')
    share_balance = db.Column(db.Float, nullable=True, default=0.0)
    savings_balance = db.Column(db.Float, nullable=True, default=0.0)
    loan_balance = db.Column(db.Float, nullable=True, default=0.0)

    @staticmethod
    def generate_account_number():
        """Generate an account number in the pattern: 1101, 10301, 101301"""
        # Get total number of customers
        customer_count = Customer.query.count()
        
        # Determine account number based on customer count
        if customer_count == 0:
            return "1101"
        elif customer_count == 1:
            return "10301"
        elif customer_count == 2:
            return "101301"
        else:
            # For subsequent customers, increment from 101301
            new_num = 101301 + (customer_count - 2)
            account_number = str(new_num)
            
            # Verify uniqueness
            while Customer.query.filter_by(account_number=account_number).first():
                new_num += 1
                account_number = str(new_num)
            
            return account_number