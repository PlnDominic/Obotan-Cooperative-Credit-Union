# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, ValidationError
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, desc, text, extract
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, FloatField, DateField, TextAreaField, SubmitField, DateTimeField, SelectField, IntegerField
from wtforms.validators import DataRequired
import json
import os
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
import secrets
from functools import wraps
from models import db, User, Role, WorkEntry, Customer, WorkSubmission  # Import all models
import re
import dotenv
import logging
from logging.handlers import RotatingFileHandler

# Load environment variables
import os
from dotenv import load_dotenv

# Priority: .env.local > .env.production > .env
if os.path.exists('.env.local'):
    load_dotenv('.env.local', override=True)
elif os.path.exists('.env.production'):
    load_dotenv('.env.production', override=True)
else:
    load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Enhanced Logging Configuration
def setup_logging():
    # Ensure logs directory exists
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    log_file = os.path.join(log_dir, 'app.log')
    handler = RotatingFileHandler(log_file, maxBytes=100000, backupCount=5)
    handler.setLevel(logging.DEBUG)
    
    # Create a logging format with CRITICAL emphasis
    formatter = logging.Formatter(
        '!!! CRITICAL !!! %(asctime)s - %(name)s - %(levelname)s - '
        'File: %(filename)s - Line: %(lineno)d - Message: %(message)s'
    )
    handler.setFormatter(formatter)
    
    # Console handler for immediate visibility
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(formatter)
    
    # Add handlers to the app's logger
    app.logger.addHandler(handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.DEBUG)

    # Print to stdout for Render logs
    print("Logging setup complete. Logging to:", log_file)

# Call logging setup
setup_logging()

# Security configurations
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:1234@localhost/obotan')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = os.getenv('DEBUG', 'False') == 'True'

# Production-specific security settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

# CSRF Protection
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = app.config['SECRET_KEY']  # Use same secret key for CSRF
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = False  # Disable SSL-only CSRF tokens for development
app.config['WTF_CSRF_CHECK_DEFAULT'] = True  # Enable CSRF protection by default

migrate = Migrate(app, db) 
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated
login_manager.session_protection = 'strong'  # Enable Flask-Login's session protection

# Initialize the db from models.py
db.init_app(app)

# Initialize Flask-Mail with environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# Configure upload folder and allowed extensions
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directories
for subfolder in ['passport_photos', 'id_photos', 'profile_pictures']:
    os.makedirs(os.path.join(UPLOAD_FOLDER, subfolder), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file, subfolder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        unique_filename = f"{timestamp}_{random_string}_{filename}"
        
        # Create relative path for database storage
        db_path = f'uploads/{subfolder}/{unique_filename}'
        
        # Create full path for file saving
        save_path = os.path.join(app.static_folder, 'uploads', subfolder)
        os.makedirs(save_path, exist_ok=True)
        
        # Save the file
        file_path = os.path.join(save_path, unique_filename)
        file.save(file_path)
        print(f"Saved file to: {file_path}")
        print(f"Database path: {db_path}")
        
        return db_path
    return None

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Define the form class
class LoginForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    remember = SelectField('Remember Me', choices=[(True, 'Yes'), (False, 'No')], default=False)

class WorkEntryForm(FlaskForm):
    # Basic Information
    member_id = StringField('Account Number', validators=[DataRequired()])
    member_name = StringField('Member Name')
    phone = StringField('Phone Number')
    transaction_date = DateField('Transaction Date', validators=[DataRequired()])
    
    # Share Account
    share_code = StringField('Share Code')
    share_deposit = FloatField('Share Deposit', default=0)
    share_balance = FloatField('Share Balance')
    share_withdrawal = FloatField('Share Withdrawal', default=0)
    share_withdrawal_code = StringField('Share Withdrawal Code')
    
    # Savings Account
    savings_code = StringField('Savings Code')
    savings_deposit = FloatField('Savings Deposit', default=0)
    savings_balance = FloatField('Savings Balance')
    savings_withdrawal = FloatField('Savings Withdrawal', default=0)
    savings_withdrawal_code = StringField('Savings Withdrawal Code')
    payment_type = SelectField('Payment Type', 
                             choices=[('', 'Select Payment Type'),
                                    ('cash', 'Cash'),
                                    ('cheque', 'Cheque'),
                                    ('mobile_money', 'Mobile Money')])
    
    # Loan Account
    loan_code = StringField('Loan Code')
    principal = FloatField('Principal', default=0)
    interest = FloatField('Interest', default=0)
    loan_balance = FloatField('Loan Balance')
    
    # Withdrawal Information
    withdrawal_charges = FloatField('Withdrawal Charges', default=0)
    payee_name = StringField('Payee Name')
    cheque_number = StringField('Cheque Number')
    cashbook = SelectField('Cashbook',
                          choices=[('', 'Select Cashbook'),
                                 ('cash', 'Cash'),
                                 ('bank', 'Bank')])
    detail_narration = TextAreaField('Detail Narration')
    
    # Totals
    total_amount = FloatField('Total Amount')
    total_withdrawal_amount = FloatField('Total Withdrawal Amount')

class WorkEntryFormFull(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    description = TextAreaField('Description')
    payment_type = SelectField('Payment Type', 
                             choices=[('cash', 'Cash'), 
                                    ('cheque', 'Cheque'), 
                                    ('mobile_money', 'Mobile Money')],
                             validators=[DataRequired()])
    share_code = StringField('Share Code')  # Removed DataRequired validator
    share_deposit = FloatField('Share Deposit', default=0.0)  # Removed DataRequired validator
    savings_code = StringField('Savings Code', validators=[DataRequired()])
    savings_deposit = FloatField('Savings Deposit', validators=[DataRequired()])
    loan_code = StringField('Loan Code', validators=[DataRequired()])
    principal = FloatField('Principal', validators=[DataRequired()])
    interest = FloatField('Interest', validators=[DataRequired()])
    date = DateTimeField('Date', format='%Y-%m-%d %H:%M:%S', default=datetime.now(timezone.utc), validators=[DataRequired()])
    receipt_no = StringField('Receipt No', validators=[DataRequired()])
    amount_paid = FloatField('Amount Paid', validators=[DataRequired()])
    last_payment_date = DateTimeField('Date', format='%Y-%m-%d %H:%M:%S', default=datetime.now(timezone.utc), validators=[DataRequired()])
    received_from = StringField('Received From', validators=[DataRequired()])
    mobile = StringField('Mobile', validators=[DataRequired()])
    share_balance = FloatField('Share Balance', validators=[DataRequired()])
    savings_balance = FloatField('Savings Balance', validators=[DataRequired()])
    loan_balance = FloatField('Loan Balance', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Define the form class for work submission
class WorkSubmissionForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    customers_visited = IntegerField('Customers Visited', validators=[DataRequired()])
    total_collections = FloatField('Total Collections', validators=[DataRequired()])
    new_accounts = IntegerField('New Accounts', validators=[DataRequired()])
    notes = TextAreaField('Notes')
    submit = SubmitField('Submit Report')

class UserForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('manager', 'Manager'), ('teller', 'Teller'), ('mobile_banker', 'Mobile Banker')], validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    submit = SubmitField('Create User')

class DailyWithdrawalForm(FlaskForm):
    account_no = StringField('Account No', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    reference = StringField('Reference', validators=[DataRequired()])
    share_code = SelectField('Share Code', choices=[('D6', 'D6')], default='D6')
    saving_code = SelectField('Saving Code', choices=[('H5', 'H5')], default='H5')
    withdrawal_mode = SelectField('Withdrawal Mode', 
                                choices=[('', 'Select Mode'),
                                        ('cash', 'Cash'),
                                        ('cheque', 'Cheque'),
                                        ('mobile_money', 'Mobile Money')],
                                validators=[DataRequired()])
    payment = FloatField('Payment', validators=[DataRequired()])
    cash_book = SelectField('Cash Book',
                          choices=[('', 'Select Cash Book'),
                                 ('cash', 'Cash'),
                                 ('bank', 'Bank')],
                          validators=[DataRequired()])
    detail_narration = TextAreaField('Detail/Narration', validators=[DataRequired()])

# User model is now imported from models.py

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database connection verification
def verify_database_connection():
    try:
        # Attempt to create a connection and perform a simple query
        with app.app_context():
            result = db.session.execute('SELECT 1').scalar()
            app.logger.info(f"Database connection verified. Test query result: {result}")
            return True
    except Exception as e:
        app.logger.error(f"Database connection error: {str(e)}", exc_info=True)
        return False

# Call database verification on app startup
verify_database_connection()

# Database connection
def get_db_connection():
    conn = psycopg2.connect("dbname='obotan' user='postgres' password='1234' host='localhost'")
    return conn

# Role-based access control decorator
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Middleware to generate a nonce for each request
@app.before_request
def generate_nonce():
    if 'nonce' not in session:
        session['nonce'] = secrets.token_hex(16)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Log all request details
    app.logger.debug(f"Login Request Method: {request.method}")
    app.logger.debug(f"Request Form Data: {request.form}")
    app.logger.debug(f"Request Args: {request.args}")
    app.logger.debug(f"Session Data: {dict(session)}")

    # Temporarily disable CSRF protection for debugging
    app.config['WTF_CSRF_ENABLED'] = False
    
    if current_user.is_authenticated:
        app.logger.info("User already authenticated, redirecting to dashboard")
        return redirect(url_for('dashboard'))

    form = LoginForm()
    
    # Log form validation details
    app.logger.debug(f"Form Errors: {form.errors}")
    app.logger.debug(f"Form Data: {form.data}")

    if form.validate_on_submit():
        try:
            user_id = form.user_id.data
            password = form.password.data
            app.logger.info(f"Login attempt - User ID: {user_id}")
            
            # Detailed database query logging
            app.logger.debug(f"Attempting to find user with ID: {user_id}")
            user = User.query.filter_by(user_id=user_id).first()
            
            if user:
                app.logger.info(f"User found - Username: {user.username}, Full Name: {user.full_name}")
                
                # Log additional user details
                app.logger.debug(f"User Details: {user.__dict__}")
                
                if not user.is_active:
                    app.logger.warning(f"Login attempt for inactive user: {user_id}")
                    flash('This account has been deactivated. Please contact an administrator.', 'error')
                    return render_template('login.html', form=form)
                
                # Detailed password checking
                app.logger.debug("Attempting password check")
                is_valid = user.check_password(password)
                app.logger.info(f"Password check result: {is_valid}")
                
                if is_valid:
                    # Update last login time
                    user.last_login = datetime.now(timezone.utc)
                    db.session.commit()
                    
                    # Remember me functionality
                    remember = form.remember.data == 'True'
                    login_user(user, remember=remember)
                    app.logger.info(f"User {user_id} logged in successfully")
                    flash('Logged in successfully!', 'success')
                    
                    # Get the next page from args, fallback to referrer, then dashboard
                    next_page = request.args.get('next')
                    if not next_page or not next_page.startswith('/'):
                        next_page = request.referrer
                    if not next_page:
                        next_page = url_for('dashboard')
                    
                    app.logger.info(f"Redirecting to: {next_page}")
                    return redirect(next_page)
                else:
                    app.logger.warning(f"Invalid password for user: {user_id}")
            else:
                app.logger.warning(f"User not found: {user_id}")
            
            flash('Invalid user ID or password.', 'error')
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.', 'error')

    return render_template('login.html', form=form)

# Route to add a new user
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])  # Only admin can add users
def add_user():
    if request.method == 'POST':
        try:
            # Get form data
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            role = request.form.get('role')
            password = request.form.get('password')

            # Validate required fields
            if not all([full_name, email, phone, role, password]):
                flash('All fields are required', 'error')
                return redirect(url_for('manage_users'))

            # Check if email already exists
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
                return redirect(url_for('manage_users'))

            # Validate Ghanaian phone number (should start with +233 or 0 followed by 9 digits)
            phone_pattern = r'^(?:\+233|0)\d{9}$'
            if not re.match(phone_pattern, phone):
                flash('Please enter a valid Ghanaian phone number (+233XXXXXXXXX or 0XXXXXXXXX)', 'error')
                return redirect(url_for('manage_users'))

            # Generate username from full name (first letter of first name + last name)
            names = full_name.lower().split()
            username = (names[0][0] + names[-1]).replace(' ', '')
            
            # Ensure username is unique by adding numbers if necessary
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1

            # Generate user_id based on role
            timestamp = datetime.now().strftime('%y%m%d%H%M')
            role_prefix = {'admin': 'ADM', 'teller': 'TLR', 'mobile_banker': 'MBK'}
            user_id = f"{role_prefix.get(role, 'USR')}{timestamp}"

            # Create new user
            new_user = User(
                user_id=user_id,
                username=username,
                full_name=full_name,  # Add full_name field
                email=email,
                phone_number=phone,
                role=role,
                is_active=True,
                created_at=datetime.utcnow()
            )
            new_user.set_password(password)  # Use the set_password method from the User model

            db.session.add(new_user)
            db.session.commit()
            flash(f'User created successfully. Username: {username}', 'success')
            return redirect(url_for('manage_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('manage_users'))

    return render_template('manage_users.html', users=User.query.all(), today=datetime.now(), nonce=session.get('nonce'))

# Route to manage users
@app.route('/manage_users')
@login_required
@role_required(['admin', 'manager'])  # Only admin and manager can manage users
def manage_users():
    users = User.query.all()
    form = UserForm()  # Create form instance
    return render_template('manage_users.html', users=users, form=form, today=datetime.now(), nonce=session.get('nonce'))

# Route to edit a user
@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin', 'manager'])  # Only admin and manager can edit users
def edit_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Update user information
        user.username = request.form.get('name')
        user.email = request.form.get('email')
        user.phone_number = request.form.get('phone')
        user.role = request.form.get('role')
        user.is_active = request.form.get('is_active') == '1'
        
        # Update password if provided
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = generate_password_hash(new_password)
        
        # Update timestamp
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('manage_users'))

# Route to delete a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin'])  # Only admin can delete users
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Don't allow deleting the admin user
        if user.role == 'admin':
            flash('Cannot delete admin user.', 'danger')
            return redirect(url_for('manage_users'))
        
        # Store user info for flash message
        user_info = f"{user.username} ({user.user_id})"
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User {user_info} has been deleted successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('manage_users'))

# Profile management routes
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        try:
            # Get the form data
            username = request.form.get('username')
            email = request.form.get('email')
            
            # Check if username or email already exists for another user
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email),
                User.id != current_user.id
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    flash('Username already taken.', 'error')
                else:
                    flash('Email already registered.', 'error')
                return redirect(url_for('settings'))
            
            # Update user information
            current_user.full_name = request.form.get('full_name')
            current_user.username = username
            current_user.email = email
            current_user.phone_number = request.form.get('phone_number')
            current_user.bio = request.form.get('bio')
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
            
    return redirect(url_for('settings'))

@app.route('/update_profile_picture', methods=['POST'])
@login_required
def update_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'})
        
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
        
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            # Save file with user ID in filename to avoid conflicts
            filename = f'profile_picture_{current_user.id}_{filename}'
            filepath = save_uploaded_file(file, 'profile_pictures')
            
            current_user.profile_picture = filepath
            db.session.commit()
            
            return jsonify({
                'success': True,
                'picture_url': url_for('serve_static', filename=filepath)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
            
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('settings'))
            
        # Validate new password
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('settings'))
            
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long', 'error')
            return redirect(url_for('settings'))
            
        try:
            current_user.set_password(new_password)
            current_user.updated_at = datetime.utcnow()
            db.session.commit()
            flash('Password changed successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error changing password: {str(e)}', 'error')
            
    return redirect(url_for('settings'))

# User logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Update settings route to include user data
@app.route('/settings')
@login_required
@role_required(['admin', 'manager', 'teller', 'mobile_banker'])  # Allow all authenticated users to access settings
def settings():
    today = datetime.now()
    return render_template('settings.html', today=today, nonce=session.get('nonce'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        today = datetime.now().date()
        
        # Get all transactions first
        all_transactions = WorkEntry.query.order_by(WorkEntry.created_at.desc()).all()
        
        # Get today's transactions
        today_transactions = WorkEntry.query.filter(
            db.cast(WorkEntry.transaction_date, db.Date) == today
        ).all()
        
        # Calculate totals for today
        total_deposits = sum(float(t.savings_deposit or 0) for t in today_transactions)
        total_withdrawals = sum(float(t.savings_withdrawal or 0) for t in today_transactions)
        total_share_deposits = sum(float(t.share_deposit or 0) for t in today_transactions)
        total_share_withdrawals = sum(float(t.share_withdrawal or 0) for t in today_transactions)
        total_loan_payments = sum(float(t.principal or 0) + float(t.interest or 0) for t in today_transactions)
        
        daily_totals = {
            'share_deposits': total_share_deposits,
            'savings_deposits': total_deposits,
            'share_withdrawals': total_share_withdrawals,
            'savings_withdrawals': total_withdrawals,
            'loan_payments': total_loan_payments,
            'total_transactions': len(today_transactions)
        }
        
        # Get recent transactions
        recent_transactions = WorkEntry.query.order_by(WorkEntry.created_at.desc()).limit(10).all()
        
        # Format transaction data
        transactions_data = []
        for transaction in recent_transactions:
            # Determine transaction type and amount
            if transaction.share_deposit and float(transaction.share_deposit) > 0:
                transaction_type = 'Share Deposit'
                amount = float(transaction.share_deposit)
            elif transaction.savings_deposit and float(transaction.savings_deposit) > 0:
                transaction_type = 'Savings Deposit'
                amount = float(transaction.savings_deposit)
            elif transaction.share_withdrawal and float(transaction.share_withdrawal) > 0:
                transaction_type = 'Share Withdrawal'
                amount = float(transaction.share_withdrawal)
            elif transaction.savings_withdrawal and float(transaction.savings_withdrawal) > 0:
                transaction_type = 'Savings Withdrawal'
                amount = float(transaction.savings_withdrawal)
            elif transaction.principal or transaction.interest:
                transaction_type = 'Loan Payment'
                amount = float(transaction.principal or 0) + float(transaction.interest or 0)
            else:
                transaction_type = 'Other'
                amount = float(transaction.amount or 0)
            
            transactions_data.append({
                'date': transaction.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'account_number': transaction.account_number,
                'name': transaction.name,
                'type': transaction_type,
                'amount': "₵{:,.2f}".format(amount),
                'balance': "₵{:,.2f}".format(float(transaction.savings_balance or 0))
            })
        
        # Get teller performance data
        teller_performance = []
        tellers = User.query.filter(User.role.in_(['staff', 'manager'])).all()
        
        for teller in tellers:
            teller_transactions = WorkEntry.query.filter(
                WorkEntry.user_id == teller.id,
                db.cast(WorkEntry.transaction_date, db.Date) == today
            ).all()
            
            if len(teller_transactions) > 0:  # Only include tellers with transactions
                performance = {
                    'username': teller.full_name,
                    'transaction_count': len(teller_transactions),
                    'share_deposits': sum(float(t.share_deposit or 0) for t in teller_transactions),
                    'savings_deposits': sum(float(t.savings_deposit or 0) for t in teller_transactions),
                    'share_withdrawals': sum(float(t.share_withdrawal or 0) for t in teller_transactions),
                    'savings_withdrawals': sum(float(t.savings_withdrawal or 0) for t in teller_transactions)
                }
                teller_performance.append(performance)
        
        # Get mobile banker performance data
        mobile_performance = []
        mobile_bankers = User.query.filter(User.role == 'staff').all()
        
        for banker in mobile_bankers:
            banker_transactions = WorkEntry.query.filter(
                WorkEntry.user_id == banker.id,
                WorkEntry.mobile.isnot(None),
                db.cast(WorkEntry.transaction_date, db.Date) == today
            ).all()
            
            if len(banker_transactions) > 0:  # Only include bankers with transactions
                performance = {
                    'username': banker.full_name,
                    'transaction_count': len(banker_transactions),
                    'share_deposits': sum(float(t.share_deposit or 0) for t in banker_transactions),
                    'savings_deposits': sum(float(t.savings_deposit or 0) for t in banker_transactions),
                    'share_withdrawals': sum(float(t.share_withdrawal or 0) for t in banker_transactions),
                    'savings_withdrawals': sum(float(t.savings_withdrawal or 0) for t in banker_transactions)
                }
                mobile_performance.append(performance)
        
        return render_template('dashboard.html',
                             today=today,
                             daily_totals=daily_totals,
                             total_deposits="{:,.2f}".format(total_deposits),
                             total_withdrawals="{:,.2f}".format(total_withdrawals),
                             total_share_deposits="{:,.2f}".format(total_share_deposits),
                             total_share_withdrawals="{:,.2f}".format(total_share_withdrawals),
                             total_loan_payments="{:,.2f}".format(total_loan_payments),
                             transactions=transactions_data,
                             teller_performance=teller_performance,
                             mobile_performance=mobile_performance,
                             nonce=session.get('nonce'))
                             
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('dashboard.html', 
                             today=datetime.now().date(),
                             daily_totals={'share_deposits': 0, 'savings_deposits': 0, 
                                         'share_withdrawals': 0, 'savings_withdrawals': 0,
                                         'loan_payments': 0, 'total_transactions': 0},
                             transactions=[],
                             teller_performance=[],
                             mobile_performance=[],
                             nonce=session.get('nonce'))

@app.route('/account_opening', methods=['GET', 'POST'])
@login_required
def account_opening():
    if request.method == 'POST':
        # Handle form submission
        member_data = {
            'full_name': request.form.get('full_name'),
            'dob': request.form.get('dob'),
            'gender': request.form.get('gender'),
            'marital_status': request.form.get('marital_status'),
            'phone': request.form.get('phone'),
            'email': request.form.get('email'),
            'address': request.form.get('address'),
            'occupation': request.form.get('occupation'),
            'id_type': request.form.get('id_type'),
            'id_number': request.form.get('id_number'),
            'next_of_kin_name': request.form.get('next_of_kin_name'),
            'next_of_kin_phone': request.form.get('next_of_kin_phone'),
            'next_of_kin_relationship': request.form.get('next_of_kin_relationship'),
            'account_type': request.form.get('account_type'),
            'initial_deposit': request.form.get('initial_deposit')
        }
        
        # TODO: Save to database
        flash('Account created successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('account_opening.html', nonce=session.get('nonce'))

@app.route('/create_customer', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'teller'])  # Only admin, manager, and teller can create customers
def create_customer():
    form = FlaskForm()  # Create a basic form for CSRF protection
    today = datetime.now()
    if request.method == 'POST':
        try:
            # Check if email already exists (if provided)
            email = request.form.get('email', '').strip()
            if email:
                existing_customer = Customer.query.filter_by(email=email).first()
                if existing_customer:
                    flash('A customer with this email address already exists.', 'danger')
                    return redirect(url_for('create_customer'))

            # Handle file uploads
            passport_photo = request.files.get('passport_photo')
            id_front_photo = request.files.get('id_front_photo')
            id_back_photo = request.files.get('id_back_photo')

            # Save uploaded files
            passport_photo_path = save_uploaded_file(passport_photo, 'passport_photos') if passport_photo else None
            id_front_path = save_uploaded_file(id_front_photo, 'id_photos') if id_front_photo else None
            id_back_path = save_uploaded_file(id_back_photo, 'id_photos') if id_back_photo else None

            # Generate account number
            account_number = Customer.generate_account_number()

            # Create new customer
            new_customer = Customer(
                account_number=account_number,
                full_name=request.form['full_name'],
                date_of_birth=datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d'),
                gender=request.form['gender'],
                phone_number=request.form['phone_number'],
                email=email if email else None,  # Set to None if empty string
                address=request.form['residential_address'],
                occupation=request.form['occupation'],
                next_of_kin=request.form['next_of_kin'],
                next_of_kin_phone=request.form['next_of_kin_phone'],
                id_type=request.form['id_type'],
                id_number=request.form['id_number'],
                account_type=request.form['account_type'],
                initial_deposit=float(request.form['initial_deposit']),
                status='active',
                passport_photo=passport_photo_path,
                id_front_photo=id_front_path,
                id_back_photo=id_back_path,
                created_at=datetime.utcnow(),
                created_by=current_user.id
            )

            db.session.add(new_customer)
            db.session.commit()

            flash('Customer created successfully!', 'success')
            return redirect(url_for('view_customers'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating customer: {str(e)}', 'danger')
            return redirect(url_for('create_customer'))

    return render_template('create_customer.html', form=form, today=today, nonce=session.get('nonce'))

@app.route('/view_customers')
@login_required
@role_required(['admin', 'manager', 'teller'])  # Only admin, manager, and teller can view customers
def view_customers():
    try:
        today = datetime.now()
        customers = Customer.query.all()
        customer_data = []
        
        for customer in customers:
            # Calculate total deposits and withdrawals
            transactions = WorkEntry.query.filter_by(account_number=customer.account_number).all()
            
            # Get initial deposit
            initial_deposit = float(customer.initial_deposit) if customer.initial_deposit else 0
            
            # Calculate total deposits and withdrawals
            total_deposits = sum(float(entry.savings_deposit) for entry in transactions if entry.savings_deposit)
            total_withdrawals = sum(float(entry.savings_withdrawal) for entry in transactions if entry.savings_withdrawal)
            
            # Calculate final account balance
            account_balance = initial_deposit + total_deposits - total_withdrawals
            
            customer_dict = {
                'id': customer.id,
                'account_number': customer.account_number,
                'full_name': customer.full_name,
                'phone_number': customer.phone_number,
                'email': customer.email,
                'account_balance': account_balance,
                'status': customer.status
            }
            customer_data.append(customer_dict)
        
        return render_template('customers.html', customers=customer_data, today=today, nonce=session.get('nonce'))
    except Exception as e:
        app.logger.error(f"Error in view_customers: {str(e)}")
        flash('An error occurred while loading customers.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/customer/<int:customer_id>')
@login_required
@role_required(['admin', 'manager', 'teller'])  # Only admin, manager, and teller can view customer details
def view_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    today = datetime.now()
    return render_template('customer_details.html', customer=customer, today=today, nonce=session.get('nonce'))

@app.route('/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'teller'])  # Only admin, manager, and teller can edit customers
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    form = FlaskForm()  # Create a basic form for CSRF protection
    today = datetime.now()
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Update customer information
            customer.full_name = request.form['full_name']
            customer.phone_number = request.form['phone_number']
            customer.email = request.form['email']
            customer.address = request.form['address']
            customer.occupation = request.form['occupation']
            customer.next_of_kin = request.form['next_of_kin']
            customer.next_of_kin_phone = request.form['next_of_kin_phone']
            customer.id_number = request.form['id_number']
            customer.status = request.form['status']
            
            # Handle optional file uploads
            passport_photo = request.files.get('passport_photo')
            id_front_photo = request.files.get('id_front_photo')
            id_back_photo = request.files.get('id_back_photo')
            
            if passport_photo and allowed_file(passport_photo.filename):
                passport_path = save_uploaded_file(passport_photo, 'passport_photos')
                if passport_path:
                    customer.passport_photo = passport_path
                    
            if id_front_photo and allowed_file(id_front_photo.filename):
                id_front_path = save_uploaded_file(id_front_photo, 'id_photos')
                if id_front_path:
                    customer.id_front_photo = id_front_path
                    
            if id_back_photo and allowed_file(id_back_photo.filename):
                id_back_path = save_uploaded_file(id_back_photo, 'id_photos')
                if id_back_path:
                    customer.id_back_photo = id_back_path
            
            customer.updated_at = datetime.utcnow()
            customer.updated_by = current_user.id
            db.session.commit()
            flash('Customer details updated successfully!', 'success')
            return redirect(url_for('view_customer', customer_id=customer.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating customer details: {str(e)}', 'danger')
            
    return render_template('edit_customer.html', customer=customer, form=form, today=today, nonce=session.get('nonce'))

@app.route('/api/get_customer_details/<account_number>')
@login_required
@role_required(['admin', 'manager', 'teller'])  # Only admin, manager, and teller can get customer details
def get_customer_details(account_number):
    customer = Customer.query.filter_by(account_number=account_number).first()
    if customer:
        # Get the latest work entry for balances
        latest_entry = WorkEntry.query.filter_by(
            account_number=account_number
        ).order_by(WorkEntry.created_at.desc()).first()

        # Calculate total savings deposits and withdrawals
        savings_transactions = WorkEntry.query.filter_by(account_number=account_number).all()
        initial_deposit = float(customer.initial_deposit) if customer.initial_deposit else 0
        total_savings_deposit = sum(float(entry.savings_deposit) for entry in savings_transactions if entry.savings_deposit)
        total_savings_withdrawal = sum(float(entry.savings_withdrawal) for entry in savings_transactions if entry.savings_withdrawal)
        account_balance = initial_deposit + total_savings_deposit - total_savings_withdrawal

        # Set default balances if no previous transactions
        share_balance = 0
        savings_balance = 0
        loan_balance = 0

        if latest_entry:
            share_balance = latest_entry.share_balance
            savings_balance = latest_entry.savings_balance
            loan_balance = latest_entry.loan_balance

        return jsonify({
            'success': True,
            'customer': {
                'name': customer.full_name,
                'phone_number': customer.phone_number,
                'account_number': customer.account_number,
                'email': customer.email,
                'address': customer.address,
                'date_of_birth': customer.date_of_birth.strftime('%Y-%m-%d') if customer.date_of_birth else None,
                'gender': customer.gender,
                'occupation': customer.occupation,
                'next_of_kin': customer.next_of_kin,
                'next_of_kin_phone': customer.next_of_kin_phone,
                'id_type': customer.id_type,
                'id_number': customer.id_number,
                'share_balance': share_balance,
                'savings_balance': savings_balance,
                'loan_balance': loan_balance,
                'account_balance': account_balance,
                'initial_deposit': initial_deposit,
                'account_type': customer.account_type,
                'account_holder': customer.full_name,  # Added account holder name
                'organization': customer.account_number
            }
        })
    return jsonify({
        'success': False,
        'message': 'Customer not found'
    }), 404

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate reset token
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.now() + timedelta(hours=1)
            db.session.commit()

            # Send reset email
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                        sender='noreply@obotan.com',
                        recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'error')

    return render_template('forgot_password.html', nonce=session.get('nonce'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if user is None or user.reset_token_expiry < datetime.now():
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', nonce=session.get('nonce'))
        
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', nonce=session.get('nonce'))

@app.route('/register', methods=['GET', 'POST'])
@role_required(['admin', 'manager'])  # Only admin and manager can create new users
def register():
    if current_user.is_authenticated and current_user.role not in ['admin', 'manager']:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            # Create initial admin user if no admin exists
            existing_admin = User.query.filter_by(role='admin').first()
            if not existing_admin:
                username = 'admin'
                email = 'admin@obotan.com'
                password = 'Obotan2024!'  # Strong initial password
                full_name = 'System Administrator'
                phone_number = '0000000000'
                role = 'admin'

                # Generate unique user ID
                user_id = User.generate_user_id(role)

                # Create new admin user
                new_user = User(
                    user_id=user_id,
                    username=username,
                    email=email,
                    full_name=full_name,
                    phone_number=phone_number,
                    role=role,
                    is_active=True
                )
                new_user.set_password(password)
                
                db.session.add(new_user)
                db.session.commit()
                
                flash(f'Initial admin user created. User ID: {user_id}, Password: Obotan2024!', 'success')
                return redirect(url_for('login'))
            
            # Existing registration logic
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            role = request.form.get('role')

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('register.html', nonce=session.get('nonce'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'error')
                return render_template('register.html', nonce=session.get('nonce'))

            # Generate unique user ID
            user_id = User.generate_user_id(role)

            new_user = User(
                user_id=user_id,
                username=username,
                email=email,
                full_name=full_name,
                phone_number=phone,
                role=role,
                is_active=True
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()

            flash('User account has been created successfully!', 'success')
            return redirect(url_for('manage_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'error')
            return render_template('register.html', nonce=session.get('nonce'))

    return render_template('register.html', nonce=session.get('nonce'))

@app.route('/submit_work', methods=['GET', 'POST'])
@login_required
@role_required(['mobile_banker'])  # Only mobile bankers should submit work
def submit_work():
    form = WorkSubmissionForm()

    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Create new work submission
            work = WorkSubmission(
                user_id=current_user.id,
                date=form.date.data,
                location=form.location.data,
                customers_visited=form.customers_visited.data,
                total_collections=form.total_collections.data,
                new_accounts=form.new_accounts.data,
                notes=form.notes.data,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(work)
            db.session.commit()
            flash('Work submission successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting work: {str(e)}', 'error')

    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('submit_work.html', form=form, today=today, nonce=session.get('nonce'))

@app.route('/get_user/<int:user_id>')
@login_required
@role_required(['admin', 'manager'])  # Only admin and manager can view user details
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify({
            'id': user.id,
            'name': user.username,
            'email': user.email,
            'phone': user.phone_number,
            'role': user.role,
            'is_active': user.is_active
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/manage_roles')
@login_required
@role_required(['admin'])  # Only admin can manage roles
def manage_roles():
    roles = Role.query.all()
    return render_template('manage_roles.html', roles=roles, today=datetime.now(), nonce=session.get('nonce'))

@app.route('/add_role', methods=['POST'])
@login_required
@role_required(['admin'])
def add_role():
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        
        if Role.query.filter_by(name=name).first():
            flash('Role already exists.', 'error')
            return redirect(url_for('manage_roles'))
        
        role = Role(name=name, description=description)
        db.session.add(role)
        db.session.commit()
        
        flash('Role added successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding role: {str(e)}', 'error')
    
    return redirect(url_for('manage_roles'))

@app.route('/get_role/<int:role_id>')
@login_required
@role_required(['admin'])
def get_role(role_id):
    try:
        role = Role.query.get_or_404(role_id)
        return jsonify({
            'name': role.name,
            'description': role.description
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/edit_role/<int:role_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def edit_role(role_id):
    try:
        role = Role.query.get_or_404(role_id)
        
        # Check if another role with the same name exists
        existing_role = Role.query.filter(Role.name == request.form.get('name'), Role.id != role_id).first()
        if existing_role:
            flash('A role with this name already exists.', 'error')
            return redirect(url_for('manage_roles'))
        
        role.name = request.form.get('name')
        role.description = request.form.get('description')
        role.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Role updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating role: {str(e)}', 'error')
    
    return redirect(url_for('manage_roles'))

@app.route('/delete_role/<int:role_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_role(role_id):
    try:
        role = Role.query.get_or_404(role_id)
        
        # Check if role is being used by any users
        if User.query.filter_by(role=role.name).first():
            return jsonify({
                'success': False,
                'message': 'Cannot delete role that is assigned to users.'
            })
        
        db.session.delete(role)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Role deleted successfully.'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error deleting role: {str(e)}'
        })

# Admin dashboard route
@app.route('/admin_dashboard')
@login_required
@role_required(['admin', 'manager'])  # Only admin and manager can access
def admin_dashboard():
    # Get all users
    users = User.query.all()
    
    # Get work submissions for the last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    work_submissions = WorkSubmission.query.filter(WorkSubmission.date >= thirty_days_ago).all()
    
    # Get recent customers
    recent_customers = Customer.query.order_by(Customer.id.desc()).limit(10).all()
    
    # Calculate some statistics
    total_users = len(users)
    active_users = len([u for u in users if u.is_active])
    total_mobile_bankers = len([u for u in users if u.role == 'mobile_banker'])
    total_tellers = len([u for u in users if u.role == 'teller'])
    
    # Work submission statistics
    total_collections = sum(ws.total_collections for ws in work_submissions)
    total_new_accounts = sum(ws.new_accounts for ws in work_submissions)
    customers_visited = sum(ws.customers_visited for ws in work_submissions)
    
    return render_template('admin_dashboard.html',
                         users=users,
                         work_submissions=work_submissions,
                         recent_customers=recent_customers,
                         total_users=total_users,
                         active_users=active_users,
                         total_mobile_bankers=total_mobile_bankers,
                         total_tellers=total_tellers,
                         total_collections=total_collections,
                         total_new_accounts=total_new_accounts,
                         customers_visited=customers_visited,
                         today=datetime.now(),
                         nonce=session.get('nonce'))

@app.route('/daily_deposit', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'teller', 'mobile_banker'])
def daily_deposit():
    form = WorkEntryForm()
    
    if form.validate_on_submit():
        try:
            # Get form data
            member_id = form.member_id.data
            share_deposit = float(form.share_deposit.data or 0)
            savings_deposit = float(form.savings_deposit.data or 0)
            principal = float(form.principal.data or 0)
            interest = float(form.interest.data or 0)
            total_amount = share_deposit + savings_deposit + principal + interest
            
            # Create new transaction
            transaction = WorkEntry(
                user_id=current_user.id,
                name=form.member_name.data,
                account_number=member_id,
                amount=total_amount,
                payment_type=form.payment_type.data,
                description=form.detail_narration.data,
                share_code=form.share_code.data,
                share_deposit=share_deposit,
                savings_code=form.savings_code.data,
                savings_deposit=savings_deposit,
                loan_code=form.loan_code.data,
                principal=principal,
                interest=interest,
                mobile=form.phone.data,
                transaction_date=form.transaction_date.data,
                created_at=datetime.now(),
                cashbook=form.cashbook.data,
                payee_name=form.payee_name.data,
                cheque_number=form.cheque_number.data
            )
            
            # Update customer balances
            customer = Customer.query.filter_by(account_number=member_id).first()
            if customer:
                if share_deposit > 0:
                    customer.share_balance = float(customer.share_balance or 0) + share_deposit
                if savings_deposit > 0:
                    customer.savings_balance = float(customer.savings_balance or 0) + savings_deposit
                if principal > 0 or interest > 0:
                    customer.loan_balance = float(customer.loan_balance or 0) - (principal + interest)
                
                # Store the current balances in the transaction
                transaction.share_balance = customer.share_balance
                transaction.savings_balance = customer.savings_balance
                transaction.loan_balance = customer.loan_balance
            
            db.session.add(transaction)
            db.session.commit()

            flash('Deposit recorded successfully', 'success')
            return redirect(url_for('daily_deposit'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error recording deposit: {str(e)}', 'error')
            return redirect(url_for('daily_deposit'))
    
    return render_template('daily_deposit.html', form=form, today=datetime.now().date(), nonce=session.get('nonce'))

# API endpoint for fetching customer details for daily deposit
@app.route('/api/daily-deposit/customer/<account_number>')
@login_required
@csrf.exempt  # Exempt this API endpoint from CSRF protection
def get_customer_details_for_deposit(account_number):
    customer = Customer.query.filter_by(account_number=account_number).first()
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404
        
    return jsonify({
        'full_name': customer.full_name,
        'phone_number': customer.phone_number,
        'share_balance': float(customer.share_balance or 0),
        'savings_balance': float(customer.savings_balance or 0),
        'loan_balance': float(customer.loan_balance or 0)
    })

@app.route('/delete_customer/<int:customer_id>', methods=['DELETE'])
@login_required
@role_required(['admin'])  # Only admin can delete customers
def delete_customer(customer_id):
    try:
        customer = Customer.query.get_or_404(customer_id)
        db.session.delete(customer)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Customer deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/daily_withdrawal', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'teller'])
def daily_withdrawal():
    form = DailyWithdrawalForm()
    today = datetime.now().date()
    
    if request.method == 'POST':
        try:
            # Get customer details
            account_no = request.form.get('account_no')
            customer = Customer.query.filter_by(account_number=account_no).first()
            
            if not customer:
                flash('Customer not found.', 'error')
                return redirect(url_for('daily_withdrawal'))
            
            # Get withdrawal details
            withdrawal_amount = float(request.form.get('payment', 0))
            withdrawal_mode = request.form.get('withdrawal_mode')
            cash_book = request.form.get('cash_book')
            reference = request.form.get('reference')
            detail_narration = request.form.get('detail_narration')
            
            # Validate sufficient balance
            current_balance = float(customer.savings_balance or 0)
            if withdrawal_amount > current_balance:
                flash('Insufficient balance for withdrawal.', 'error')
                return redirect(url_for('daily_withdrawal'))
            
            # Calculate new balance
            new_balance = current_balance - withdrawal_amount
            
            # Create work entry for the withdrawal
            work_entry = WorkEntry(
                transaction_date=today,
                user_id=current_user.id,
                name=customer.full_name,
                account_number=account_no,
                amount=withdrawal_amount,
                description=detail_narration,
                payment_type=withdrawal_mode,
                cashbook=cash_book,
                savings_withdrawal=withdrawal_amount,
                savings_code=form.saving_code.data,
                savings_balance=new_balance,
                share_balance=customer.share_balance,
                loan_balance=customer.loan_balance,
                mobile=customer.phone_number
            )
            
            # Update customer balance
            customer.savings_balance = new_balance
            
            # Save changes to database
            db.session.add(work_entry)
            db.session.commit()
            
            flash('Withdrawal processed successfully!', 'success')
            return redirect(url_for('daily_withdrawal'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing withdrawal: {str(e)}', 'error')
            return redirect(url_for('daily_withdrawal'))
    
    return render_template('daily_withdrawal.html', form=form, today=today, nonce=session.get('nonce'))

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():  # Create an application context
        # Initialize Flask-Migrate
        migrate = Migrate(app, db)

        # Import migration
        from migrations.add_full_name_to_users import upgrade as add_full_name

        # Create tables and run migrations
        db.create_all()
        try:
            add_full_name()
        except Exception as e:
            print(f"Migration error (this is normal if the column already exists): {str(e)}")

        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        
        # Create default roles if they don't exist
        default_roles = {
            'bank_teller': {
                'create': True,
                'read': True,
                'update': True,
                'delete': False,
                'manage_users': False,
                'manage_roles': False,
                'process_transactions': True,
                'view_customer_info': True,
                'handle_cash': True
            },
            'mobile_banker': {
                'create': True,
                'read': True,
                'update': True,
                'delete': False,
                'manage_users': False,
                'manage_roles': False,
                'process_transactions': True,
                'view_customer_info': True,
                'handle_cash': True,
                'field_operations': True
            },
            'manager': {
                'create': True,
                'read': True,
                'update': True,
                'delete': True,
                'manage_users': True,
                'manage_roles': True,
                'process_transactions': True,
                'view_customer_info': True,
                'handle_cash': True,
                'approve_transactions': True,
                'view_reports': True,
                'manage_staff': True
            }
        }

        for role_name, permissions in default_roles.items():
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                new_role = Role(name=role_name, permissions=permissions)
                db.session.add(new_role)
                print(f"{role_name} role created with permissions: {permissions}")

        # Create admin role if it doesn't exist
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(
                name='admin',
                permissions={
                    'create': True,
                    'read': True,
                    'update': True,
                    'delete': True,
                    'manage_users': True,
                    'manage_roles': True,
                    'process_transactions': True,
                    'view_customer_info': True,
                    'handle_cash': True,
                    'approve_transactions': True,
                    'view_reports': True,
                    'manage_staff': True,
                    'system_config': True,
                    'all': True
                }
            )
            db.session.add(admin_role)
            print("Admin role created with full permissions")

        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin = User(
                user_id='ADM' + datetime.now().strftime('%y%m%d%H%M'),
                username='admin',
                full_name='System Administrator',  
                email='admin@obotancredit.com',
                phone_number='+233000000000',
                role='admin',
                is_active=True,
                created_at=datetime.utcnow()
            )
            admin.set_password('admin123')  
            db.session.add(admin)
            db.session.commit()
            print('Admin user created successfully')
            
    app.run(debug=True, host='0.0.0.0', port=5000)