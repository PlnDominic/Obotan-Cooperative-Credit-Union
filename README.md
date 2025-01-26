# Obotan Co-operative Credit Union Management System

## Overview
Obotan is a comprehensive web application for managing a co-operative credit union, providing features for user management, financial transactions, and reporting.

## Features
- User Authentication
- Customer Management
- Financial Transactions
- Work Submissions
- Reporting Dashboard

## Deployment Instructions

### Prerequisites
- Python 3.8+
- PostgreSQL
- pip

### Local Setup
1. Clone the repository
2. Create a virtual environment
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install dependencies
   ```
   pip install -r requirements.txt
   ```
4. Set up environment variables in `.env`
5. Initialize the database
   ```
   flask db upgrade
   ```
6. Run the application
   ```
   gunicorn app:app
   ```

### Deployment Platforms
- Heroku
- Render
- PythonAnywhere

## Deployment on Render

### Prerequisites
- GitHub account
- Render account
- PostgreSQL database (Render offers a free tier)

### Deployment Steps
1. **Create a Render Web Service**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "New Web Service"
   - Connect your GitHub repository
   - Choose the `main` branch

2. **Configure Build Settings**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

3. **Environment Variables**
   Set the following environment variables in Render:
   - `DATABASE_URL`: Your PostgreSQL database connection string
   - `SECRET_KEY`: A long random string (use `python -c "import secrets; print(secrets.token_hex(32))"`
   - `FLASK_ENV`: `production`
   - `DEBUG`: `False`

4. **Database Setup**
   - Create a free PostgreSQL database on Render
   - Use the provided connection string in `DATABASE_URL`

### Troubleshooting
- Ensure all dependencies are in `requirements.txt`
- Check Render logs for any deployment issues
- Verify environment variables are correctly set

### Recommended Production Configurations
- Use environment-specific settings
- Enable HTTPS
- Set up proper logging
- Implement rate limiting

## Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Flask secret key
- `DEBUG`: Set to False in production
- `MAIL_*`: Email configuration settings

## Contributing
Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the LICENSE.md file for details.
