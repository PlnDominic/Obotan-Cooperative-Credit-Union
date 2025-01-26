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

## Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Flask secret key
- `DEBUG`: Set to False in production
- `MAIL_*`: Email configuration settings

## Contributing
Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the LICENSE.md file for details.
