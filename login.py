from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
import random

app = Flask(__name__)
app.secret_key = 'secret_key_here'

# Mock user data with hashed passwords for testing
users = {
    'doctor_user': {'password': generate_password_hash('password1'), 'role': 'doctor'},
    'admin_user': {'password': generate_password_hash('password2'), 'role': 'admin'},
    'test_user': {'password': generate_password_hash('password3'), 'role': 'user'}
}

failed_attempts = {}

# Reset failed attempts
def reset_failed_attempts(username):
    failed_attempts[username] = 0
    session['captcha_verified'] = False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/create_account')
def create_account():
    return render_template('create_account.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' not in session:
        session['username'] = None

    if session['username'] and failed_attempts.get(session['username'], 0) >= 3:
        if 'captcha_verified' not in session or not session['captcha_verified']:
            flash('Please complete the captcha verification.', 'danger')
            return redirect(url_for('captcha'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username and password meet character limit criteria
        if len(username) > 16 or len(password) > 16:
            flash('Username or password exceeds character limit of 16.', 'danger')
            return redirect(url_for('login'))

        if username in users and check_password_hash(users[username]['password'], password):
            reset_failed_attempts(username)
            flash('Login successful!', 'success')
            if users[username]['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            flash('Incorrect username or password', 'danger')

            if failed_attempts[username] >= 3:
                session['captcha_verified'] = False
                return redirect(url_for('captcha'))

    return render_template('login.html')


# CAPTCHA route
@app.route('/captcha', methods=['GET', 'POST'])
def captcha():
    if request.method == 'POST':
        captcha_answer = request.form['captcha_answer']
        if int(captcha_answer) == session['captcha_sum']:
            session['captcha_verified'] = True
            return redirect(url_for('login'))
        else:
            flash('Incorrect captcha answer. Please try again.', 'danger')
            return redirect(url_for('captcha'))

    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['captcha_sum'] = num1 + num2

    return render_template('captcha.html', num1=num1, num2=num2)

# Dashboard routes
@app.route('/doctor_dashboard')
def doctor_dashboard():
    return render_template('doctor_dashboard.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/user_dashboard')
def user_dashboard():
    return render_template('user_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
