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

# Dictionary to track failed login attempts
failed_attempts = {}


# Reset failed attempts and clear CAPTCHA verification
def reset_failed_attempts(username):
    failed_attempts[username] = 0
    session.pop('captcha_verified', None)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/create_account')
def create_account():
    return render_template('create_account.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Initialize session variables if not already set
    if 'username' not in session:
        session['username'] = None
        session['captcha_verified'] = False

    show_captcha = False
    num1, num2 = None, None

    # Show CAPTCHA if failed attempts are 4 or more and not verified
    if session['username'] and failed_attempts.get(session['username'], 0) >= 4:
        show_captcha = True
        if not session.get('captcha_verified', False):
            # Generate new CAPTCHA values if needed
            if 'captcha_sum' not in session:
                num1, num2 = random.randint(1, 10), random.randint(1, 10)
                session['captcha_sum'] = num1 + num2
            else:
                num1, num2 = session['captcha_sum_values']
            session['captcha_sum_values'] = (num1, num2)  # Ensure values are stored for display

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check CAPTCHA answer if required
        if show_captcha and not session.get('captcha_verified', False):
            captcha_answer = request.form.get('captcha_answer')
            if captcha_answer and int(captcha_answer) == session['captcha_sum']:
                session['captcha_verified'] = True  # Mark CAPTCHA as solved
                flash('CAPTCHA verification successful.', 'success')
                session.pop('captcha_sum', None)
            else:
                flash('Incorrect CAPTCHA answer. Please try again.', 'danger')
                return render_template('login.html', show_captcha=True, num1=num1, num2=num2)

        # Check if username and password meet character limit criteria
        if len(username) > 16 or len(password) > 16:
            flash('Username or password exceeds character limit of 16.', 'danger')
            return redirect(url_for('login'))

        if username in users and check_password_hash(users[username]['password'], password):
            reset_failed_attempts(username)  # Reset attempts and CAPTCHA
            session['username'] = username  # Set session username

            flash('Login successful!', 'success')
            if users[username]['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            # Increment failed attempts and check CAPTCHA requirement
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            flash('Incorrect username or password', 'danger')

            # Trigger CAPTCHA display after 4 attempts
            if failed_attempts[username] >= 4:
                session['captcha_verified'] = False  # Reset CAPTCHA verified status
                session['username'] = username  # Store username for CAPTCHA verification
                num1, num2 = random.randint(1, 10), random.randint(1, 10)
                session['captcha_sum'] = num1 + num2
                session['captcha_sum_values'] = (num1, num2)  # Store values for display
                return render_template('login.html', show_captcha=True, num1=num1, num2=num2)

    return render_template('login.html', show_captcha=show_captcha, num1=num1, num2=num2)


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
