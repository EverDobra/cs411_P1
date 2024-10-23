from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
import random

app = Flask(__name__)
app.secret_key = 'secret_key_here'

# Mock user data
users = {
    'doctor_user': {'password': 'hashed_password1', 'role': 'doctor'},
    'admin_user': {'password': 'hashed_password2', 'role': 'admin'}
}

failed_attempts = {}

# Reset failed attempts
def reset_failed_attempts(username):
    failed_attempts[username] = 0
    session['captcha_verified'] = False

@app.route('/login', methods=['GET', 'POST'])
# Render the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' not in session:
        session['username'] = None

    # After 3 failed attempts, always require captcha for every subsequent attempt
    if session['username'] and failed_attempts.get(session['username'], 0) >= 3:
        if 'captcha_verified' not in session or not session['captcha_verified']:
            # Redirect to captcha every time after 3 attempts
            flash('Please complete the captcha verification.', 'danger')
            return redirect(url_for('captcha'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password'], password):
            reset_failed_attempts(username)
            flash('Login successful!', 'success')
            return redirect(url_for(f'{users[username]["role"]}_dashboard'))
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            flash('Incorrect username or password', 'danger')

            # Force captcha after 3 failed attempts and every time afterward
            if failed_attempts[username] >= 3:
                session['captcha_verified'] = False
                return redirect(url_for('captcha'))

    return render_template('login.html')



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

    # Generate random numbers for captcha
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    session['captcha_sum'] = num1 + num2

    return render_template('captcha.html', num1=num1, num2=num2)

# Dashboard routes
@app.route('/admin_dashboard')
def admin_dashboard():
    return 'Admin Dashboard'

@app.route('/doctor_dashboard')
def doctor_dashboard():
    return 'Doctor Dashboard'

if __name__ == '__main__':
    app.run(debug=True)
