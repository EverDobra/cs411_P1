from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
import requests

app = Flask(__name__)
app.secret_key = 'secret_key_here'

users = {
    'doctor_user': {'password': generate_password_hash('password1'), 'role': 'doctor'},
    'admin_user': {'password': generate_password_hash('password2'), 'role': 'admin'},
    'test_user': {'password': generate_password_hash('password3'), 'role': 'user'},
    'lab_user': {'password': generate_password_hash('password4'), 'role': 'laboratorist'}
}

failed_attempts = {}


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
    if 'username' not in session:
        session['username'] = None
        session['captcha_verified'] = False

    show_captcha = False

    if session['username'] and failed_attempts.get(session['username'], 0) >= 4:
        show_captcha = True

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check reCAPTCHA if required
        if show_captcha and not session.get('captcha_verified', False):
            recaptcha_response = request.form.get('g-recaptcha-response')
            if not recaptcha_response:
                flash('reCAPTCHA verification failed. Please try again.', 'danger')
                return render_template('login.html', show_captcha=True)

            secret_key = '6LcxAmwqAAAAAIv01gX_nHMAmPjzpNKmMAwSQNxT'

            data = {
                'secret': secret_key,
                'response': recaptcha_response
            }
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = r.json()

            if not result.get('success'):
                flash('Invalid reCAPTCHA. Please try again.', 'danger')
                return render_template('login.html', show_captcha=True)

            session['captcha_verified'] = True

        if len(username) > 16 or len(password) > 16:
            flash('Username or password exceeds character limit of 16.', 'danger')
            return redirect(url_for('login'))

        if username in users and check_password_hash(users[username]['password'], password):
            reset_failed_attempts(username)
            session['username'] = username

            flash('Login successful!', 'success')
            if users[username]['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif users[username]['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif users[username]['role'] == 'laboratorist':
                return redirect(url_for('lab_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            flash('Incorrect username or password', 'danger')

            if failed_attempts[username] >= 4:
                session['captcha_verified'] = False
                session['username'] = username
                return render_template('login.html', show_captcha=True)

    return render_template('login.html', show_captcha=show_captcha)


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


@app.route('/lab_dashboard')
def lab_dashboard():
    return render_template('lab_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
