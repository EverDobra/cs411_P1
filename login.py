from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key_here'

users = {
    'doctor_user': {'password': generate_password_hash('password1'), 'role': 'doctor'},
    'admin_user': {'password': generate_password_hash('password2'), 'role': 'admin'},
    'test_user': {'password': generate_password_hash('password3'), 'role': 'user'},
    'lab_user': {'password': generate_password_hash('password4'), 'role': 'laboratorist'},
    'nurse_user': {'password': generate_password_hash('password5'), 'role': 'nurse'}
}


failed_attempts = {}
patients = []


# Define a custom date filter
def format_date(value, format='%Y-%m-%d'):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value


# Register the filter with Jinja2
app.jinja_env.filters['date'] = format_date

def reset_failed_attempts(username):
    failed_attempts[username] = 0
    session.pop('captcha_verified', None)


@app.route('/')
def index():
    return render_template('index.html')


# In-memory patient database
# Global variables for rooms and inpatients
rooms = {101: "Vacant", 102: "Occupied", 103: "Vacant", 104: "Vacant"}
inpatients = []
from datetime import datetime

@app.route('/inpatient_module', methods=['GET', 'POST'])
def inpatient_module():
    global rooms, patients, inpatients

    if 'username' not in session or session['username'] is None:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        # Assign room to a patient
        if action == 'assign_room':
            patient_id = int(request.form['patient_id'])
            new_room = int(request.form['room'])
            assign_date = request.form.get('assign_date') or datetime.now().strftime('%Y-%m-%d')
            discharge_date = request.form.get('discharge_date')

            # Find the patient
            patient = next((p for p in patients if p["id"] == patient_id), None)
            if not patient:
                flash('Patient not found!', 'danger')
                return redirect(url_for('inpatient_module'))

            # Check if the patient already has a room assigned
            if patient.get('room'):
                old_room = int(patient['room'])
                if old_room == new_room:
                    flash(f"Patient is already in Room {old_room}.", 'warning')
                else:
                    # Store room reassignment request in session
                    session['pending_room_change'] = {
                        'patient_id': patient_id,
                        'new_room': new_room,
                        'assign_date': assign_date,
                        'discharge_date': discharge_date,
                    }
                    flash(f"Patient is currently in Room {old_room}. Confirm to move to Room {new_room}.", 'info')
                    return redirect(url_for('inpatient_module'))
            else:
                # Assign room if vacant
                if rooms[new_room] == "Vacant":
                    rooms[new_room] = "Occupied"
                    patient['room'] = new_room
                    patient['admission_date'] = assign_date
                    patient['discharge_date'] = discharge_date
                    inpatients.append(patient)
                    flash(f"Room {new_room} assigned to {patient['name']}.", 'success')
                else:
                    flash('Room is already occupied!', 'danger')

        elif action == 'confirm_room_change':
            # Retrieve pending change from session
            pending_change = session.pop('pending_room_change', None)
            if pending_change:
                patient_id = pending_change['patient_id']
                new_room = pending_change['new_room']
                assign_date = pending_change['assign_date']
                discharge_date = pending_change['discharge_date']

                # Locate the patient
                patient = next((p for p in patients if p["id"] == patient_id), None)
                if patient:
                    old_room = patient.get('room')
                    if old_room and old_room != "None":
                        # Make the old room vacant
                        rooms[int(old_room)] = "Vacant"
                    # Assign the new room
                    patient['room'] = new_room
                    rooms[int(new_room)] = "Occupied"
                    patient['admission_date'] = assign_date
                    patient['discharge_date'] = discharge_date

                    # Update inpatients list for proper synchronization
                    if patient not in inpatients:
                        inpatients.append(patient)

                    flash(f"Room reassigned from {old_room or 'None'} to {new_room} for {patient['name']}.", 'success')
                else:
                    flash("Error: Patient not found for reassignment.", 'danger')
            else:
                flash("Error: No pending room change request.", 'danger')


        # Discharge a patient
        elif action == 'discharge':
            patient_id = int(request.form['patient_id'])
            patient = next((p for p in inpatients if p['id'] == patient_id), None)
            if patient:
                room_number = int(patient['room'])
                rooms[room_number] = "Vacant"  # Make the room vacant
                patient['room'] = None  # Clear room assignment
                inpatients.remove(patient)
                flash(f"{patient['name']} has been discharged.", 'success')
            else:
                flash('Inpatient not found!', 'danger')

    return render_template('inpatient_module.html', patients=patients, rooms=rooms, inpatients=inpatients)








@app.route('/patient_admission', methods=['GET', 'POST'])
def patient_admission():
    if 'username' not in session or session['username'] is None:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Capture patient data from the form
        tc = request.form['tc']
        if any(patient['tc'] == tc for patient in patients):
            flash(f'A patient with TC {tc} already exists in the system!', 'danger')
            return redirect(url_for('patient_admission'))

        patient = {
            'id': len(patients) + 1,
            'tc': tc,
            'name': request.form['name'],
            'dob': request.form['dob'],
            'gender': request.form['gender'],
            'contact': request.form['contact'],
            'emergency_contact': request.form['emergency_contact']
        }
        patients.append(patient)
        flash('Patient record added successfully!', 'success')
        return redirect(url_for('patient_admission'))

    return render_template('patient_admission.html', patients=patients)


@app.route('/manage_patients', methods=['GET', 'POST'])
def manage_patients():
    if 'username' not in session or session['username'] is None:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle editing patient details
        patient_id = int(request.form['patient_id'])
        for patient in patients:
            if patient['id'] == patient_id:
                patient['name'] = request.form['name']
                patient['dob'] = request.form['dob']
                patient['gender'] = request.form['gender']
                patient['contact'] = request.form['contact']
                patient['emergency_contact'] = request.form['emergency_contact']
                # Room field should not be updated
                flash('Patient details updated successfully!', 'success')
                break

    return render_template('manage_patients.html', patients=patients)

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    global patients
    patients = [patient for patient in patients if patient['id'] != patient_id]
    flash('Patient record deleted successfully!', 'success')
    return redirect(url_for('manage_patients'))

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


@app.route('/manage_users', methods=['GET', 'POST'])
@app.route('/manage_users', methods=['GET', 'POST'])
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session['username'] is None:
        flash('You must be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    global users

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            if username in users:
                flash('User already exists!', 'danger')
            else:
                users[username] = {
                    'password': generate_password_hash(password),
                    'role': role
                }
                flash('User added successfully!', 'success')

        elif action == 'update':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            if username in users:
                users[username]['password'] = generate_password_hash(password)
                users[username]['role'] = role
                flash('User updated successfully!', 'success')
            else:
                flash('User not found!', 'danger')

        elif action == 'delete':
            username = request.form['username']
            if username in users:
                del users[username]
                flash('User deleted successfully!', 'success')
            else:
                flash('User not found!', 'danger')

    return render_template('manage_users.html', users=users)


@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
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
