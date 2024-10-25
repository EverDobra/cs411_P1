Login page designated for open source "Open Hospital" project. 

Install Dependencies:

    pip install flask werkzeug requests

Run App:

    python login.py

Access App: Visit http://127.0.0.1:5000.

**How the Code Works:**

User Data: Users dictionary stores user roles and hashed passwords.
Each user has a role that determines which dashboard they access.
Login Functionality:

If the user enters a valid username and password combination, they are redirected to the appropriate dashboard based on
their role.
If the login fails, the failed attempt is counted. After four failed attempts, reCAPTCHA verification is required.
reCAPTCHA Verification:

After four incorrect login attempts, the user is presented with reCAPTCHA.
If reCAPTCHA is successfully passed, the user can continue trying to log in.
Session Handling:

Flask sessions are used to track login attempts and reCAPTCHA status.