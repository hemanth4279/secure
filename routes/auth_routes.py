from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import base64
import pyotp
from mail import send_otp_email  # Import from your mail.py

auth_bp = Blueprint('auth', __name__)

mysql = MySQL()

# Home Route
@auth_bp.route('/')
def home():
    return render_template('main.html')

# ------------------- Registration ------------------- #
def generate_patient_id():
    return f"PID{random.randint(100000, 999999)}"

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Check if this is OTP verification submission
        if 'otp' in request.form:
            otp_input = request.form['otp']
            secret = session.get('otp_secret')
            
            if not secret:
                flash("Session expired. Please register again.", 'danger')
                return redirect(url_for('auth.register'))
                
            totp = pyotp.TOTP(secret, interval=600)  # 10-minute validity
            if totp.verify(otp_input, valid_window=1):
                patient_data = session.pop('patient_data')
                cursor = mysql.connection.cursor()
                cursor.execute("""
                    INSERT INTO patients (patient_id, name, phone, email, dob, password, address, is_activated) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (patient_data['patient_id'], patient_data['name'], patient_data['phone'],
                      patient_data['email'], patient_data['dob'], patient_data['password'],
                      patient_data['address'], '0'))
                mysql.connection.commit()
                cursor.close()
                flash(f"Registration successful. Your Patient ID is {patient_data['patient_id']}. Await activation.", 'success')
                session.pop('otp_secret', None)
                return redirect(url_for('auth.login'))
            else:
                flash("Invalid OTP. Please try again.", 'danger')
                return render_template('verify_otp.html', email=session['patient_data']['email'])

        # Initial registration form submission
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        dob = request.form['dob']
        password = request.form['password']
        address = request.form['address']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM patients WHERE email = %s OR phone = %s", (email, phone))
        existing_user = cursor.fetchone()
        
        if existing_user:
            cursor.close()
            flash('User with this email or phone number already exists.', 'danger')
            return redirect(url_for('auth.register'))
        
        # Generate unique patient ID
        while True:
            patient_id = generate_patient_id()
            cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
            if not cursor.fetchone():
                break

        # Generate and send OTP
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, interval=600)
        otp = totp.now()
        
        # Send OTP via email
        if send_otp_email(email, otp):
            # Store data in session
            hashed_password = generate_password_hash(password)
            session['patient_data'] = {
                'patient_id': patient_id,
                'name': name,
                'phone': phone,
                'email': email,
                'dob': dob,
                'password': hashed_password,
                'address': address
            }
            session['otp_secret'] = secret
            
            cursor.close()
            flash('OTP has been sent to your email.', 'info')
            return render_template('verify_otp.html', email=email)
        else:
            cursor.close()
            flash('Failed to send OTP. Please try again.', 'danger')
            return redirect(url_for('auth.register'))
    
    return render_template('register.html')

# ------------------- Login ------------------- #
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM patients WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            if account['is_activated']:
                session['loggedin'] = True
                session['id'] = account['id']
                session['patient_id'] = account['patient_id']
                session['name'] = account['name']
                flash('Login successful!', 'success')
                return redirect(url_for('patient.dashboard'))
            else:
                flash('Account not activated by cloud server.', 'warning')
        else:
            flash('Incorrect email/password.', 'danger')
    return render_template('login.html')

# ------------------- Logout ------------------- #
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.home'))