from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from utils.encryption import AESEncryption, RSAEncryption, DSASignature
from config import DB_CONFIG, AES_SECRET_KEY
import MySQLdb.cursors
import base64
import random
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from io import BytesIO
import secrets
import pyotp
import qrcode
import requests
import json
from uuid import uuid4
from datetime import datetime

app = Flask(__name__)
app.secret_key = '5e8e565836ec4ab43a22afe1d316f35f87bf7eeab2d0b80d862d31d6321b976e'
app.permanent_session_lifetime = 3600  # Sessions last 1 hour

# ---------------- UPI Gateway Constants ---------------- #
UPI_GATEWAY_API_KEY = "eb8414ec-1f13-4c8f-b713-ae55fbc94a97"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

# ---------------- MySQL Configuration ---------------- #
app.config['MYSQL_HOST'] = DB_CONFIG['host']
app.config['MYSQL_USER'] = DB_CONFIG['user']
app.config['MYSQL_PASSWORD'] = DB_CONFIG['password']
app.config['MYSQL_DB'] = DB_CONFIG['database']

mysql = MySQL(app)

# ---------------- Initialize Encryption ---------------- #
aes = AESEncryption(AES_SECRET_KEY)
rsa = RSAEncryption()
dsa = DSASignature()

# ------------------- ROUTES ------------------- #

# Home Route
@app.route('/')
def home():
    return render_template('main.html')

# ------------------- Registration ------------------- #
def generate_patient_id():
    return f"PID{random.randint(100000, 999999)}"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
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
            flash('User with this email or phone number already exists.', 'danger')
            return redirect(url_for('register'))
        
        while True:
            patient_id = generate_patient_id()
            cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
            if not cursor.fetchone():
                break

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO patients (patient_id, name, phone, email, dob, password, address) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                       (patient_id, name, phone, email, dob, hashed_password, address))
        mysql.connection.commit()
        flash(f'Registration successful. Your Patient ID is {patient_id}. Await activation.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# ------------------- Login ------------------- #
@app.route('/login', methods=['GET', 'POST'])
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
                return redirect(url_for('dashboard'))
            else:
                flash('Account not activated by cloud server.', 'warning')
        else:
            flash('Incorrect email/password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM patients WHERE patient_id = %s', (session['patient_id'],))
        patient = cursor.fetchone()
        return render_template('dashboard.html', patient=patient)
    return redirect(url_for('login'))

# ------------------- Upload Medical Data ------------------- #
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'loggedin' not in session:
        flash('Please login to upload medical data.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        blood_group = request.form['blood_group']
        blood_pressure = request.form['blood_pressure']
        body_temp = request.form['body_temp']
        pulse_rate = request.form['pulse_rate']
        medications = request.form['medications']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM patients WHERE id = %s", (session['id'],))
        patient = cursor.fetchone()

        if not patient:
            flash('Patient not found.', 'danger')
            return redirect(url_for('upload'))

        data = f"{blood_group}|{blood_pressure}|{body_temp}|{pulse_rate}|{medications}"
        encrypted_data = aes.encrypt(data)

        cursor.execute("""
            INSERT INTO medical_records (patient_id, encrypted_data)
            VALUES (%s, %s)
        """, (patient['patient_id'], encrypted_data))
        mysql.connection.commit()
        cursor.close()

        flash('Medical data uploaded and encrypted successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload_data.html')

# ------------------- Decrypt Key ------------------- #
@app.route('/decrypt_key', methods=['GET', 'POST'])
def decrypt_key():
    encrypted_keys = []
    decrypted_data = {}
    edit_mode = False

    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
            SELECT patient_id, blood_group, blood_pressure, body_temp, pulse_rate, previous_medications, updated_time, encrypted_data
            FROM medical_records
            WHERE patient_id = %s
        ''', (session['patient_id'],))
        records = cursor.fetchall()
        cursor.close()

        for record in records:
            if record['encrypted_data']:
                if isinstance(record['encrypted_data'], str):
                    record_bytes = record['encrypted_data'].encode('utf-8')
                else:
                    record_bytes = record['encrypted_data']
                record['encrypted_data'] = base64.b64encode(record_bytes).decode('utf-8')
            encrypted_keys.append(record)

    if request.method == 'POST':
        action = request.form.get('action')
        encrypted_key = request.form.get('encrypted_key')

        user_keys = [record['encrypted_data'] for record in encrypted_keys]
        if encrypted_key not in user_keys:
            flash("Unauthorized attempt.", 'danger')
            return redirect(url_for('decrypt_key'))

        if action == 'decrypt' or action == 'edit':
            try:
                decrypted_text = aes.decrypt(base64.b64decode(encrypted_key))
                decrypted_values = decrypted_text.split('|')

                if len(decrypted_values) == 5:
                    blood_group, blood_pressure, body_temp, pulse_rate, medications = decrypted_values
                    decrypted_data = {
                        'Blood Group': blood_group,
                        'Blood Pressure': blood_pressure,
                        'Body Temperature': body_temp,
                        'Pulse Rate': pulse_rate,
                        'Previous Medications': medications,
                        'encrypted_key': encrypted_key
                    }
                    edit_mode = (action == 'edit')
                else:
                    flash("Decryption failed: Invalid data format", 'danger')

            except Exception as e:
                flash(f"Decryption failed: {str(e)}", 'danger')

        elif action == 'update':
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                blood_group = request.form.get('blood_group')
                blood_pressure = request.form.get('blood_pressure')
                body_temp = request.form.get('body_temp')
                pulse_rate = request.form.get('pulse_rate')
                medications = request.form.get('previous_medications')

                new_data = f"{blood_group}|{blood_pressure}|{body_temp}|{pulse_rate}|{medications}"
                new_encrypted_data = aes.encrypt(new_data)

                cursor.execute('''
                    UPDATE medical_records 
                    SET blood_group = %s, blood_pressure = %s, body_temp = %s, 
                        pulse_rate = %s, previous_medications = %s, 
                        encrypted_data = %s, updated_time = NOW()
                    WHERE patient_id = %s AND encrypted_data = %s
                ''', (blood_group, blood_pressure, body_temp, pulse_rate, 
                      medications, new_encrypted_data, session['patient_id'], 
                      base64.b64decode(encrypted_key)))
                
                mysql.connection.commit()
                cursor.close()
                flash("Record updated successfully", 'success')
                return redirect(url_for('decrypt_key'))

            except Exception as e:
                flash(f"Update failed: {str(e)}", 'danger')

        elif action == 'delete':
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('''
                    DELETE FROM medical_records 
                    WHERE patient_id = %s AND encrypted_data = %s
                ''', (session['patient_id'], base64.b64decode(encrypted_key)))
                
                mysql.connection.commit()
                cursor.close()
                flash("Record deleted successfully", 'success')
                return redirect(url_for('decrypt_key'))

            except Exception as e:
                flash(f"Delete failed: {str(e)}", 'danger')

    return render_template('decrypt_form.html', 
                         encrypted_keys=encrypted_keys, 
                         decrypted_data=decrypted_data,
                         edit_mode=edit_mode)

from flask import Flask, request, render_template, flash, redirect, url_for, session
import MySQLdb.cursors
import plotly.graph_objects as go

# ------------------- Cloud Server Route ------------------- #
@app.route('/cloud_server', methods=['GET', 'POST'])
def cloud_server():
    # Enforce login check with consistent session key
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud_login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Handle POST requests for CRUD operations
    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')

        try:
            if not action or not entity:
                flash("Action and entity type are required.", "danger")
                return redirect(url_for('cloud_server'))

            # Patient-specific actions
            if entity == 'patient':
                patient_id = request.form.get('patient_id')
                if not patient_id:
                    flash("Patient ID is required.", "danger")
                    return redirect(url_for('cloud_server'))

                if action == 'create':
                    name = request.form.get('name')
                    email = request.form.get('email')
                    phone = request.form.get('phone')
                    address = request.form.get('address')
                    cursor.execute("""
                        INSERT INTO patients (patient_id, name, email, phone, address, is_activated)
                        VALUES (%s, %s, %s, %s, %s, '1')
                    """, (patient_id, name, email, phone, address))
                    mysql.connection.commit()
                    flash(f"Patient {name} added successfully.", "success")

                elif action == 'update':
                    name = request.form.get('name')
                    email = request.form.get('email')
                    phone = request.form.get('phone')
                    address = request.form.get('address')
                    cursor.execute("""
                        UPDATE patients 
                        SET name = %s, email = %s, phone = %s, address = %s 
                        WHERE patient_id = %s
                    """, (name, email, phone, address, patient_id))
                    mysql.connection.commit()
                    flash(f"Patient {patient_id} updated successfully.", "success")

                elif action == 'delete':
                    cursor.execute("DELETE FROM patients WHERE patient_id = %s", (patient_id,))
                    mysql.connection.commit()
                    flash(f"Patient {patient_id} deleted successfully.", "danger")

                elif action in ['activate', 'deactivate']:
                    activation_status = '1' if action == 'activate' else '0'
                    cursor.execute("""
                        UPDATE patients 
                        SET is_activated = %s 
                        WHERE patient_id = %s
                    """, (activation_status, patient_id))
                    mysql.connection.commit()
                    flash(f"Patient {patient_id} has been {'activated' if activation_status == '1' else 'deactivated'}.", "info")

            # Doctor-specific actions
            elif entity == 'doctor':
                doctor_id = request.form.get('doctor_id')
                if not doctor_id:
                    flash("Doctor ID is required.", "danger")
                    return redirect(url_for('cloud_server'))

                if action == 'update':
                    name = request.form.get('name')
                    email = request.form.get('email')
                    phone = request.form.get('phone')
                    specialization = request.form.get('specialization')
                    cursor.execute("""
                        UPDATE doctors
                        SET name = %s, email = %s, phone = %s, specialization = %s
                        WHERE doctor_id = %s
                    """, (name, email, phone, specialization, doctor_id))
                    mysql.connection.commit()
                    flash(f"Doctor {doctor_id} updated successfully.", "success")

                elif action == 'delete':
                    cursor.execute("DELETE FROM doctors WHERE doctor_id = %s", (doctor_id,))
                    mysql.connection.commit()
                    flash(f"Doctor {doctor_id} deleted successfully.", "danger")

                elif action in ['activate', 'deactivate']:
                    activation_status = '1' if action == 'activate' else '0'
                    cursor.execute("""
                        UPDATE doctors 
                        SET is_activated = %s 
                        WHERE doctor_id = %s
                    """, (activation_status, doctor_id))
                    mysql.connection.commit()
                    flash(f"Doctor {doctor_id} has been {'activated' if activation_status == '1' else 'deactivated'}.", "info")

            else:
                flash("Invalid entity type.", "danger")

        except Exception as e:
            mysql.connection.rollback()
            flash(f"An error occurred: {str(e)}", "danger")

        finally:
            return redirect(url_for('cloud_server'))

    # Fetch data for patients and doctors
    cursor.execute("SELECT id, patient_id, name, email, phone, address, is_activated FROM patients")
    patients = cursor.fetchall()

    cursor.execute("SELECT doctor_id, name, email, phone, specialization, is_activated FROM doctors")
    doctors = cursor.fetchall()

    # Graph: Pie Chart (Patients vs Doctors Distribution)
    cursor.execute('SELECT COUNT(*) as patient_count FROM patients')
    patient_count = cursor.fetchone()['patient_count']
    cursor.execute('SELECT COUNT(*) as doctor_count FROM doctors')
    doctor_count = cursor.fetchone()['doctor_count']
    
    pie_fig = go.Figure(data=[go.Pie(
        labels=['Patients', 'Doctors'],
        values=[patient_count, doctor_count],
        hole=0.3,
        marker_colors=['#9333ea', '#3b82f6'],
        textinfo='label+percent',
        textposition='inside'
    )])
    pie_fig.update_layout(
        title_text="Patients vs Doctors Distribution",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    pie_graph = pie_fig.to_html(full_html=False)

    # Graph: Bar Chart (Medical Records Over Time)
    cursor.execute('SELECT DATE(updated_time) as date, COUNT(*) as count FROM medical_records GROUP BY DATE(updated_time)')
    records_data = cursor.fetchall()
    dates = [row['date'] for row in records_data]
    counts = [row['count'] for row in records_data]
    
    bar_fig = go.Figure(data=[go.Bar(
        x=dates,
        y=counts,
        marker_color='#9333ea',
        text=counts,
        textposition='auto'
    )])
    bar_fig.update_layout(
        title_text="Medical Records Creation Over Time",
        xaxis_title="Date",
        yaxis_title="Number of Records",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    bar_graph = bar_fig.to_html(full_html=False)

    # Graph: Line Chart (Simulated Cryptographic Operation Times)
    cursor.execute('SELECT updated_time, encrypted_data FROM medical_records WHERE patient_id = %s', (session.get('patient_id', 'default_patient_id'),))
    crypto_data = cursor.fetchall()
    times = [row['updated_time'] for row in crypto_data]
    encryption_times = [len(row['encrypted_data']) * 0.1 for row in crypto_data]
    
    line_fig = go.Figure(data=[go.Scatter(
        x=times,
        y=encryption_times,
        mode='lines+markers',
        line_color='#3b82f6',
        marker=dict(size=8)
    )])
    line_fig.update_layout(
        title_text="Simulated Cryptographic Operation Times",
        xaxis_title="Record Creation Time",
        yaxis_title="Operation Time (ms)",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    line_graph = line_fig.to_html(full_html=False)

    # Graph: Bar Chart (Patients per Doctor)
    cursor.execute('''
        SELECT d.name, COUNT(dp.patient_id) as patient_count 
        FROM doctors d 
        LEFT JOIN doctor_patient dp ON d.doctor_id = dp.doctor_id 
        GROUP BY d.doctor_id, d.name
    ''')
    dp_data = cursor.fetchall()
    doctor_names = [row['name'] for row in dp_data]
    patient_counts = [row['patient_count'] for row in dp_data]
    
    dp_fig = go.Figure(data=[go.Bar(
        x=doctor_names,
        y=patient_counts,
        marker_color='#9333ea',
        text=patient_counts,
        textposition='auto'
    )])
    dp_fig.update_layout(
        title_text="Patients per Doctor",
        xaxis_title="Doctor Name",
        yaxis_title="Number of Patients",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='white'
    )
    dp_graph = dp_fig.to_html(full_html=False)

    cursor.close()

    return render_template('cloudserver.html', 
                         patients=patients, 
                         doctors=doctors,
                         pie_graph=pie_graph,
                         bar_graph=bar_graph,
                         line_graph=line_graph,
                         dp_graph=dp_graph)
# ------------------- Logout ------------------- #
# ------------------- Logout ------------------- #
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('cloud_login'))

# ------------------- Cloud Server Login with OTP ------------------- #
CLOUD_TOTP_SECRET = "JBSWY3DPEHPK3PXP"

@app.route('/cloud_login', methods=['GET', 'POST'])
def cloud_login():
    if 'cloud_loggedin' in session and session['cloud_loggedin']:
        return redirect(url_for('cloud_server'))  # Redirect if already logged in

    # Generate QR code for TOTP setup
    totp = pyotp.TOTP(CLOUD_TOTP_SECRET)
    qr_uri = totp.provisioning_uri(name="Cloud Server Admin", issuer_name="YourApp")
    qr = qrcode.make(qr_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

    if request.method == 'POST':
        otp = request.form.get('otp')  # Get combined OTP from hidden input
        if not otp or len(otp) != 6 or not otp.isdigit():
            return redirect(url_for('cloud_login', status='error'))  # Invalid OTP format

        if totp.verify(otp):
            session['cloud_loggedin'] = True
            return redirect(url_for('cloud_server', status='success'))  # Redirect with success status
        else:
            return redirect(url_for('cloud_login', status='error'))  # Redirect with error status

    return render_template('cloud_login.html', qr_code=qr_code)


@app.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        while True:
            random_number = secrets.randbelow(10**6)
            doctor_id = f"DD{str(random_number).zfill(6)}"
            cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
            if not cursor.fetchone():
                break

        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        specialization = request.form['specialization']
        password = request.form['password']

        cursor.execute("""
            INSERT INTO doctors (doctor_id, name, email, phone, specialization, password, is_activated) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (doctor_id, name, email, phone, specialization, password, '0'))
        mysql.connection.commit()
        cursor.close()

        flash(f"Doctor {name} registered successfully with ID {doctor_id}.", 'success')
        return redirect(url_for('register_doctor'))

    return render_template('register_doctor.html')

@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("""
            SELECT * FROM doctors 
            WHERE email = %s AND password = %s AND is_activated = '1'
        """, (email, password))
        doctor = cursor.fetchone()

        if doctor:
            session['doctor_id'] = doctor['doctor_id']
            flash(f"Welcome Dr. {doctor['name']}!", 'success')
            return redirect(url_for('doctor_dashboard'))
        else:
            flash("Invalid credentials or account not activated.", 'danger')

    return render_template('doctor_login.html')

@app.route('/doctor_logout')
def doctor_logout():
    session.pop('doctor_id', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('doctor_login'))


@app.route('/appointments', methods=['GET', 'POST'])
def appointments():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if 'loggedin' not in session:
        flash("Please log in to book an appointment.", 'warning')
        return redirect(url_for('login'))

    # Handle POST request (new appointment booking)
    if request.method == 'POST':
        if 'doctor_id' not in request.form:
            flash("Please select a doctor and fill all fields.", "danger")
            return redirect(url_for('appointments'))

        patient_id = session['patient_id']
        doctor_id = request.form['doctor_id']
        appointment_date = request.form['appointment_date']
        appointment_time = request.form['appointment_time']
        reason = request.form['reason']
        amount = "2"  # Fixed amount for now
        client_txn_id = str(uuid4()).replace('-', '')[:10]
        txn_date = datetime.now().strftime('%d-%m-%Y')

        # Generate unique URL upfront
        unique_url = str(uuid4()).replace('-', '')[:40]

        # Store in session
        session['pending_appointment'] = {
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'appointment_date': appointment_date,
            'appointment_time': appointment_time,
            'reason': reason,
            'unique_url': unique_url,
            'amount': amount,
            'client_txn_id': client_txn_id,
            'txn_date': txn_date,
            'payment_initiated': datetime.now().timestamp()
        }

        # Initiate payment
        redirect_url = "https://monkfish-engaging-kiwi.ngrok-free.app/appointments"  # Update with your actual URL
        payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "amount": amount,
            "p_info": "Doctor Appointment",
            "customer_name": session['name'],
            "customer_email": "patient@example.com",
            "customer_mobile": "9876543210",
            "redirect_url": redirect_url,
            "udf1": "", "udf2": "", "udf3": ""
        }
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(UPI_GATEWAY_CREATE_ORDER_URL, json=payload, headers=headers)
            result = response.json()
            if result.get("status") and "data" in result:
                payment_url = result["data"]["payment_url"]
                qr = qrcode.make(payment_url)
                buffer = BytesIO()
                qr.save(buffer, format="PNG")
                qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

                cursor.execute("SELECT * FROM doctors")
                doctors = cursor.fetchall()
                cursor.execute("""
                    SELECT a.*, d.name AS doctor_name 
                    FROM appointments a 
                    JOIN doctors d ON a.doctor_id = d.doctor_id 
                    WHERE a.patient_id = %s 
                    ORDER BY a.appointment_date ASC
                """, (patient_id,))
                patient_appointments = cursor.fetchall()
                cursor.close()

                return render_template('appointments.html', doctors=doctors, appointments=patient_appointments,
                                     show_payment=True, amount=amount, payment_url=payment_url,
                                     qr_code=qr_code, client_txn_id=client_txn_id)
            else:
                flash(f"Payment initiation failed: {result.get('msg', 'Unknown error')}", "danger")
        except Exception as e:
            flash(f"Payment gateway error: {str(e)}", "danger")
        return redirect(url_for('appointments'))

    # Handle GET request (check payment status or display appointments)
    if 'pending_appointment' in session:
        appt = session['pending_appointment']
        client_txn_id = appt['client_txn_id']
        txn_date = appt['txn_date']

        # Check payment status
        status_payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "txn_date": txn_date
        }
        try:
            status_response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
            status_result = status_response.json()
            if status_result.get("status") and status_result["data"].get("status") == "SUCCESS":
                # Check if already booked to avoid duplicates
                cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (client_txn_id,))
                if not cursor.fetchone():
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                          appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id))
                    mysql.connection.commit()
                session.pop('pending_appointment', None)
                flash("Appointment booked successfully! Awaiting doctor approval.", "success")
            elif status_result["data"].get("status") == "FAILED":
                flash("Payment failed. Please try again.", "danger")
                session.pop('pending_appointment', None)
        except Exception as e:
            flash(f"Error checking payment status: {str(e)}", "warning")

    # Default GET: Show appointments and doctors
    cursor.execute("SELECT * FROM doctors")
    doctors = cursor.fetchall()
    cursor.execute("""
        SELECT a.*, d.name AS doctor_name 
        FROM appointments a 
        JOIN doctors d ON a.doctor_id = d.doctor_id 
        WHERE a.patient_id = %s 
        ORDER BY a.appointment_date ASC
    """, (session['patient_id'],))
    patient_appointments = cursor.fetchall()
    cursor.close()

    return render_template('appointments.html', doctors=doctors, appointments=patient_appointments, show_payment=False)
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    print("Webhook received:", json.dumps(data, indent=2))
    if not data or 'client_txn_id' not in data:
        return "Invalid data", 400

    client_txn_id = data['client_txn_id']
    
    # Check session for pending appointment
    if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
        if data.get('status') == "success":
            appt = session['pending_appointment']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""
                INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                    appointment_time, reason, status, video_call_url, transaction_id)
                VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
            """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'], 
                  appt['appointment_time'], appt['reason'], appt['unique_url'], 
                  data.get('upi_txn_id', 'manual_check')))
            mysql.connection.commit()
            cursor.close()

            # Clear the pending appointment from session
            session.pop('pending_appointment', None)
        elif data.get('status') == "failure":
            session.pop('pending_appointment', None)
        else:
            print("Webhook status pending:", data.get('status'))
    else:
        # Handle the case where the webhook arrives but session might be expired or different
        print("Webhook received but no matching pending_appointment in session")
        if data.get('status') == "success":
            # Check database to see if this transaction was already processed
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", 
                          (data.get('upi_txn_id', 'not_found'),))
            existing = cursor.fetchone()
            
            # If not found in DB and payment successful, store in a pending_webhooks table
            if not existing and data.get('status') == "success":
                try:
                    cursor.execute("""
                        INSERT INTO pending_webhooks (client_txn_id, upi_txn_id, status, data, received_at)
                        VALUES (%s, %s, %s, %s, NOW())
                    """, (client_txn_id, data.get('upi_txn_id'), data.get('status'), json.dumps(data)))
                    mysql.connection.commit()
                except Exception as e:
                    print("Failed to store webhook data:", str(e))
            cursor.close()
            
    return "Webhook received", 200

@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json()
    client_txn_id = data.get('client_txn_id')
    
    # First check if this transaction ID exists in session
    if not client_txn_id:
        return jsonify({'status': 'INVALID', 'message': 'No transaction ID provided'}), 400
        
    if 'pending_appointment' not in session or session['pending_appointment']['client_txn_id'] != client_txn_id:
        # Check if this might be a transaction that was completed but session expired
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (client_txn_id,))
        existing = cursor.fetchone()
        cursor.close()
        
        if existing:
            return jsonify({'status': 'SUCCESS', 'message': 'Appointment already booked'}), 200
        
        print("Invalid status check request:", data)
        return jsonify({'status': 'INVALID', 'message': 'No matching transaction found'}), 400

    appt = session['pending_appointment']
    status_payload = {
        "key": UPI_GATEWAY_API_KEY,
        "client_txn_id": client_txn_id,
        "txn_date": appt['txn_date']
    }
    
    try:
        response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
        result = response.json()
        print("Check payment status result:", json.dumps(result, indent=2))
        
        if result.get("status"):
            payment_status = result["data"].get("status", "").lower()
            
            # If payment was successful, create the appointment
            if payment_status == "success" or payment_status == "success":
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                
                # Check if appointment was already created (avoid duplicates)
                cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", 
                              (result["data"].get("upi_txn_id", "not_found"),))
                existing = cursor.fetchone()
                
                if not existing:
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'], 
                          appt['appointment_time'], appt['reason'], appt['unique_url'], 
                          result["data"].get("upi_txn_id", "manual_check")))
                    mysql.connection.commit()
                
                cursor.close()
                session.pop('pending_appointment', None)
                
            return jsonify({
                'status': result["data"].get("status", "UNKNOWN"),
                'message': result["data"].get("msg", "")
            })
        return jsonify({'status': 'UNKNOWN', 'message': 'Could not determine payment status'})
    except Exception as e:
        print("Check payment status failed:", str(e))
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500

@app.route('/doctor_dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    if 'doctor_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('doctor_login'))

    doctor_id = session['doctor_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        appointment_id = request.form['appointment_id']
        action = request.form['action']

        if action == 'Accept':
            unique_url = str(uuid4()).replace('-', '')[:40]
            cursor.execute("""
                UPDATE appointments 
                SET status = 'Confirmed', video_call_url = %s 
                WHERE appointment_id = %s
            """, (unique_url, appointment_id))
        elif action == 'Reject':
            cursor.execute("""
                UPDATE appointments 
                SET status = 'Cancelled' 
                WHERE appointment_id = %s
            """, (appointment_id,))

        mysql.connection.commit()
        flash(f"Appointment {action}ed successfully!", "success")
        return redirect(url_for('doctor_dashboard'))

    cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
    doctor = cursor.fetchone()

    cursor.execute("""
        SELECT DISTINCT p.patient_id, p.name, p.dob, p.phone AS contact
        FROM patients p
        JOIN appointments a ON p.patient_id = a.patient_id
        WHERE a.doctor_id = %s
    """, (doctor_id,))
    patients = cursor.fetchall()

    cursor.execute("""
        SELECT a.*, p.name AS patient_name 
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        WHERE a.doctor_id = %s
        ORDER BY a.appointment_date ASC
    """, (doctor_id,))
    appointments = cursor.fetchall()

    cursor.close()

    return render_template('doctor_dashboard.html', doctor=doctor, patients=patients, appointments=appointments)

@app.route('/join_video/<unique_url>')
def join_video(unique_url):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute("""
        SELECT a.*, p.name AS patient_name, d.name AS doctor_name
        FROM appointments a
        JOIN patients p ON a.patient_id = p.patient_id
        JOIN doctors d ON a.doctor_id = d.doctor_id
        WHERE a.video_call_url = %s AND a.status = 'Confirmed'
    """, (unique_url,))
    appointment = cursor.fetchone()
    cursor.close()

    if not appointment:
        flash("Invalid or unauthorized video call link!", "danger")
        return redirect(url_for('appointments'))

    current_time = datetime.now()
    appt_datetime = datetime.strptime(
        f"{appointment['appointment_date']} {appointment['appointment_time']}",
        "%Y-%m-%d %H:%M:%S"
    )
    
    if abs((current_time - appt_datetime).total_seconds()) > 900:  # 15 minutes window
        flash("Video call is only available at scheduled time!", "warning")
        return redirect(url_for('appointments'))

    return render_template('video_call.html', appointment=appointment)
# ------------------- Error Handler ------------------- #
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__== "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)