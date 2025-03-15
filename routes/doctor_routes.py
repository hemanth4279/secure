from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from config import AES_SECRET_KEY
from utils.encryption import AESEncryption
import MySQLdb.cursors
import base64
from uuid import uuid4
import secrets
import pyotp
from mail import send_otp_email, send_activation_email
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

doctor_bp = Blueprint('doctor', __name__)

mysql = MySQL()
aes = AESEncryption(AES_SECRET_KEY)

# Helper functions for digital signatures
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem

def sign_data(private_key_pem, data):
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

@doctor_bp.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        if 'otp' not in request.form:
            name = request.form['name']
            email = request.form['email']
            phone = request.form['phone']
            specialization = request.form['specialization']
            password = request.form['password']

            while True:
                random_number = secrets.randbelow(10**6)
                doctor_id = f"DD{str(random_number).zfill(6)}"
                cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
                if not cursor.fetchone():
                    break

            # Generate RSA key pair
            private_key, public_key = generate_key_pair()

            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret, interval=600)
            otp = totp.now()
            session['otp_secret'] = secret
            session['doctor_data'] = {
                'doctor_id': doctor_id, 'name': name, 'email': email,
                'phone': phone, 'specialization': specialization, 'password': password,
                'private_key': private_key, 'public_key': public_key
            }

            send_otp_email(email, otp)
            flash("OTP sent to your email. Please verify.", 'info')
            return render_template('verify_otp.html', email=email)

        else:
            otp_input = request.form['otp']
            secret = session.get('otp_secret')
            if not secret:
                flash("Session expired. Please register again.", 'danger')
                return redirect(url_for('doctor.register_doctor'))
                
            totp = pyotp.TOTP(secret, interval=600)
            if totp.verify(otp_input, valid_window=1):
                doctor_data = session.pop('doctor_data')
                cursor.execute("""
                    INSERT INTO doctors (doctor_id, name, email, phone, specialization, password, is_activated, private_key, public_key) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (doctor_data['doctor_id'], doctor_data['name'], doctor_data['email'],
                      doctor_data['phone'], doctor_data['specialization'], doctor_data['password'], '0',
                      doctor_data['private_key'], doctor_data['public_key']))
                mysql.connection.commit()
                flash(f"Doctor {doctor_data['name']} registered successfully with ID {doctor_data['doctor_id']}. Awaiting cloud activation.", 'success')
                session.pop('otp_secret', None)
            else:
                flash("Invalid OTP. Please try again.", 'danger')
                return render_template('verify_otp.html', email=session['doctor_data']['email'])

            cursor.close()
            return redirect(url_for('doctor.register_doctor'))

    cursor.close()
    return render_template('register_doctor.html')

@doctor_bp.route('/doctor_login', methods=['GET', 'POST'])
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
            return redirect(url_for('doctor.doctor_dashboard'))
        else:
            flash("Invalid credentials or account not activated.", 'danger')

    return render_template('doctor_login.html')

@doctor_bp.route('/doctor_logout')
def doctor_logout():
    session.pop('doctor_id', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('doctor.doctor_login'))

@doctor_bp.route('/doctor_dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    if 'doctor_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('doctor.doctor_login'))

    doctor_id = session['doctor_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    decrypted_report = None

    if request.method == 'POST':
        action = request.form.get('action')

        if 'appointment_id' in request.form and action in ['Accept', 'Reject']:
            appointment_id = request.form['appointment_id']
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

        elif action == 'request_access':
            patient_id = request.form.get('patient_id')
            if patient_id:
                cursor.execute("""
                    INSERT INTO doctor_requests (doctor_id, patient_id, status)
                    VALUES (%s, %s, 'pending')
                """, (doctor_id, patient_id))
                mysql.connection.commit()
                flash(f"Data access request for patient {patient_id} submitted successfully!", "success")
            else:
                flash("Please select a patient to request access.", "danger")

        elif action == 'view_report':
            decryption_key = request.form.get('decryption_key')
            if decryption_key:
                cursor.execute("""
                    SELECT dr.patient_id, p.name AS patient_name, mr.encrypted_data,
                           mr.blood_group, mr.blood_pressure, mr.body_temp, 
                           mr.pulse_rate, mr.previous_medications, mr.updated_time
                    FROM doctor_requests dr
                    JOIN patients p ON dr.patient_id = p.patient_id
                    LEFT JOIN medical_records mr ON dr.patient_id = mr.patient_id
                    WHERE dr.doctor_id = %s AND dr.decryption_key = %s AND dr.status = 'accepted'
                """, (doctor_id, decryption_key))
                report = cursor.fetchone()

                if report and report['encrypted_data']:
                    if isinstance(report['encrypted_data'], str):
                        record_bytes = report['encrypted_data'].encode('utf-8')
                    else:
                        record_bytes = report['encrypted_data']
                    encrypted_data_base64 = base64.b64encode(record_bytes).decode('utf-8')

                    if decryption_key == encrypted_data_base64:
                        try:
                            decrypted_text = aes.decrypt(base64.b64decode(decryption_key))
                            decrypted_values = decrypted_text.split('|')

                            if len(decrypted_values) == 5:
                                blood_group, blood_pressure, body_temp, pulse_rate, medications = decrypted_values
                                decrypted_report = {
                                    'patient_name': report['patient_name'],
                                    'patient_id': report['patient_id'],
                                    'blood_group': blood_group,
                                    'blood_pressure': blood_pressure,
                                    'body_temp': body_temp,
                                    'pulse_rate': pulse_rate,
                                    'previous_medications': medications,
                                    'updated_time': report['updated_time'],
                                    'encrypted_data': encrypted_data_base64
                                }
                                flash("Report decrypted successfully!", "success")
                            else:
                                flash("Decryption failed: Invalid data format", "danger")
                        except Exception as e:
                            flash(f"Decryption failed: {str(e)}", "danger")
                    else:
                        flash("Decryption key does not match the encrypted data.", "danger")
                        decrypted_report = {
                            'patient_name': report['patient_name'],
                            'patient_id': report['patient_id'],
                            'blood_group': report['blood_group'],
                            'blood_pressure': report['blood_pressure'],
                            'body_temp': report['body_temp'],
                            'pulse_rate': report['pulse_rate'],
                            'previous_medications': report['previous_medications'],
                            'updated_time': report['updated_time'],
                            'encrypted_data': encrypted_data_base64
                        }
                elif report:
                    flash("No encrypted data available, showing plain text fields.", "info")
                    decrypted_report = {
                        'patient_name': report['patient_name'],
                        'patient_id': report['patient_id'],
                        'blood_group': report['blood_group'],
                        'blood_pressure': report['blood_pressure'],
                        'body_temp': report['body_temp'],
                        'pulse_rate': report['pulse_rate'],
                        'previous_medications': report['previous_medications'],
                        'updated_time': report['updated_time'],
                        'encrypted_data': 'N/A'
                    }
                else:
                    flash("Invalid or unauthorized decryption key.", "danger")

        elif action == 'assign_doctor':
            patient_id = request.form.get('patient_id')
            if patient_id:
                cursor.execute("SELECT private_key FROM doctors WHERE doctor_id = %s", (doctor_id,))
                doctor = cursor.fetchone()
                assignment_message = f"Assign {doctor_id} to {patient_id}"
                signature = sign_data(doctor['private_key'], assignment_message)
                cursor.execute("""
                    INSERT INTO doctor_patient (doctor_id, patient_id, status, signature)
                    VALUES (%s, %s, 'active', %s)
                    ON DUPLICATE KEY UPDATE status = 'active', signature = %s
                """, (doctor_id, patient_id, signature, signature))
                mysql.connection.commit()
                flash(f"Assigned to patient {patient_id} with digital signature.", "success")

        elif action == 'create_prescription':
            patient_id = request.form.get('patient_id')
            medicine_id = request.form.get('medicine_id')
            dosage = request.form.get('dosage')
            duration = request.form.get('duration')
            instructions = request.form.get('instructions')
            appointment_id = request.form.get('appointment_id') or None

            if not all([patient_id, medicine_id, dosage, duration]):
                flash("All fields (Patient, Medicine, Dosage, Duration) are required.", "danger")
            else:
                cursor.execute("SELECT private_key FROM doctors WHERE doctor_id = %s", (doctor_id,))
                doctor = cursor.fetchone()
                prescription_message = f"{doctor_id}|{patient_id}|{appointment_id or 'None'}|{medicine_id}|{dosage}|{duration}|{instructions or 'None'}"
                signature = sign_data(doctor['private_key'], prescription_message)

                cursor.execute("""
                    INSERT INTO prescriptions (appointment_id, doctor_id, patient_id, medicine_id, dosage, duration, instructions, signature, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pending')
                """, (appointment_id, doctor_id, patient_id, medicine_id, dosage, duration, instructions, signature))
                mysql.connection.commit()
                flash("Prescription created successfully with digital signature!", "success")

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

    cursor.execute("SELECT patient_id, name FROM patients")
    all_patients = cursor.fetchall()

    cursor.execute("""
        SELECT dr.id, dr.patient_id, dr.status, dr.decryption_key, p.name as patient_name
        FROM doctor_requests dr
        JOIN patients p ON dr.patient_id = p.patient_id
        WHERE dr.doctor_id = %s
    """, (doctor_id,))
    requests = cursor.fetchall()

    cursor.execute("""
        SELECT pr.prescription_id, pr.patient_id, pr.medicine_id, m.name AS medicine_name,
               pr.dosage, pr.duration, pr.status AS prescription_status,
               po.pharmacy_order_id, po.total_amount, po.status AS order_status,
               ph.name AS pharmacy_name
        FROM prescriptions pr
        JOIN medicines m ON pr.medicine_id = m.medicine_id
        LEFT JOIN pharmacy_orders po ON pr.prescription_id = po.prescription_id
        LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
        WHERE pr.doctor_id = %s
        ORDER BY pr.prescribed_date DESC
    """, (doctor_id,))
    prescriptions = cursor.fetchall()

    cursor.execute("SELECT medicine_id, name, brand FROM medicines")
    medicines = cursor.fetchall()

    cursor.close()

    return render_template('doctor_dashboard.html', 
                         doctor=doctor, 
                         patients=patients, 
                         appointments=appointments,
                         all_patients=all_patients,
                         requests=requests, 
                         report=decrypted_report,
                         prescriptions=prescriptions,
                         medicines=medicines)