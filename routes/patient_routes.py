from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from config import AES_SECRET_KEY
from utils.encryption import AESEncryption
import MySQLdb.cursors
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

patient_bp = Blueprint('patient', __name__)

mysql = MySQL()
aes = AESEncryption(AES_SECRET_KEY)

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

@patient_bp.route('/dashboard')
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('auth.login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM patients WHERE patient_id = %s', (session['patient_id'],))
    patient = cursor.fetchone()

    cursor.execute("""
        SELECT pr.prescription_id, pr.medicine_id, m.name AS medicine_name,
               pr.dosage, pr.duration, pr.status AS prescription_status,
               d.name AS doctor_name,
               po.pharmacy_order_id, po.total_amount, po.status AS order_status,
               ph.name AS pharmacy_name
        FROM prescriptions pr
        JOIN medicines m ON pr.medicine_id = m.medicine_id
        JOIN doctors d ON pr.doctor_id = d.doctor_id
        LEFT JOIN pharmacy_orders po ON pr.prescription_id = po.prescription_id
        LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
        WHERE pr.patient_id = %s
        ORDER BY pr.prescribed_date DESC
    """, (session['patient_id'],))
    prescriptions = cursor.fetchall()

    cursor.close()
    return render_template('dashboard.html', patient=patient, prescriptions=prescriptions)

@patient_bp.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('patient_id', None)
    return redirect(url_for('auth.login'))

@patient_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'loggedin' not in session:
        flash('Please login to upload medical data.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        blood_group = request.form['blood_group']
        blood_pressure = request.form['blood_pressure']
        body_temp = request.form['body_temp']
        pulse_rate = request.form['pulse_rate']
        medications = request.form['medications']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (session['patient_id'],))
        patient = cursor.fetchone()

        if not patient:
            flash('Patient not found.', 'danger')
            return redirect(url_for('patient.upload'))

        data = f"{blood_group}|{blood_pressure}|{body_temp}|{pulse_rate}|{medications}"
        encrypted_data = aes.encrypt(data)

        cursor.execute("""
            INSERT INTO medical_records (patient_id, encrypted_data)
            VALUES (%s, %s)
        """, (patient['patient_id'], encrypted_data))
        mysql.connection.commit()
        cursor.close()

        flash('Medical data uploaded and encrypted successfully.', 'success')
        return redirect(url_for('patient.dashboard'))

    return render_template('upload_data.html')

@patient_bp.route('/decrypt_key', methods=['GET', 'POST'])
def decrypt_key():
    encrypted_keys = []
    decrypted_data = {}
    edit_mode = False

    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
            SELECT patient_id, blood_group, blood_pressure, body_temp, pulse_rate, 
                   previous_medications, updated_time, encrypted_data
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
            return redirect(url_for('patient.decrypt_key'))

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
                return redirect(url_for('patient.decrypt_key'))

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
                return redirect(url_for('patient.decrypt_key'))

            except Exception as e:
                flash(f"Delete failed: {str(e)}", 'danger')

    return render_template('decrypt_form.html', 
                         encrypted_keys=encrypted_keys, 
                         decrypted_data=decrypted_data,
                         edit_mode=edit_mode)

@patient_bp.route('/verify_doctor', methods=['GET', 'POST'])
def verify_doctor():
    if 'loggedin' not in session:
        flash('Please login to verify doctor.', 'warning')
        return redirect(url_for('auth.login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    verification_result = None

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        patient_id = session['patient_id']

        cursor.execute("""
            SELECT dp.signature, d.public_key
            FROM doctor_patient dp
            JOIN doctors d ON dp.doctor_id = d.doctor_id
            WHERE dp.doctor_id = %s AND dp.patient_id = %s AND dp.status = 'active'
        """, (doctor_id, patient_id))
        result = cursor.fetchone()

        if result:
            assignment_message = f"Assign {doctor_id} to {patient_id}"
            is_valid = verify_signature(result['public_key'], assignment_message, result['signature'])
            verification_result = "Doctor verified successfully." if is_valid else "Doctor verification failed."
            flash(verification_result, "success" if is_valid else "danger")
        else:
            flash("No active assignment found for this doctor.", "danger")

    cursor.close()
    return render_template('verify_doctor.html', verification_result=verification_result)