from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
import MySQLdb.cursors
import requests
import qrcode
from io import BytesIO
import base64
from uuid import uuid4
from datetime import datetime
import json

appointment_bp = Blueprint('appointment', __name__)

# Global variable to store dependency
db = None
UPI_GATEWAY_API_KEY = "eb8414ec-1f13-4c8f-b713-ae55fbc94a97"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

def init_appointment(mysql):
    global db
    db = mysql
    return appointment_bp

# Helper function to check if appointment exists
def appointment_exists(cursor, transaction_id):
    cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (transaction_id,))
    return cursor.fetchone() is not None

# Appointments Route
@appointment_bp.route('/appointments', methods=['GET', 'POST'])
def appointments():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))

    if 'loggedin' not in session:
        flash("Please log in to book an appointment.", 'warning')
        return redirect(url_for('auth.login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if request.method == 'POST':
            if 'doctor_id' not in request.form:
                flash("Please select a doctor and fill all fields.", "danger")
                return redirect(url_for('appointment.appointments'))

            patient_id = session['patient_id']
            doctor_id = request.form['doctor_id']
            appointment_date = request.form['appointment_date']
            appointment_time = request.form['appointment_time']
            reason = request.form['reason']
            amount = "2"
            client_txn_id = str(uuid4()).replace('-', '')[:10]
            txn_date = datetime.now().strftime('%d-%m-%Y')
            unique_url = str(uuid4()).replace('-', '')[:40]

            # Store pending appointment in session
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

            redirect_url = "https://monkfish-engaging-kiwi.ngrok-free.app/appointments"
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

                return render_template('appointments.html', doctors=doctors, appointments=patient_appointments,
                                       show_payment=True, amount=amount, payment_url=payment_url,
                                       qr_code=qr_code, client_txn_id=client_txn_id)
            else:
                flash(f"Payment initiation failed: {result.get('msg', 'Unknown error')}", "danger")
                return redirect(url_for('appointment.appointments'))

        # Check for pending appointment and verify payment status
        if 'pending_appointment' in session:
            appt = session['pending_appointment']
            client_txn_id = appt['client_txn_id']
            txn_date = appt['txn_date']

            status_payload = {
                "key": UPI_GATEWAY_API_KEY,
                "client_txn_id": client_txn_id,
                "txn_date": txn_date
            }
            status_response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
            status_result = status_response.json()

            if status_result.get("status") and status_result["data"].get("status") == "SUCCESS":
                if not appointment_exists(cursor, client_txn_id):
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                          appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id))
                    db.connection.commit()
                session.pop('pending_appointment', None)
                flash("Appointment booked successfully! Awaiting doctor approval.", "success")
            elif status_result["data"].get("status") == "FAILED":
                flash("Payment failed. Please try again.", "danger")
                session.pop('pending_appointment', None)

        # Fetch doctors and appointments for display
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

        return render_template('appointments.html', doctors=doctors, appointments=patient_appointments, show_payment=False)

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('appointment.appointments'))
    finally:
        cursor.close()

# Webhook Route
@appointment_bp.route('/webhook', methods=['POST'])
def webhook():
    if db is None:
        print("Database connection not initialized for webhook.")
        return "Server error", 500

    data = request.get_json() or request.form.to_dict()
    if not data or 'client_txn_id' not in data:
        print("Webhook data missing or no client_txn_id:", data)
        return "Invalid data", 400

    client_txn_id = data['client_txn_id']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if data.get('status') == "success":
            cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (client_txn_id,))
            if not cursor.fetchone():
                # If no session data, we might need to fetch from a temporary store or logs (not implemented here)
                # For now, assume webhook provides enough data or rely on prior session handling
                if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
                    appt = session['pending_appointment']
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                          appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id))
                    db.connection.commit()
                    session.pop('pending_appointment', None)
            return "Webhook processed", 200
        elif data.get('status') == "failure":
            if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
                session.pop('pending_appointment', None)
            return "Webhook processed (payment failed)", 200
        return "Webhook received, no action taken", 200

    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return "Webhook error", 500
    finally:
        cursor.close()

# Check Payment Status Route
@appointment_bp.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    if db is None:
        return jsonify({'status': 'ERROR', 'message': 'Database connection not initialized'}), 500

    data = request.get_json()
    client_txn_id = data.get('client_txn_id')
    if not client_txn_id:
        return jsonify({'status': 'INVALID', 'message': 'No transaction ID provided'}), 400

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Check if appointment already exists
        if appointment_exists(cursor, client_txn_id):
            return jsonify({'status': 'SUCCESS', 'message': 'Appointment already booked'}), 200

        # If no appointment exists, check payment status
        if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
            appt = session['pending_appointment']
            status_payload = {
                "key": UPI_GATEWAY_API_KEY,
                "client_txn_id": client_txn_id,
                "txn_date": appt['txn_date']
            }
            response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
            result = response.json()

            if result.get("status") and result["data"].get("status", "").lower() == "success":
                cursor.execute("""
                    INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                        appointment_time, reason, status, video_call_url, transaction_id)
                    VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s)
                """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                      appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id))
                db.connection.commit()
                session.pop('pending_appointment', None)
                return jsonify({'status': 'SUCCESS', 'message': 'Payment successful'}), 200
            elif result["data"].get("status", "").lower() == "failed":
                session.pop('pending_appointment', None)
                return jsonify({'status': 'FAILED', 'message': 'Payment failed'}), 200
            return jsonify({'status': 'PENDING', 'message': 'Payment still pending'}), 200

        return jsonify({'status': 'INVALID', 'message': 'No matching transaction found'}), 400

    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500
    finally:
        cursor.close()