from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import qrcode
from io import BytesIO
import base64
from uuid import uuid4
from datetime import datetime
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

pharmacy_bp = Blueprint('pharmacy', __name__)

# Global variable to store dependency
db = None

# UPI Gateway Constants
UPI_GATEWAY_API_KEY = "eb8414ec-1f13-4c8f-b713-ae55fbc94a97"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

def init_pharmacy(mysql):
    global db
    db = mysql
    return pharmacy_bp

# Helper function for signature verification
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

# Patient-Facing Routes

@pharmacy_bp.route('/pharmacy', methods=['GET'])
def pharmacy():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))
    
    if 'loggedin' not in session:
        flash("Please log in to access pharmacy.", 'warning')
        return redirect(url_for('auth.login'))
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        cursor.execute("""
            SELECT p.prescription_id, p.dosage, p.duration, p.instructions, p.status,
                   m.name as medicine_name, m.brand, m.price,
                   d.name as doctor_name
            FROM prescriptions p
            JOIN medicines m ON p.medicine_id = m.medicine_id
            JOIN doctors d ON p.doctor_id = d.doctor_id
            WHERE p.patient_id = %s
            ORDER BY p.prescribed_date DESC
        """, (session['patient_id'],))
        prescriptions = cursor.fetchall()
        
        cursor.execute("SELECT pharmacy_id, name, address FROM pharmacies WHERE is_active = 1")
        pharmacies = cursor.fetchall()
        
        return render_template('pharmacy.html',
                             prescriptions=prescriptions,
                             pharmacies=pharmacies)
    
    finally:
        if cursor:
            cursor.close()

@pharmacy_bp.route('/create_pharmacy_order', methods=['POST'])
def create_pharmacy_order():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))
    
    if 'loggedin' not in session:
        flash("Please log in to place an order.", 'warning')
        return redirect(url_for('auth.login'))
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        prescription_id = request.form.get('prescription_id')
        pharmacy_id = request.form.get('pharmacy_id')
        
        if not prescription_id or not pharmacy_id:
            flash('Please select a prescription and pharmacy', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        cursor.execute("""
            SELECT p.*, m.price, m.name as medicine_name, d.public_key
            FROM prescriptions p
            JOIN medicines m ON p.medicine_id = m.medicine_id
            JOIN doctors d ON p.doctor_id = d.doctor_id
            WHERE p.prescription_id = %s AND p.patient_id = %s AND p.status = 'Pending'
        """, (prescription_id, session['patient_id']))
        prescription = cursor.fetchone()
        
        if not prescription:
            flash('Invalid or unavailable prescription', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        # Verify doctor's signature
        prescription_message = f"{prescription['doctor_id']}|{prescription['patient_id']}|{prescription['appointment_id'] or 'None'}|{prescription['medicine_id']}|{prescription['dosage']}|{prescription['duration']}|{prescription['instructions'] or 'None'}"
        if not verify_signature(prescription['public_key'], prescription_message, prescription['signature']):
            flash('Prescription signature verification failed', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        cursor.execute("""
            SELECT stock_quantity 
            FROM pharmacy_inventory 
            WHERE pharmacy_id = %s AND medicine_id = %s
        """, (pharmacy_id, prescription['medicine_id']))
        inventory = cursor.fetchone()
        
        if not inventory or inventory['stock_quantity'] <= 0:
            flash('Medicine out of stock at selected pharmacy', 'warning')
            return redirect(url_for('pharmacy.pharmacy'))
        
        amount = str(prescription['price'])
        client_txn_id = str(uuid4()).replace('-', '')[:10]
        txn_date = datetime.now().strftime('%d-%m-%Y')
        
        session['pending_pharmacy_order'] = {
            'prescription_id': prescription_id,
            'pharmacy_id': pharmacy_id,
            'patient_id': session['patient_id'],
            'amount': amount,
            'client_txn_id': client_txn_id,
            'txn_date': txn_date,
            'medicine_id': prescription['medicine_id'],
            'payment_initiated': datetime.now().timestamp()
        }
        
        redirect_url = "https://monkfish-engaging-kiwi.ngrok-free.app/pharmacy"
        payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "amount": amount,
            "p_info": f"Medicine: {prescription['medicine_name']}",
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
            print(f"Payment initiation response: {result}")  # Debugging
            
            if result.get("status") and "data" in result:
                payment_url = result["data"]["payment_url"]
                qr = qrcode.make(payment_url)
                buffer = BytesIO()
                qr.save(buffer, format="PNG")
                qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
                
                return render_template('pharmacy.html',
                                     prescriptions=[prescription],
                                     pharmacies=[],
                                     show_payment=True,
                                     amount=amount,
                                     payment_url=payment_url,
                                     qr_code=qr_code,
                                     client_txn_id=client_txn_id)
            else:
                flash(f"Payment initiation failed: {result.get('msg', 'Unknown error')}", "danger")
        
        except Exception as e:
            flash(f"Payment gateway error: {str(e)}", "danger")
        
        return redirect(url_for('pharmacy.pharmacy'))
    
    finally:
        if cursor:
            cursor.close()

@pharmacy_bp.route('/check_pharmacy_payment', methods=['POST'])
def check_pharmacy_payment():
    if db is None:
        return jsonify({'status': 'ERROR', 'message': 'Database connection not initialized'}), 500
    
    data = request.get_json()
    client_txn_id = data.get('client_txn_id')
    
    if not client_txn_id or 'pending_pharmacy_order' not in session or session['pending_pharmacy_order']['client_txn_id'] != client_txn_id:
        return jsonify({'status': 'INVALID', 'message': 'No matching transaction found'}), 400
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        order = session['pending_pharmacy_order']
        status_payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "txn_date": order['txn_date']
        }
        
        response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
        result = response.json()
        print(f"Payment status response: {result}")  # Debugging
        
        if result.get("status"):
            payment_status = result["data"].get("status", "").lower()
            
            if payment_status == "success":
                cursor.execute("SELECT * FROM pharmacy_orders WHERE prescription_id = %s", 
                             (order['prescription_id'],))
                existing = cursor.fetchone()
                
                if not existing:
                    cursor.execute("""
                        INSERT INTO pharmacy_orders (prescription_id, pharmacy_id, patient_id, total_amount, delivery_address, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (order['prescription_id'],
                          order['pharmacy_id'],
                          order['patient_id'],
                          order['amount'],
                          session.get('address', 'Default Address'),
                          'Pending'))
                    
                    cursor.execute("""
                        UPDATE prescriptions 
                        SET status = 'Filled' 
                        WHERE prescription_id = %s
                    """, (order['prescription_id'],))
                    
                    cursor.execute("""
                        UPDATE pharmacy_inventory 
                        SET stock_quantity = stock_quantity - 1 
                        WHERE pharmacy_id = %s AND medicine_id = %s
                    """, (order['pharmacy_id'], order['medicine_id']))
                    
                    db.connection.commit()
                    print(f"Order created: {order}")  # Debugging
                
                session.pop('pending_pharmacy_order', None)
                flash("Order placed successfully!", "success")
            
            elif payment_status == "failed":
                session.pop('pending_pharmacy_order', None)
                flash("Payment failed. Please try again.", "danger")
            
            return jsonify({
                'status': payment_status.upper(),
                'message': result["data"].get("msg", "")
            })
        
        return jsonify({'status': 'UNKNOWN', 'message': 'Could not determine payment status'})
    
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500
    
    finally:
        if cursor:
            cursor.close()

# Pharmacy Management Routes

@pharmacy_bp.route('/pharmacy_login', methods=['GET', 'POST'])
def pharmacy_login():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM pharmacies WHERE email = %s", (email,))
        pharmacy = cursor.fetchone()
        cursor.close()
        
        if pharmacy and check_password_hash(pharmacy['password'], password):
            session['pharmacy_loggedin'] = True
            session['pharmacy_id'] = pharmacy['pharmacy_id']
            session['pharmacy_name'] = pharmacy['name']
            flash('Login successful!', 'success')
            return redirect(url_for('pharmacy.pharmacy_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('pharmacy_login.html')

@pharmacy_bp.route('/pharmacy_register', methods=['GET', 'POST'])
def pharmacy_register():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    if request.method == 'POST':
        name = request.form['name']
        license_number = request.form['license_number']
        address = request.form['address']
        phone = request.form['phone']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM pharmacies WHERE email = %s OR phone = %s OR license_number = %s", 
                      (email, phone, license_number))
        existing = cursor.fetchone()
        
        if existing:
            flash('Email, phone, or license number already exists', 'danger')
        else:
            cursor.execute("""
                INSERT INTO pharmacies (name, license_number, address, phone, email, password, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, 1)
            """, (name, license_number, address, phone, email, password))
            db.connection.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('pharmacy.pharmacy_login'))
        
        cursor.close()
    
    return render_template('pharmacy_register.html')

@pharmacy_bp.route('/pharmacy_dashboard', methods=['GET', 'POST'])
def pharmacy_dashboard():
    if db is None or 'pharmacy_loggedin' not in session:
        flash("Please login to access the pharmacy dashboard.", "warning")
        return redirect(url_for('pharmacy.pharmacy_login'))
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_medicine':
            medicine_id = request.form['medicine_id']
            stock_quantity = request.form['stock_quantity']
            cursor.execute("""
                INSERT INTO pharmacy_inventory (pharmacy_id, medicine_id, stock_quantity)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE stock_quantity = stock_quantity + %s
            """, (session['pharmacy_id'], medicine_id, stock_quantity, stock_quantity))
            db.connection.commit()
            flash('Medicine added to inventory successfully!', 'success')
        
        elif action == 'verify_prescription':
            prescription_id = request.form.get('prescription_id')
            cursor.execute("""
                SELECT p.doctor_id, p.patient_id, p.appointment_id, p.medicine_id, p.dosage,
                       p.duration, p.instructions, p.signature, d.public_key
                FROM prescriptions p
                JOIN doctors d ON p.doctor_id = d.doctor_id
                WHERE p.prescription_id = %s AND p.status = 'Filled'
            """, (prescription_id,))
            prescription = cursor.fetchone()

            if prescription:
                prescription_message = f"{prescription['doctor_id']}|{prescription['patient_id']}|{prescription['appointment_id'] or 'None'}|{prescription['medicine_id']}|{prescription['dosage']}|{prescription['duration']}|{prescription['instructions'] or 'None'}"
                print(f"Verifying prescription: message={prescription_message}, signature={prescription['signature']}")
                if verify_signature(prescription['public_key'], prescription_message, prescription['signature']):
                    cursor.execute("""
                        UPDATE pharmacy_orders 
                        SET status = 'Verified'
                        WHERE prescription_id = %s AND pharmacy_id = %s
                    """, (prescription_id, session['pharmacy_id']))
                    cursor.execute("""
                        UPDATE prescriptions 
                        SET status = 'verified'
                        WHERE prescription_id = %s
                    """, (prescription_id,))
                    db.connection.commit()
                    flash('Prescription verified successfully!', 'success')
                else:
                    flash('Prescription signature verification failed', 'danger')
            else:
                flash('Invalid or unprocessed prescription', 'danger')

        elif action == 'update_order_status':  # Fixed from 'update_order'
            order_id = request.form['order_id']
            new_status = request.form['status']
            print(f"Updating order {order_id} with status: {new_status}")  # Debug
            if new_status == 'Delivered':
                cursor.execute("""
                    UPDATE prescriptions 
                    SET status = 'delivered'
                    WHERE prescription_id = (
                        SELECT prescription_id FROM pharmacy_orders WHERE pharmacy_order_id = %s
                    )
                """, (order_id,))
            cursor.execute("""
                UPDATE pharmacy_orders 
                SET status = %s 
                WHERE pharmacy_order_id = %s AND pharmacy_id = %s
            """, (new_status, order_id, session['pharmacy_id']))
            db.connection.commit()
            flash(f'Order status updated to {new_status}', 'success')

    # Fetch pharmacy info
    cursor.execute("SELECT * FROM pharmacies WHERE pharmacy_id = %s", (session['pharmacy_id'],))
    pharmacy = cursor.fetchone()

    # Fetch inventory
    cursor.execute("""
        SELECT pi.*, m.name, m.brand, m.price
        FROM pharmacy_inventory pi
        JOIN medicines m ON pi.medicine_id = m.medicine_id
        WHERE pi.pharmacy_id = %s
    """, (session['pharmacy_id'],))
    inventory = cursor.fetchall()
    
    # Fetch orders
    cursor.execute("""
        SELECT po.pharmacy_order_id, po.total_amount, po.status, po.order_date,
               pt.name as patient_name, pr.prescription_id, pr.medicine_id, pr.dosage, 
               pr.duration, m.name as medicine_name
        FROM pharmacy_orders po
        LEFT JOIN prescriptions pr ON po.prescription_id = pr.prescription_id
        LEFT JOIN patients pt ON po.patient_id = pt.patient_id
        LEFT JOIN medicines m ON pr.medicine_id = m.medicine_id
        WHERE po.pharmacy_id = %s
        ORDER BY po.order_date DESC
    """, (session['pharmacy_id'],))
    orders = cursor.fetchall()
    print(f"Orders for Pharmacy ID {session['pharmacy_id']}: {orders}")  # Debug
    
    # Fetch available medicines
    cursor.execute("SELECT medicine_id, name, brand FROM medicines")
    medicines = cursor.fetchall()
    
    cursor.close()
    
    # Always return the rendered template
    return render_template('pharmacy_dashboard.html',
                         pharmacy=pharmacy,
                         inventory=inventory,
                         orders=orders,
                         medicines=medicines)

@pharmacy_bp.route('/pharmacy_logout')
def pharmacy_logout():
    session.pop('pharmacy_loggedin', None)
    session.pop('pharmacy_id', None)
    session.pop('pharmacy_name', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('pharmacy.pharmacy_login'))