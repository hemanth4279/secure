from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from utils.encryption import AESEncryption, RSAEncryption, DSASignature
from config import DB_CONFIG, AES_SECRET_KEY
import MySQLdb.cursors
import base64
import random
import secrets
import pyotp
import qrcode
from io import BytesIO
import logging
from datetime import datetime
from uuid import uuid4
import plotly.graph_objects as go
import plotly.express as px

# Set up Flask app
app = Flask(__name__)
app.secret_key = '5e8e565836ec4ab43a22afe1d316f35f87bf7eeab2d0b80d862d31d6321b976e'

# MySQL Configuration
app.config['MYSQL_HOST'] = DB_CONFIG['host']
app.config['MYSQL_USER'] = DB_CONFIG['user']
app.config['MYSQL_PASSWORD'] = DB_CONFIG['password']
app.config['MYSQL_DB'] = DB_CONFIG['database']
mysql = MySQL(app)

# Initialize Encryption
aes = AESEncryption(AES_SECRET_KEY)
rsa = RSAEncryption()
dsa = DSASignature()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Hardcoded TOTP secret for cloud login
CLOUD_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
# Graphs
# Doctor Login
@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM doctors WHERE email = %s AND password = %s AND is_activated = '1'",
            (request.form['email'], request.form['password'])
        )
        doctor = cursor.fetchone()
        cursor.close()

        if doctor:
            session['doctor_id'] = doctor['doctor_id']
            flash(f"Welcome Dr. {doctor['name']}!", 'success')
            return redirect(url_for('doctor_dashboard'))
        else:
            flash("Invalid credentials or account not activated.", 'danger')
    return render_template('doctor_login.html')