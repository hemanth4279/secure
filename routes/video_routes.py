from flask import Blueprint, render_template, redirect, url_for, flash
import MySQLdb.cursors
from datetime import datetime

video_bp = Blueprint('video', __name__)

# Global variable to store dependency
db = None

def init_video(mysql):
    global db
    db = mysql
    return video_bp

# Join Video Route
@video_bp.route('/join_video/<unique_url>')
def join_video(unique_url):
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('appointment.appointments'))

    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        cursor.execute("""
            SELECT a.*, p.name AS patient_name, d.name AS doctor_name
            FROM appointments a
            JOIN patients p ON a.patient_id = p.patient_id
            JOIN doctors d ON a.doctor_id = d.doctor_id
            WHERE a.video_call_url = %s AND a.status = 'Confirmed'
        """, (unique_url,))
        appointment = cursor.fetchone()

        if not appointment:
            flash("Invalid or unauthorized video call link!", "danger")
            return redirect(url_for('appointment.appointments'))

        current_time = datetime.now()
        appt_datetime = datetime.strptime(
            f"{appointment['appointment_date']} {appointment['appointment_time']}",
            "%Y-%m-%d %H:%M:%S"
        )
        
        if abs((current_time - appt_datetime).total_seconds()) > 900:  # 15-minute window
            flash("Video call is only available at scheduled time!", "warning")
            return redirect(url_for('appointment.appointments'))

        return render_template('video_call.html', appointment=appointment)

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('appointment.appointments'))    
    finally:
        if cursor:
            cursor.close()