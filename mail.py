from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def init_mail(app):
    mail.init_app(app)

def send_otp_email(to_email, otp):
    subject = "Your OTP for Registration"
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white font-sans">
        <div class="max-w-xl mx-auto my-10 p-6 bg-gray-800 rounded-xl shadow-2xl">
            <!-- Header -->
            <div class="bg-gradient-to-r from-purple-700 to-purple-900 text-center py-4 rounded-t-xl">
                <h1 class="text-3xl font-extrabold text-white">Healthcare System</h1>
            </div>
            <!-- Content -->
            <div class="p-6">
                <p class="text-gray-200 text-lg mb-4">Hello,</p>
                <p class="text-gray-300 mb-6">Your One-Time Password (OTP) for registration is:</p>
                <div class="bg-purple-900 text-white text-center py-4 px-6 rounded-lg text-2xl font-bold tracking-wider mb-6 shadow-inner">
                    {otp}
                </div>
                <p class="text-gray-300 mb-6">Please use this OTP to verify your email address. It’s valid for <span class="text-purple-400 font-semibold">10 minutes</span>.</p>
                <p class="text-gray-400 text-sm">If you didn’t request this, please ignore this email.</p>
            </div>
            <!-- Footer -->
            <div class="bg-gray-700 text-center py-3 rounded-b-xl">
                <p class="text-gray-300 text-sm">Regards,<br><span class="text-purple-400 font-medium">Healthcare System Team</span></p>
            </div>
        </div>
    </body>
    </html>
    """
    msg = Message(subject, recipients=[to_email], html=html_body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send OTP email: {str(e)}")
        return False

def send_activation_email(to_email, name, role, activated):
    subject = f"Account {'Activated' if activated else 'Deactivated'}"
    status = "activated" if activated else "deactivated"
    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-white font-sans">
        <div class="max-w-xl mx-auto my-10 p-6 bg-gray-800 rounded-xl shadow-2xl">
            <!-- Header -->
            <div class="bg-gradient-to-r from-purple-700 to-purple-900 text-center py-4 rounded-t-xl">
                <h1 class="text-3xl font-extrabold text-white">Healthcare System</h1>
            </div>
            <!-- Content -->
            <div class="p-6">
                <p class="text-gray-200 text-lg mb-4">Hello {name},</p>
                <p class="text-gray-300 mb-6">Your <span class="text-purple-400 font-semibold">{role}</span> account has been <span class="font-bold {'text-green-400' if activated else 'text-red-400'}">{status}</span> by the cloud server.</p>
                <p class="text-gray-300 mb-6">
                    {'You can now <a href="#" class="text-purple-400 underline hover:text-purple-300">log in to your account</a>.' if activated else 'Please contact support if you believe this is an error.'}
                </p>
            </div>
            <!-- Footer -->
            <div class="bg-gray-700 text-center py-3 rounded-b-xl">
                <p class="text-gray-300 text-sm">Regards,<br><span class="text-purple-400 font-medium">Healthcare System Team</span></p>
            </div>
        </div>
    </body>
    </html>
    """
    msg = Message(subject, recipients=[to_email], html=html_body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send activation email: {str(e)}")
        return False