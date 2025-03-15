DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '4279',
    'database': 'secure_patient_db'
}

# 🔑 AES Secret Key
AES_SECRET_KEY = bytes.fromhex('1c09e94c774261bad417ea8ac1d54226')  # 16 bytes for AES-128

# 🔐 RSA Key Configurations
RSA_KEY_SIZE = 2048

# 📂 Paths to RSA Keys (Update if stored elsewhere)
RSA_PRIVATE_KEY_PATH = '/home/guduru-hemanth-kumar-reddy/private_key.pem'
RSA_PUBLIC_KEY_PATH = '/home/guduru-hemanth-kumar-reddy/public_key.pem'
