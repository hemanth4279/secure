from flask import Flask, request, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import os

app = Flask(__name__)

# In-memory database for simplicity
patients_data = {}
aes_keys = {}

# RSA key generation (for AES key encryption)
rsa_key = RSA.generate(2048)
private_rsa = rsa_key.export_key()
public_rsa = rsa_key.publickey().export_key()

# DSA key generation (for digital signatures)
dsa_key = DSA.generate(2048)


# Utility function: AES Encryption
def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }


# Utility function: AES Decryption
def aes_decrypt(enc_data, aes_key):
    try:
        nonce = base64.b64decode(enc_data['nonce'])
        ciphertext = base64.b64decode(enc_data['ciphertext'])
        tag = base64.b64decode(enc_data['tag'])

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption Error: {str(e)}"


# Endpoint: Register Patient Data (Encrypted)
@app.route('/register_patient', methods=['POST'])
def register_patient():
    data = request.json
    patient_id = data['patient_id']

    # Generate AES key for this patient
    aes_key = os.urandom(16)  # 128-bit key
    aes_keys[patient_id] = aes_key

    # Encrypt patient data
    encrypted_data = {}
    for field in ['blood_group', 'blood_pressure', 'body_temperature', 'pulse_rate', 'previous_medications']:
        encrypted_data[field] = aes_encrypt(data[field], aes_key)

    # RSA encrypt AES key
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_rsa))
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Create digital signature
    h = SHA256.new(encrypted_aes_key)
    signer = DSS.new(dsa_key, 'fips-186-3')
    signature = signer.sign(h)

    # Store encrypted data and key
    patients_data[patient_id] = {
        'encrypted_data': encrypted_data,
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'signature': base64.b64encode(signature).decode('utf-8')
    }

    return jsonify({'status': 'success', 'patient_id': patient_id})


# Endpoint: Decrypt Patient Data
@app.route('/decrypt_data', methods=['POST'])
def decrypt_data():
    data = request.json
    patient_id = data['patient_id']
    secret_key = data['secret_key']  # The secret key input from user

    if patient_id not in patients_data:
        return jsonify({'status': 'error', 'message': 'Patient not found'})

    # Decrypt AES key using RSA private key
    encrypted_aes_key = base64.b64decode(patients_data[patient_id]['encrypted_aes_key'])
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_rsa))
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Verify secret key (basic check for this demo)
    if secret_key != base64.b64encode(aes_key).decode('utf-8'):
        return jsonify({'status': 'error', 'message': 'Invalid Secret Key'})

    # Decrypt patient data
    decrypted_data = {}
    for field, enc_value in patients_data[patient_id]['encrypted_data'].items():
        decrypted_data[field] = aes_decrypt(enc_value, aes_key)

    return jsonify({'status': 'success', 'data': decrypted_data})


# Endpoint: Activate Patient Account
@app.route('/activate_patient', methods=['POST'])
def activate_patient():
    data = request.json
    patient_id = data['patient_id']

    if patient_id in patients_data:
        # For simplicity, activation is just a flag in real DB
        patients_data[patient_id]['activated'] = True
        return jsonify({'status': 'success', 'message': 'Patient account activated'})
    else:
        return jsonify({'status': 'error', 'message': 'Patient not found'})


if __name__ == '__main__':
    app.run(port=5001, debug=True)
