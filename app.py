
import base64
import os
import jwt
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import sqlite3
import uuid
from passlib.hash import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pytest

db_file = 'totally_not_my_privateKeys.db'
aes_key = os.environ.get('NOT_MY_KEY', os.urandom(32))
iv = os.urandom(16)

app = Flask(__name__)

def encrypt_key(plain_text):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(ct).decode('utf-8')

def decrypt_key(cipher_text):
    cipher_text = base64.urlsafe_b64decode(cipher_text)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()

def init_db():
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            iv BLOB NOT NULL,
            exp INTEGER NOT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        conn.commit()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = uuid.uuid4().hex
    hashed_password = argon2.hash(password)
    
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_password))
            conn.commit()
        return jsonify({'password': password}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 409

@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    expired = request.json.get('expired', False)  # Handling the 'expired' flag
    request_ip = request.remote_addr
    
    if not username:
        return jsonify({"error": "Username is required"}), 400

    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_id = cursor.fetchone()
            if user_id is None:
                return jsonify({"error": "User does not exist"}), 404

            cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id[0]))
            conn.commit()

        # Adjust exp based on the expired flag
        exp_time = datetime.now(timezone.utc) - timedelta(hours=1) if expired else datetime.now(timezone.utc) + timedelta(hours=1)
        payload = {
            'user_id': user_id[0],
            'Fullname': 'username',
            'exp': exp_time.timestamp()
        }
        token = jwt.encode(payload, 'your_secret_key_here', algorithm='HS256', headers={'kid': 'your_kid_here'})
        return jsonify(message="Authentication successful", token=token), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        # Removing the exp filter temporarily for debugging
        cursor.execute('SELECT kid, key, exp FROM keys')
        rows = cursor.fetchall()
        print("Database rows:", rows)  # Debug output to see what is fetched from the database

    jwks_data = {"keys": []}
    for row in rows:
        kid, key_blob, exp = row
        if exp > datetime.now(timezone.utc).timestamp():
            key = base64.urlsafe_b64encode(key_blob).decode('utf-8')
            jwks_data["keys"].append({
                "kty": "oct",
                "k": key,
                "alg": "HS256",
                "use": "sig",
                "kid": str(kid)
            })
    return jsonify(jwks_data)

@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO keys (key, iv, exp) VALUES (?, ?, strftime('%s','now') + 3600)",
                       (base64.urlsafe_b64encode(b'sample_key').decode('utf-8'), base64.urlsafe_b64encode(b'sample_iv').decode('utf-8')))
        conn.commit()
    yield
    # Clean up after tests
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")
        conn.commit()


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080)
