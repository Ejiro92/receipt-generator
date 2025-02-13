from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

# Database setup
conn = sqlite3.connect('receipts.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY,
        sender_public_key TEXT,
        signature TEXT,
        timestamp TEXT,
        data_hash TEXT
    )
''')
conn.commit()

@app.route('/generate_receipt', methods=['POST'])
def generate_receipt():
    data = request.json['data'].encode()
    private_key = serialization.load_pem_private_key(
        open("private_key.pem", "rb").read(),
        password=None
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    receipt = {
        "sender_public_key": open("public_key.pem", "rb").read().decode(),
        "signature": signature.hex(),
        "timestamp": datetime.now().isoformat(),
        "data_hash": hashlib.sha256(data).hexdigest()
    }
    cursor.execute('''
        INSERT INTO receipts (sender_public_key, signature, timestamp, data_hash)
        VALUES (?, ?, ?, ?)
    ''', (receipt['sender_public_key'], receipt['signature'], receipt['timestamp'], receipt['data_hash']))
    conn.commit()
    return jsonify(receipt)

@app.route('/verify_receipt', methods=['POST'])
def verify_receipt():
    receipt = request.json
    public_key = serialization.load_pem_public_key(
        receipt['sender_public_key'].encode()
    )
    try:
        public_key.verify(
            bytes.fromhex(receipt['signature']),
            receipt['data_hash'].encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({"status": "valid"})
    except Exception as e:
        return jsonify({"status": "invalid", "error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
