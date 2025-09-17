from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import base64

load_dotenv()

# Load environment variables
MONGO_URI = os.environ.get("MONGO_URI")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
PUBLIC_KEY = os.environ.get("PUBLIC_KEY")

# Decode keys from base64
private_key_bytes = base64.b64decode(PRIVATE_KEY)
public_key_bytes = base64.b64decode(PUBLIC_KEY)

# Initialize Flask
app = Flask(__name__)

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client.crypto_db
messages_collection = db.messages

# Encryption / decryption using Fernet symmetric key (as example)
# You can replace this with hybrid crypto (RSA + AES) for more security
key = Fernet.generate_key()
cipher = Fernet(key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    message = data.get('message')
    if not message:
        return jsonify({"error": "No message provided"}), 400

    encrypted = cipher.encrypt(message.encode()).decode()
    messages_collection.insert_one({"encrypted": encrypted})
    return jsonify({"encrypted": encrypted})

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted = data.get('encrypted')
    if not encrypted:
        return jsonify({"error": "No encrypted message provided"}), 400

    try:
        decrypted = cipher.decrypt(encrypted.encode()).decode()
        return jsonify({"decrypted": decrypted})
    except Exception as e:
        return jsonify({"error": "Decryption failed"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
