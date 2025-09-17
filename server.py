import os, base64
from flask import Flask, send_file, request, jsonify
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from bson import ObjectId
from dotenv import load_dotenv

# Load .env file
load_dotenv()

app = Flask(__name__)

# ---------- CONFIG ----------
MONGO_URI = os.environ.get("MONGO_URI", "").strip()
if not MONGO_URI:
    raise RuntimeError("MONGO_URI not set in .env file")

client = MongoClient(MONGO_URI)
db = client.get_database()  # uses DB from URI or default
secrets = db.secrets

KEYS_DIR = "keys"
PRIV_PATH = os.path.join(KEYS_DIR, "private.pem")
PUB_PATH = os.path.join(KEYS_DIR, "public.pem")

# ensure RSA keys exist
def ensure_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(PRIV_PATH) and os.path.exists(PUB_PATH):
        with open(PRIV_PATH, "rb") as f:
            private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(PUB_PATH, "rb") as f:
            public = serialization.load_pem_public_key(f.read(), backend=default_backend())
        return private, public

    # generate 4096-bit RSA keypair
    private = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public = private.public_key()

    priv_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PRIV_PATH, "wb") as f:
        f.write(priv_bytes)
    with open(PUB_PATH, "wb") as f:
        f.write(pub_bytes)
    print("Generated RSA keypair in ./keys/")
    return private, public

private_key, public_key = ensure_keys()

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def from_b64(s: str) -> bytes:
    return base64.b64decode(s.encode())

# ---------- Routes ----------
@app.route("/")
def index():
    return send_file("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json(force=True)
    message = data.get("message", "")
    mouse_trail = data.get("trail", [])
    if not message:
        return jsonify({"error":"message required"}), 400

    # AES-256-GCM encrypt
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, message.encode("utf-8"), None)

    # RSA-OAEP wrap
    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    doc = {
        "ciphertext": b64(ct),
        "iv": b64(iv),
        "encKey": b64(enc_key),
        "alg": "AES-256-GCM+RSA-OAEP",
        "mouseTrail": mouse_trail,
    }
    res = secrets.insert_one(doc)
    return jsonify({"id": str(res.inserted_id)}), 200

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json(force=True)
    _id = data.get("id", "").strip()
    if not _id:
        return jsonify({"error":"id required"}), 400
    try:
        doc = secrets.find_one({"_id": ObjectId(_id)})
    except Exception:
        return jsonify({"error":"invalid id"}), 400
    if not doc:
        return jsonify({"error":"not found"}), 404

    try:
        enc_key = from_b64(doc["encKey"])
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        iv = from_b64(doc["iv"])
        ct = from_b64(doc["ciphertext"])
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ct, None).decode("utf-8")
        return jsonify({"plaintext": plaintext, "mouseTrail": doc.get("mouseTrail", [])})
    except Exception as e:
        return jsonify({"error":"decryption_failed", "detail": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
