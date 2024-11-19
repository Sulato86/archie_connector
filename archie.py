from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import requests
import json
import urllib.parse

app = Flask(__name__)

# API Key dan Private Key
XENDIT_API_KEY = os.getenv('XENDIT_API_KEY', 'xnd_development_api_key')  # Xendit API Key
PRIVATE_KEY = base64.b64decode(os.getenv('PRIVATE_KEY', 'archie_private_key='))  # Private Key untuk dekripsi

# Archie API Credentials
ARCHIE_CLIENT_ID = os.getenv('ARCHIE_CLIENT_ID', 'archie_client_id')
ARCHIE_CLIENT_SECRET = os.getenv('ARCHIE_CLIENT_SECRET', 'archie_client_secret')

def fix_base64_padding(data):
    """
    Memperbaiki padding Base64 jika data tidak memiliki panjang yang valid.
    """
    print(f"Base64 String sebelum padding: {data}")  # Debugging
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    print(f"Base64 String setelah padding: {data}")  # Debugging
    return data

def decrypt_message(secret, encrypted):
    """
    Mendekripsi pesan terenkripsi dengan AES-256-GCM menggunakan pustaka cryptography.
    """
    try:
        print(f"Data terenkripsi (sebelum padding): {encrypted}")  # Debugging
        encrypted = fix_base64_padding(encrypted)
        ciphertext = base64.b64decode(encrypted)

        nonce_size = 12  # Panjang nonce untuk AES-GCM
        if len(ciphertext) < nonce_size + 16:
            raise ValueError("Ciphertext terlalu pendek untuk AES-GCM.")

        nonce = ciphertext[:nonce_size]
        ciphertext_without_nonce = ciphertext[nonce_size:-16]
        auth_tag = ciphertext[-16:]

        # Debugging log
        print(f"Nonce: {nonce.hex()}")
        print(f"Ciphertext: {ciphertext_without_nonce.hex()}")
        print(f"Auth Tag: {auth_tag.hex()}")

        # Dekripsi menggunakan AESGCM
        aesgcm = AESGCM(secret)
        plaintext = aesgcm.decrypt(nonce, ciphertext_without_nonce + auth_tag, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Error during decryption: {e}")
        raise ValueError(f"Gagal mendekripsi data: {e}")

def get_archie_token():
    """
    Mendapatkan token akses dari Archie API.
    """
    url = "https://api.archie.com/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": ARCHIE_CLIENT_ID,
        "client_secret": ARCHIE_CLIENT_SECRET,
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        raise ValueError(f"Gagal mendapatkan token dari Archie API: {response.text}")

def update_archie_payment(transaction_id, status):
    """
    Mengupdate status pembayaran ke Archie API.
    """
    token = get_archie_token()
    url = f"https://api.archie.com/v1/payments/{transaction_id}"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": status}
    response = requests.put(url, json=payload, headers=headers)
    if response.status_code == 200:
        print("Status pembayaran berhasil diperbarui ke Archie")
    else:
        print(f"Error dari Archie API: {response.text}")

@app.route('/custom-payment', methods=['GET', 'POST'])
def custom_payment():
    """
    Endpoint untuk menerima request dari Archie, mendekripsi data, memvalidasi, 
    dan membuat invoice di Xendit.
    """
    try:
        # Ambil data terenkripsi dari request
        encrypted_data = request.args.get('data') if request.method == 'GET' else request.json.get('data')
        if not encrypted_data:
            return jsonify({"error": "Data terenkripsi tidak ditemukan dalam request"}), 400

        # Decode URL jika diperlukan
        encrypted_data = urllib.parse.unquote_plus(encrypted_data)
        print(f"Data terenkripsi yang diterima: {encrypted_data}")  # Debugging

        # Dekripsi data
        decrypted_data = decrypt_message(PRIVATE_KEY, encrypted_data)
        transaction = json.loads(decrypted_data)  # Parsing JSON

        # Validasi data
        required_keys = ["transaction_id", "customer_email", "description", "amount"]
        missing_keys = [key for key in required_keys if key not in transaction]
        if missing_keys:
            return jsonify({"error": f"Missing keys: {', '.join(missing_keys)}"}), 400

        # Buat invoice di Xendit
        invoice_data = {
            "external_id": transaction["transaction_id"],
            "payer_email": transaction["customer_email"],
            "description": transaction["description"],
            "amount": transaction["amount"],
        }

        response = requests.post(
            'https://api.xendit.co/v2/invoices',
            json=invoice_data,
            auth=(XENDIT_API_KEY, '')
        )

        if response.status_code == 200:
            invoice_url = response.json().get("invoice_url")
            # Return URL pembayaran ke Archie
            return jsonify({"payment_url": invoice_url}), 200
        else:
            error_message = response.json().get("message", "Unknown error")
            print(f"Error dari Xendit: {response.text}")
            return jsonify({"error": error_message}), response.status_code
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/xendit-callback', methods=['POST'])
def xendit_callback():
    """
    Endpoint untuk menangani callback dari Xendit.
    """
    try:
        data = request.json
        transaction_id = data.get("external_id")
        status = data.get("status")  # Status dari Xendit, misalnya "PAID"

        if not transaction_id or not status:
            return jsonify({"error": "Invalid callback data"}), 400

        # Perbarui status pembayaran ke Archie
        update_archie_payment(transaction_id, status)
        return jsonify({"message": "Callback processed successfully"}), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
