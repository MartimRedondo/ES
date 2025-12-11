import os
import base64
import json
import hmac
import hashlib
from cryptography.fernet import Fernet

def generate_hmac_key(length=32):
    return os.urandom(length)

def save_hmac_key(key, filename="hmac/shared_hmac_key.json"):
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)
    encrypted_key = cipher.encrypt(key)

    with open(filename, 'w') as f:
        json.dump({
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'encryption_key': base64.b64encode(encryption_key).decode('utf-8')
        }, f)

def load_hmac_key(filename="hmac/shared_hmac_key.json"):
    with open(filename, 'r') as f:
        data = json.load(f)
    
    encryption_key = base64.b64decode(data['encryption_key'])
    cipher = Fernet(encryption_key)
    encrypted_key = base64.b64decode(data['encrypted_key'])
    return cipher.decrypt(encrypted_key)

def create_hmac_signature(message, key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac_signature(message, signature, key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    computed_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, signature)

def key_exists(filename="hmac/shared_hmac_key.json"):
    try:
        key = load_hmac_key(filename)
    except (FileNotFoundError, json.JSONDecodeError):
        key = generate_hmac_key()
        save_hmac_key(key, filename)
    return key