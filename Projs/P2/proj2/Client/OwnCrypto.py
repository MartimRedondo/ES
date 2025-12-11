from PathsImports import *
from register_helper import set_user_path

def generate_aes_key():
    return secrets.token_bytes(32)

def encrypt_with_aes(data, key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the data to a multiple of 16 bytes (AES block size)
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length]) * padding_length
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext 

def decrypt_with_aes(encrypted_data, key):

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def load_or_generate_rsa_keys(email):
    user_path = set_user_path(email)
    keys_path = os.path.join(user_path, "keys")
    os.makedirs(keys_path, exist_ok=True)
    
    private_key_path = os.path.join(keys_path, "private_key.pem")
    public_key_path = os.path.join(keys_path, "public_key.pem")
    
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def get_file_mime_type(filepath):
    mime_type, _ = mimetypes.guess_type(filepath)
    return mime_type or "application/octet-stream"


def encrypt_file(file_path, public_key):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        aes_key = generate_aes_key()
        encrypted_file = encrypt_with_aes(file_data, aes_key)

        encrypted_key = encrypt_aes_key_with_rsa(aes_key, public_key)

        encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        
        return {
            "encrypted_file": encrypted_file_b64,
            "encrypted_key": encrypted_key_b64
        }
    except Exception as e:
        typer.echo(f"Error encrypting file {file_path}: {str(e)}")
        return None