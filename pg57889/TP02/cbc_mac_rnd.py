import sys
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class InvalidTag(Exception):
    pass

def padding_by_me(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize() 

    return padded_data

def cbc_mac_rnd(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    return iv + ciphertext[-16:]


def generate_tag(key, data):
    tag = cbc_mac_rnd(key, data)
    tag_b64 = base64.b64encode(tag).decode()
    
    with open("tag", "w") as tag_file:
        tag_file.write(tag_b64)
    

def main():
    if len(sys.argv) < 4:
        print("Uso:")
        print("  python3 cbc_mac_rnd.py tag <key_file> <file>")
        print("  python3 cbc_mac_rnd.py check <key_file> <file> <tag_file>")
        sys.exit(1)


    mode = sys.argv[1]



    key_file = sys.argv[2]
    with open(key_file, 'rb') as f:
        key_64 = f.read().strip()
    key = base64.b64decode(key_64)



    filename = sys.argv[3]
    with open(filename, 'rb') as f:
        data = f.read()
    
    data_padded = padding_by_me(data)



    if mode == "tag":
        generate_tag(key, data_padded)
        print("Tag generated and Saved.")


    elif mode == "check":
        tag_file = sys.argv[4]

        with open(tag_file, "r") as tag_file:
            expected_tag_b64 = tag_file.read().strip()

        expected_tag = base64.b64decode(expected_tag_b64)

        iv, expected_mac = expected_tag[:16], expected_tag[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(data_padded) + encryptor.finalize()
        computed_mac = ciphertext[-16:]

        if computed_mac != expected_mac:
            raise InvalidTag("Invalid MAC tag!")
        print("Valid tag.")

if __name__ == "__main__":
    main()