import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hmac

class InvalidTag(Exception):
    pass



def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))



def padding_by_me(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize() 

    return padded_data



def generate_tag(key, message):
    tag = bytes([0] * 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(tag))
    encryptor = cipher.encryptor()
    
    for i in range(0, len(message), 16):
        block = message[i:i+16]
        tag = encryptor.update(xor_bytes(tag, block))
    
    return tag 



def write_tag_into_file(tag):
    with open("tag", 'wb') as f:
        f.write(base64.b64encode(tag))



def main():
    if len(sys.argv) < 4:
        print("Uso:")
        print("  python3 cbc_mac.py tag <key_file> <file>")
        print("  python3 cbc_mac.py check <key_file> <file> <tag_file>")
        sys.exit(1)

    mode = sys.argv[1]


    key_file = sys.argv[2]
    with open(key_file, 'rb') as f:
        key_64 = f.read().strip()
    key = base64.b64decode(key_64)


    filename = sys.argv[3]
    with open(filename, 'rb') as f:
        data_without_pad = f.read()

    data = padding_by_me(data_without_pad)
    tag = generate_tag(key, data)


    if mode == "tag":
        print(base64.b64encode(tag).decode())
        write_tag_into_file(tag)

    elif mode == "check":
        tag_file = sys.argv[4]
        with open(tag_file, 'rb') as f:
            tag_64 = f.read().strip()
        tag_verify = base64.b64decode(tag_64)


        if hmac.compare_digest(tag_verify, tag):
            print("Tag válida")
        else:
            raise InvalidTag("Tag inválida")
        
    else:
        print("Modo desconhecido. Use 'tag' ou 'check'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
