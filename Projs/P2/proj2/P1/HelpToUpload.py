import socket
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import base64

def gerar_chaves_rsa(caminho):
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chave_publica = chave_privada.public_key()
    
    caminho_chave_privada = os.path.join(caminho, "chave_privada.pem")
    with open(caminho_chave_privada, "wb") as f:
        f.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    caminho_chave_publica = os.path.join(caminho, "chave_publica.pem")
    with open(caminho_chave_publica, "wb") as f:
        f.write(chave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Par de chaves RSA gerado e salvo para o cliente com mail {caminho}")
    return chave_privada, chave_publica


def carregar_chaves_rsa(caminho):
    caminho_chave_privada = os.path.join(caminho, "chave_privada.pem")
    caminho_chave_publica = os.path.join(caminho, "chave_publica.pem")
    
    try:
        with open(caminho_chave_privada, "rb") as f:
            chave_privada = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        with open(caminho_chave_publica, "rb") as f:
            chave_publica = serialization.load_pem_public_key(
                f.read()
            )
        
        print(f"Chaves RSA carregadas com sucesso para o cliente com mail {caminho}.")
        return chave_privada, chave_publica
    except:
        return gerar_chaves_rsa(caminho)

def cifrar_arquivo(caminho_arquivo, caminho, chave_publica_rsa):
    chave_aes = secrets.token_bytes(32) 
    print(f"Chave AES-256 gerada para o arquivo {os.path.basename(caminho_arquivo)}")
    with open(caminho_arquivo, 'rb') as f:
        dados = f.read()

    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(chave_aes), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    dados_cifrados = encryptor.update(dados) + encryptor.finalize()
    
    tag = encryptor.tag

    resultado = nonce + tag + dados_cifrados
    
    nome_arquivo = os.path.basename(caminho_arquivo)
    caminho_cifrado = os.path.join(caminho, nome_arquivo + ".encrypted")
    with open(caminho_cifrado, 'wb') as f:
        f.write(resultado)
    
    print(f"Arquivo cifrado salvo em '{caminho_cifrado}'")
    
    chave_aes_cifrada = chave_publica_rsa.encrypt(
        chave_aes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    caminho_chave_cifrada = os.path.join(caminho, nome_arquivo + ".key.encrypted")
    with open(caminho_chave_cifrada, 'wb') as f:
        f.write(chave_aes_cifrada)
    
    print(f"Chave AES cifrada e salva em '{caminho_chave_cifrada}'")
    
    return caminho_cifrado, caminho_chave_cifrada, chave_aes

def decifrar_arquivo(caminho_arquivo_cifrado, chave_aes=None, caminho_chave_cifrada=None, chave_privada_rsa=None, mail=None):
    if chave_aes is None and caminho_chave_cifrada and chave_privada_rsa:
        with open(caminho_chave_cifrada, 'rb') as f:
            chave_aes_cifrada = f.read()
        
        chave_aes = chave_privada_rsa.decrypt(
            chave_aes_cifrada,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Chave AES recuperada usando chave privada RSA")
    
    if chave_aes is None:
        raise ValueError("É necessário fornecer a chave AES ou o caminho da chave cifrada e a chave privada RSA")
    
    with open(caminho_arquivo_cifrado, 'rb') as f:
        dados = f.read()
    
    nonce = dados[:12]
    tag = dados[12:28]
    dados_cifrados = dados[28:]
    
    cipher = Cipher(algorithms.AES(chave_aes), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    
    dados_original = decryptor.update(dados_cifrados) + decryptor.finalize()
    
    nome_arquivo_base = os.path.basename(caminho_arquivo_cifrado).replace(".encrypted", "")
    caminho_saida = os.path.join(mail, "decifrado_" + nome_arquivo_base)
    
    with open(caminho_saida, 'wb') as f:
        f.write(dados_original)
    
    print(f"Arquivo decifrado salvo em '{caminho_saida}'")
    return caminho_saida

def transcifrar_chave_aes(encrypted_key, private_key_data, target_public_key_data):
    """
    Decifra uma chave AES com uma chave privada RSA e a recifra com outra chave pública RSA.
    
    Args:
        encrypted_key (bytes): Chave AES cifrada com a chave RSA de origem
        private_key_data (bytes/str): Dados da chave privada RSA (PEM) ou objeto de chave privada
        target_public_key_data (bytes/str): Dados da chave pública RSA (PEM) ou objeto de chave pública
    
    Returns:
        bytes: Chave AES cifrada com a nova chave pública RSA
    """
    # Padding para RSA
    padding = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    
    # Converter private_key_data para objeto de chave privada se necessário
    if isinstance(private_key_data, (bytes, str)) and not hasattr(private_key_data, 'decrypt'):
        try:
            # Se for base64, decodificar primeiro
            if isinstance(private_key_data, str) and private_key_data.startswith("LS0tLS"):
                private_key_data = base64.b64decode(private_key_data)
            
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None
            )
        except Exception as e:
            raise ValueError(f"Falha ao carregar a chave privada: {e}")
    else:
        private_key = private_key_data
    
    # Converter target_public_key_data para objeto de chave pública se necessário
    if isinstance(target_public_key_data, (bytes, str)) and not hasattr(target_public_key_data, 'encrypt'):
        try:
            # Se for base64, decodificar primeiro
            if isinstance(target_public_key_data, str) and target_public_key_data.startswith("LS0tLS"):
                target_public_key_data = base64.b64decode(target_public_key_data)
            
            public_key = serialization.load_pem_public_key(
                target_public_key_data
            )
        except Exception as e:
            raise ValueError(f"Falha ao carregar a chave pública: {e}")
    else:
        public_key = target_public_key_data
    
    # 1. Decifrar a chave AES com a chave privada de origem
    try:
        chave_aes = private_key.decrypt(
            encrypted_key,
            padding
        )
        print("Chave AES recuperada com sucesso usando a chave privada de origem")
    except Exception as e:
        raise ValueError(f"Falha ao decifrar a chave AES: {e}")
    
    # 2. Cifrar a chave AES com a chave pública de destino
    try:
        nova_chave_cifrada = public_key.encrypt(
            chave_aes,
            padding
        )
        print("Chave AES recifrada com sucesso usando a chave pública de destino")
    except Exception as e:
        raise ValueError(f"Falha ao recifrar a chave AES: {e}")
    
    return nova_chave_cifrada