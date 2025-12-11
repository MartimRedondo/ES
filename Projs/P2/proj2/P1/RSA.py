from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def carregar_chave_publica(caminho = "../rsa_keys/login_public.pem"):
    with open(caminho, "rb") as f:
        key = RSA.import_key(f.read())
    return PKCS1_OAEP.new(key)

def carregar_chave_privada(caminho = "../rsa_keys/login_private.pem"):
    with open(caminho, "rb") as f:
        key = RSA.import_key(f.read())
    return PKCS1_OAEP.new(key)



#-------------------//-------------

# def gerar_chaves_rsa_login(diretorio="rsa_keys", bits=2048):
#     os.makedirs(diretorio, exist_ok=True)

#     chave_privada = RSA.generate(bits)
#     chave_publica = chave_privada.publickey()

#     caminho_privada = os.path.join(diretorio, "login_private.pem")
#     caminho_publica = os.path.join(diretorio, "login_public.pem")

#     with open(caminho_privada, "wb") as f:
#         f.write(chave_privada.export_key())

#     with open(caminho_publica, "wb") as f:
#         f.write(chave_publica.export_key())

#     print(f"✅ Par de chaves RSA criado com sucesso em '{diretorio}'.")

def gerar_chaves_rsa_login(diretorio="../rsa_keys", bits=2048):
    os.makedirs(diretorio, exist_ok=True)

    caminho_privada = os.path.join(diretorio, "login_private.pem")
    caminho_publica = os.path.join(diretorio, "login_public.pem")

    # Só gera se os dois ficheiros não existirem
    if os.path.exists(caminho_privada) and os.path.exists(caminho_publica):
        print("ℹ️ Chaves RSA já existem. Nenhuma nova chave foi gerada.")
        return

    chave_privada = RSA.generate(bits)
    chave_publica = chave_privada.publickey()

    with open(caminho_privada, "wb") as f:
        f.write(chave_privada.export_key())

    with open(caminho_publica, "wb") as f:
        f.write(chave_publica.export_key())

    print(f"✅ Par de chaves RSA criado com sucesso em '{diretorio}'.")

if __name__ == "__main__":
    gerar_chaves_rsa_login()


