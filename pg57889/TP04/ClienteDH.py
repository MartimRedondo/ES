#!/usr/bin/env python3
import socket
import secrets
import hashlib
import json


P_hex = """
21907153604610140591413853060873569488799889545658499345199954499288513214495373162018722276190048176453652397664537072464364660353276556674291687790361787435091460602031819701696205848778364694457002959752093446607221996010036337184792838247025102191936341390662068744021282838757199568626081187227742559172776873502282499069629660067520588953222350511785313015510628099851763437253603253292206693665849951761355348626222976632736302988522601311275484771250652762026921947170188217539811008577940147903383872484450616566697941278828073032953299017447498073055295325961865824002868867473303760698067810206224428310567
"""
N = int(P_hex.strip(), 10)
g = 2

def H(*args):
    sha = hashlib.sha256()
    for a in args:
        if isinstance(a, int):
            length = (N.bit_length() + 7) // 8
            sha.update(a.to_bytes(length, byteorder='big'))
        elif isinstance(a, bytes):
            sha.update(a)
        elif isinstance(a, str):
            sha.update(a.encode('utf-8'))
    return sha.digest()

k = int.from_bytes(H(N, g), 'big')


def srp_client(username, password, salt_hex, A, B, a): # o username nao e usado, pois e dado manualmente, mas e necessario para a funcao 
    """
    Computa a chave do lado cliente e retorna (K_c, M1_c).
    """
    salt = bytes.fromhex(salt_hex)

    xH = H(salt, password)
    x = int.from_bytes(xH, 'big')

    uH = H(A, B)
    u = int.from_bytes(uH, 'big')

    gx = pow(g, x, N)
    tmp = (B - k * gx) % N
    S_c = pow(tmp, (a + u*x), N)

    K_c = H(S_c)

    M1_c = H(K_c, A, B)
    return (K_c, M1_c)

def run_srp_client(username="alice", password="12345", host="127.0.0.1", port=8080):
    print(f"Cliente SRP à escuta em {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        a = secrets.randbelow(N)
        A = pow(g, a, N)

        msg_out = {"username": username, "A": A}
        s.sendall(json.dumps(msg_out).encode('utf-8'))

        data = s.recv(4096)
        msg_in = json.loads(data.decode('utf-8'))
        if "error" in msg_in:
            print("[Client] Erro recebido:", msg_in["error"])
            return

        salt_hex = msg_in["salt"]
        B = msg_in["B"]

        K_c, M1_c = srp_client(username, password, salt_hex, A, B, a)
        M1_hex = M1_c.hex()

        #Envia M1
        msg_out = {"M1": M1_hex}
        s.sendall(json.dumps(msg_out).encode('utf-8'))
        
        #Recebe M2
        data = s.recv(4096)
        msg_in = json.loads(data.decode('utf-8'))
        if "error" in msg_in:
            print("[Client] Erro recebido:", msg_in["error"])
            return

        M2_hex = msg_in["M2"]
        M2_s = bytes.fromhex(M2_hex)

        # Verifica M2
        M2_expected = H(A, M1_c, K_c)
        if M2_s == M2_expected:
            print("[Client] Autenticação bem-sucedida! Servidor comprovou conhecimento da chave.")
            print(f"[Client] Chave derivada K_c = {K_c.hex()}")
        else:
            print("[Client] Falha na verificação de M2.")

if __name__ == "__main__":
    run_srp_client()
