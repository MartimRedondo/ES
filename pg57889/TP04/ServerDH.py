import socket
import secrets
import hashlib
import json

# ----------------------------
# PARÂMETROS SRP (N, g, k)
# ----------------------------
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

k = int.from_bytes(H(N, g), 'big')  # k = H(N, g)

USER_DB = {}

def srp_register(username, password):
    salt = secrets.token_bytes(16)
    xH = H(salt, password)
    x = int.from_bytes(xH, 'big')
    v = pow(g, x, N)
    USER_DB[username] = (salt, v)

srp_register("alice", "12345") # Adiciona um usuário ao DB de forma fixa


def srp(username, A):
    """
    Recebe username e A.
    Retorna (salt, B) para o cliente.
    E guarda localmente tudo que precisamos para checar M1.
    """
    if username not in USER_DB:
        raise ValueError("Usuário não encontrado no DB.")

    salt, v = USER_DB[username]

    b = secrets.randbelow(N)
    B = (k * v + pow(g, b, N)) % N

    server_state = {
        "username": username,
        "salt": salt,
        "v": v,
        "A": A,
        "b": b,
        "B": B
    }
    return (salt, B, server_state)

def srp_M2(server_state, M1_client):
    """
    Recebe M1 do cliente, valida e gera M2.
    Retorna (M2, K_s) para o servidor usar, ou (None, None) se falhar.
    """
    A = server_state["A"]
    B = server_state["B"]
    b = server_state["b"]
    v = server_state["v"]
    salt = server_state["salt"]

    uH = H(A, B)
    u = int.from_bytes(uH, 'big')

    S_s = pow(A * pow(v, u, N), b, N)
    K_s = H(S_s)  # chave derivada do servidor

    M1_expected = H(K_s, A, B)
    if M1_expected != M1_client:
        print("[Server] M1 incorreto, falha de autenticação.")
        return (None, None)

    print("[Server] M1 está correto. Cliente autenticado!")
    M2_s = H(A, M1_client, K_s)
    return (M2_s, K_s)


def run_srp_server(host="127.0.0.1", port=8080):
    print(f"Servidor SRP a ouvir em {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print(f"Connection from {addr}")
            data = conn.recv(4096)
            msg_in = json.loads(data.decode('utf-8'))
            username = msg_in["username"]
            A = msg_in["A"]  

            salt, B, server_state = srp(username, A)
            msg_out = {
                "salt": salt.hex(),
                "B": B
            }
            conn.sendall(json.dumps(msg_out).encode('utf-8'))

            #Recebe M1 do cliente
            data = conn.recv(4096)
            msg_in = json.loads(data.decode('utf-8'))
            M1_hex = msg_in["M1"]  # hex string
            M1_client = bytes.fromhex(M1_hex)

            # Computa M2 e envia
            M2_s, K_s = srp_M2(server_state, M1_client)
            if M2_s is None:
                msg_out = {"error": "Authentication failed"}
                conn.sendall(json.dumps(msg_out).encode('utf-8'))
                return
            else:
                M2_hex = M2_s.hex()
                msg_out = {"M2": M2_hex}
                conn.sendall(json.dumps(msg_out).encode('utf-8'))

            print("[Server] Autenticação concluída com sucesso!")
            print(f"[Server] Chave derivada K_s = {K_s.hex()}")

if __name__ == "__main__":
    run_srp_server()
