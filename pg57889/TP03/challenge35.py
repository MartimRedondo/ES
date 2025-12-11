import secrets

def my_own_modexp(base, exp, mod):
    result = 1
    base = base % mod
    e = exp
    while e > 0:
        if e & 1:  
            result = (result * base) % mod
        base = (base * base) % mod
        e >>= 1 
    return result

def alice_send_A(p, g, a):
    return my_own_modexp(g, a, p)

def bob_send_B(p, g, b):
    return my_own_modexp(g, b, p)

def dh_shared_secret(public_val, private_exponent, p):
    return my_own_modexp(public_val, private_exponent, p)

def mitm_exchange(p, g_malicioso):
    a = secrets.randbelow(p)
    b = secrets.randbelow(p)

    A = alice_send_A(p, g_malicioso, a)
    B = bob_send_B(p, g_malicioso, b)

    s_alice = dh_shared_secret(B, a, p)
    s_bob   = dh_shared_secret(A, b, p)

    return (a, b, A, B, s_alice, s_bob)



p = 37

for g_mal in [1, p, p-1]:
    a, b, A, B, sA, sB = mitm_exchange(p, g_mal)
    print ("==========================================")
    print ("TESTANDO O MITM com g malacioso = ", g_mal)
    print ("==========================================")
    print(f"Alice's secret exponent a = {a}")
    print(f"Bob's secret exponent   b = {b}")
    print(f"A = g^a mod p = {A}")
    print(f"B = g^b mod p = {B}")
    print(f"Chave final de Alice = {sA}")
    print(f"Chave final de Bob   = {sB}")
    print(f"As chaves batem? {sA == sB}")
