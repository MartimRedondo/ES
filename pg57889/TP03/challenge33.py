import secrets 
import hashlib

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

p = 37
g = 5

print("====================================")
print("EXEMPLO INICIAL COM VALORES PEQUENOS")
print("====================================")

a = secrets.randbelow(p) # ou seja, a vai estar no intervalo [0, 36], ou seja, é mod 37
b = secrets.randbelow(p) # IDEM

#public keys
A = my_own_modexp(g, a, p)
B = my_own_modexp(g, b, p)


s1 = my_own_modexp(B, a, p)
s2 = my_own_modexp(A, b, p)

print("As chaves são iguais?", s1 == s2)

key = hashlib.sha256(str(s1).encode()).digest()
print("Key material (SHA-256 de s1):", key.hex())
print()


print("====================================")
print("AGORA COM NÚMEROS GRANDES")
print("====================================")

p_hex = (
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff"
)

p_big = int(p_hex, 16)
g_big = 2

a_big = secrets.randbelow(p_big)
b_big = secrets.randbelow(p_big)

A_big = my_own_modexp(g_big, a_big, p_big)
B_big = my_own_modexp(g_big, b_big, p_big)


s1_big = my_own_modexp(B_big, a_big, p_big)
s2_big = my_own_modexp(A_big, b_big, p_big)

print("As chaves são iguais?", s1_big == s2_big)

key_material_big = hashlib.sha256(str(s1_big).encode()).digest()
print("Key material (SHA-256 de s1_big):", key_material_big.hex())
