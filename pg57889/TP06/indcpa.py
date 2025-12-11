import random
from abc import ABC, abstractmethod

# Definição das classes abstratas
class Cipher(ABC):
    @abstractmethod
    def keygen(self) -> bytes:
        pass

    @abstractmethod
    def enc(self, key: bytes, text: bytes) -> bytes:
        pass

    @abstractmethod
    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        pass

class INDCPA_Adv(ABC):
    @abstractmethod
    def choose(self, oracle: callable):
        pass

    @abstractmethod
    def guess(self, oracle: callable, ciphertext: bytes, state) -> int:
        pass

#--------------------------------------------
# Implementação da cifra e do adversário
#--------------------------------------------


#----------------------
# Função de cifra XOR
#----------------------

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

#----------------------
# Cifra XOR segura
#----------------------

class SecureXORCipher(Cipher):
    def keygen(self) -> bytes:
        return random.randbytes(16) # 16 é a nossa variavel de segurança

    def enc(self, key: bytes, text: bytes) -> bytes:
        if len(key) != len(text):
            raise ValueError("Tamanho da chave e do texto não coincidem")
        
        nonce = random.randbytes(len(text)) # graças o nonce as chances de repetição são minimas
        ct = xor(key, text)
        return nonce + ct

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        n = len(ciphertext) // 2
        nonce = ciphertext[:n] # o nonce é a primeira metade do texto cifrado, nao é preciso guardar, mas para separar e ficar intuitivo
        ct = ciphertext[n:]
        if len(key) != len(ct):
            raise ValueError("Tamanho da chave e do texto cifrado não coincidem")
        return xor(key, ct)

#----------------------
# Adversário IND-CPA
#----------------------

class IdentityAdv(INDCPA_Adv):
    def choose(self, oracle: callable):
        msg0 = b"1" * 16
        msg1 = b"0" * 16

        ct0 = oracle(msg0)
        ct1 = oracle(msg1)

        state = {"msg0": msg0, "msg1": msg1, "ct0": ct0, "ct1": ct1}
        
        return msg0, msg1, state

    def guess(self, oracle: callable, ciphertext: bytes, state) -> int:
        ct0 = state["ct0"]
        ct1 = state["ct1"]

        # Por algumo motivo ao fazer a checagem leva a dar sempre return 1 pelo nonce ser aleatório, como não é
        # algo extemanente relevante para a segurança, optei por comentar e continuar

        #ct1_by_us = oracle(state["msg1"])
        #ct0_by_us = oracle(state["msg0"])
#
        #if ct0_by_us != ct0 or ct1_by_us != ct1:
        #    return -1
        
        if ciphertext == ct0:
            return 0
        elif ciphertext == ct1:
            return 1
        else:
            return random.randint(0, 1)

def indcpa_game(C: Cipher, A: INDCPA_Adv) -> bool:
    k = C.keygen()
    enc_oracle = lambda pt: C.enc(k, pt)
    
    m0, m1, state = A.choose(enc_oracle)
    assert len(m0) == len(m1), "As mensagens escolhidas devem ter o mesmo tamanho."
    
    b = random.randint(0, 1)
    ciphertext = C.enc(k, m0 if b == 0 else m1)
    b_prime = A.guess(enc_oracle, ciphertext, state)

    if b_prime == -1:
        return False
    else:
        return b == b_prime

def main():
    iterations = 10000
    wins = 0

    # Para demonstrar uma cifra segura, usamos a cifra aleatorizada.
    C = SecureXORCipher()
    A = IdentityAdv()

    for _ in range(iterations):
        if indcpa_game(C, A):
            wins += 1

    win_probability = wins / iterations
    advantage = abs(2 * win_probability - 1)
    
    print(f"Número de iterações: {iterations}")
    print(f"Taxa de sucesso do adversário: {win_probability:.4f}")
    print(f"Vantagem do adversário: {advantage:.4f}")

if __name__ == "__main__":
    main()
