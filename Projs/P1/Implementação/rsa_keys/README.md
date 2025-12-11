# RSA Keys

⚠️ **IMPORTANTE: NÃO FAZER COMMIT DE CHAVES PRIVADAS REAIS!**

## Como gerar suas próprias chaves RSA

### Método 1: OpenSSL (Recomendado)

```bash
# Gerar chave privada (2048 bits)
openssl genrsa -out login_private.pem 2048

# Gerar chave pública a partir da privada
openssl rsa -in login_private.pem -pubout -out login_public.pem
```

### Método 2: Python

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Gerar par de chaves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Salvar chave privada
with open("login_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Salvar chave pública
public_key = private_key.public_key()
with open("login_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
```

## Ficheiros necessários

- `login_private.pem` - Chave privada (NÃO fazer commit!)
- `login_public.pem` - Chave pública (pode fazer commit se necessário)

## Boas práticas

1. ✅ Adicione `*.pem` ao `.gitignore`
2. ✅ Use variáveis de ambiente para paths de chaves
3. ✅ Mantenha chaves privadas fora do repositório
4. ✅ Rotacione chaves regularmente
5. ✅ Use permissões restritivas (chmod 600) em chaves privadas
6. ❌ NUNCA faça commit de chaves privadas
7. ❌ NUNCA partilhe chaves privadas
8. ❌ NUNCA use as mesmas chaves em produção e desenvolvimento
