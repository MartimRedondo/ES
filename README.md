# Composição do grupo:

| Num.  | Nome  | username  |
| :---  | :--- | :---:      |
| pg57511 | Benjamim Meleiro Rodrigues | 150benjamim |
| pg57879 | João Andrade Rodrigues | joaorodriguesss |
| pg57889 | Martim José Amaro Redondo | MartimRedondo |

---

## SEGURANÇA

## Gestão de Credenciais

### Boas Práticas de Segurança

#### 1. Chaves Privadas e Certificados

**NUNCA commit de:**
- Chaves privadas RSA (`*.pem`, `*_private*`)
- Certificados privados (`*.key`)
- Tokens de autenticação
- Passwords ou credenciais

**Como gerar chaves próprias:**

```bash
# Gerar par de chaves RSA
openssl genrsa -out login_private.pem 2048
openssl rsa -in login_private.pem -pubout -out login_public.pem

# Definir permissões corretas
chmod 600 login_private.pem
chmod 644 login_public.pem
```

#### 2. Variáveis de Ambiente

Variáveis de ambient sensiveis:

```python
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv('DATABASE_URL')
```

#### 3. Ficheiros de Configuração

Ficheiro `.env.example` com valores de exemplo:

```bash
# .env.example
SECRET_KEY=your_secret_key_here
DATABASE_URL=postgresql://user:password@localhost/dbname
JWT_SECRET=your_jwt_secret_here
```

**Nunca faça commit do `.env` real!**

#### 4. Verificar Histórico Git

Se acidentalmente fez commit de credenciais:

```bash
# Instalar git-filter-repo
pip install git-filter-repo

# Remover ficheiro do histórico
git-filter-repo --path caminho/para/ficheiro --invert-paths --force

# Force push
git push origin branch-name --force
```

## Boas práticas

1. ✅ Adicionar os ficheiros `*.pem` ao `.gitignore`
2. ✅ Usar as variáveis de ambiente para paths de chaves
3. ✅ Manter as chaves privadas fora do repositório
4. ✅ Rotacionar as chaves regularmente
5. ✅ Usar as permissões restritivas (chmod 600) em chaves privadas
6. ❌ NUNCA fazer commit de chaves privadas
7. ❌ NUNCA partilhar chaves privadas
8. ❌ NUNCA usar as mesmas chaves em produção e desenvolvimento