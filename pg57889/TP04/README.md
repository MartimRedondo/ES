## Resolução do exercício 4

Server.py:
  - Armazena (em um dicionário) as informações de registro do usuário (salt, v).
  - Aguarda conexão do cliente, recebe (username, A), gera (b, B), envia (salt, B), recebe M1, valida e responde M2.
    
Client.py:
  - Faz conexão com o servidor.
  - Envia (username, A), recebe (salt, B).
  - Calcula a chave SRP, gera M1, envia ao servidor.
  - Recebe M2 e valida.

### Este exemplo ilustra a troca de mensagens SRP em rede (mesmo que seja localhost)


### INSTRUÇÕES:

Começar por:
  - python3 ServerDH.py
    
e depois:
  - python3 ClienteDH.py
