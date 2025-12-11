# Imagem do modelo da solução

Abaixo será apresentada a imagem de um modelo que dá a solução para o problema proposto pelo professor.

Esta solução não só respeita o devido funcionamento do **Cofre Digital**, como também leva em conta o levantamento de requisitos e a análise de riscos, uma vez que mitiga todos os problemas. 

Contudo, o modelo não é suficiente para explicar quais tecnologias foram projetadas para serem usadas em cada parte do nosso sistema, por tal motivo terá um texto explicativo, que não só explica o fluxo de forma organizada, como expõe como é assegurada a segurança do sistema.

![Digital Vault Solution](https://github.com/uminho-mei-es/2425-G8/blob/main/Projs/P1/Solução/Digital_Vault_Solution.png)

# Explicação

Para a apresentação dos fluxos do sistema ser apresentada de forma organizada, definiu-se uma estrutura que lista todas as funcionalidades essenciais e, para cada uma delas, descreve o processo e as implementações de segurança associadas. Essa abordagem permite identificar precisamente quais etapas do fluxo são afetadas por cada requisito de segurança.

O formato utilizado para esta explicação é o seguinte:

```
Processo:
1. (...)
2. (...)
...
n. (...)

Implementação de Segurança:
- (Parte do fluxo afetada)   Medida de Segurança   (Requisito de Segurança correspondente)
- ...
```

## Fluxo de Registro de Utilizadores

### Processo:
1. O utilizador acede à aplicação cliente (CLI) e através dela começa o seu registro;
2. O utilizador fornece os dados, ou seja, email, nome e senha;
3. No CLI há a valição dos dados localmente (formato de email, complexidade da senha);
4. Os dados, depois de validados, são enviados ao servidor através de um canal seguro (TLS 1.3 + HMAC);
5. O servidor gera um identificador único para o utilizador e esse utilizador fica em "espera";
6. A senha é processada de forma segura;
7. Um email de verificação (com token expirável) é enviado ao utilizador;
8. O utilizador confirma o email ao clicar no link de verificação;
9. A conta é validada e o utilizador deixa de ficar em "espera" e se torna um utilizador legítimo.

### Implementações de Segurança:
- (3) Validação do formato e da unicidade do email **(SEG1)**;
- (3) Validação da complexidade da senha (mais de 8 caracteres, maiúsculas, minúsculas, números e símbolos) **(SEG2)**.
- (6) Armazenar de forma seguro das senhas com uso de hashing + salt com Argon2id **(SEG3)**.
- (7, 8) Verificação de email com token único e expirável (24 horas) **(SEG4)**.
- (3) Sanitização dos inputs para prevenir injeção de metadados **(SEG5)**.
- (5) Geração de identificadores únicos através de UUID v4 **(SEG6)**.
- (5) Proteção do identificador contra ataques que vizem alterar ou falsificá-lo **(SEG7)**.
- (4) Comunicação segura via TLS 1.3 e HMAC **(SEG23)**.

---

## Fluxo de Autenticação

### Processo:
1. O utilizador fornece as credenciais ao CLI;
2. No CLI encaminha-se essas credenciais ao **módulo de autenticação**;
3. O **módulo de autenticação** verifica as credenciais com o servidor;
4. Se as credenciais forem válidas, solicita o segundo fator;
5. O utilizador fornece o segundo fator;
6. Após a validação de dois fatores, um token de sessão é gerado;
7. CLI e servidor estabelecem comunicação segura;
8. A _**Gestão das sessões**_ no cliente gerencia o ciclo de vida do token.

### Implementações de Segurança:
- (4) Autenticação multifator (SEG8).
- (1) Bloqueio de conta após três tentativas falhas **(SEG9)**.
- (6) Tokens de sessão aleatórios com tempo limite de 5 minutos **(SEG10)**.
- (7) TLS 1.3 em todos os endpoints de autenticação **(SEG11)**.
- (7) Limite de _Ratting_, sendo de 10 tentativas por minuto (com o mesmo IP) **(SEG12)**.
- (8) Renovação e expiração adequada de sessões **(SEG26)**.
- (7) Validação de certificados para TLS **(SEG25)**.
- (7) HMAC para integridade e autenticidade das mensagens **(SEG24)**.

---

## Fluxo de Gestão do Cofre Digital

### Processo:
1. O utilizador autenticado acede ao seu cofre através do CLI;
2. O CLI apresenta a estrutura hierárquica das pastas e ficheiros;
3. O **Gestor de Recursos** no servidor verifica as permissões do utilizador;
4. O utilizador pode visualizar, modificar ou criar pastas/ficheiros se tiver permissões para tal;
5. Todas as operações são registradas pelo **Controlador de Logs** no **Log Dataset**;
6. O **Gestor de Metadados** controla as informações associadas aos recursos.

### Implementações de Segurança:
- (3,4,6) Isolamento dos cofres entre utilizadores **(SEG13)**.
- (5) Proteção dos metadados sensíveis com criação de _logs_ **(SEG14)**.
- (3) Verificações das consistência em operações hierárquicas **(SEG19)**.
- (6) Sistema de filas para quando há um acumuar de muitos pedidos **(SEG34)**.
- (6) Limite de _Ratting_ para utilizadores legítimos de  100 pedidos por minuto **(SEG32)**.
- (6) Deteção de padrões anómalos (200 pedidos por minuto, do mesmo IP) **(SEG33)**.

---

## Fluxo de Gestão de Ficheiros e Pastas

### Processo:
1. O utilizador pode escolher que operação realizar das permitidas pelo sistema (criar, modificar e remover);
2. O **Interpretador de Comandos** no cliente processa a operação pedida;
3. O **Controlador de Acesso** no servidor verifica se o utilizador tem as permissões para tal operação;
4. O **Gestor de Recursos** executa a operação, caso se verifique que o utilizador tem as permissões necessárias;
5. Operações de reciclagem/eliminação movem esses recursos para uma "Lixeira", sendo passíveis de recuperação;
6. Todas as operações são registradas pelo **Controlador de Logs**.

### Implementações de Segurança:
- (3, 4) Controlo no acesso baseado em utilizadores autorizados **(SEG15)**.
- (6) Registro de todas as operações para auditoria **(SEG16)**.
- (5) Proteção contra remoções acidentais **(SEG17)**.
- (1, 2, 3, 4) Verificação de permissões em cascata na hierarquia **(SEG18)**.

---

## Fluxo de Encriptação e Processamento de Dados

### Processo:
1. Quando um ficheiro é selecionado para _upload_, o **Encriptador Local** o encripta;
2. O cliente, no CLI, gera uma chave única para o ficheiro através do uso de **AES-256-GCM**;
3. A chave do ficheiro é encriptada com a **MasterKey** do utilizador;
4. O ficheiro encriptado e a chave encriptada são enviados para servidor;
5. O servidor armazena os dados (ficheiro encriptado + chave encriptada) sem conhecer o conteúdo;
6. Para acessar o conteúdo, o processo é revertido, com a decriptação a ocorrer no cliente.

### Implementações de Segurança:
- (1) Encriptação de todos os ficheiros com AES-256-GCM **(SEG29)**.
- (2, 3) Derivação de chaves baseada na senha do utilizador via KDF **(SEG30)**.
- (3, 4) Armazenamento seguro de chaves com encriptação assimétrica **(SEG31)**.
- (4, 5, 6) O servidor nunca tem acesso ao conteúdo dos ficheiros **(FUNC 10)**.

---

## Fluxo de Partilha de Recursos

### Processo:
1. O utilizador (proprietário do ficheiro) seleciona um ficheiro/pasta para partilhar;
2. Define permissões específicas (read, append, write) para o destinatário em relação àquele recurso;
3. O propietário reencripta a chave do recurso (que antes era encriptada com a **MasterKey** do próprio utilizador) com a chave pública do destinatário;
4. O servidor armazena a nova chave encriptada e as permissões que o proprietário especificou;
5. O sistema de partilha atualiza as permissões em tempo real;
6. Todas as alterações de permissões são registradas.

### Implementações de Segurança:
- (5) Verificação de permissões em tempo real **(SEG20)**.
- (2, 4) Prevenção de escalada indevida de privilégios **(SEG21)**.
- (6) Logs de auditoria para alterações de permissões **(SEG22)**.

---

## Fluxo de Auditoria e Rastreabilidade

### Processo:
1. Cada operação no sistema é registrada pelo **Controlador de Logs**;
2. Os _logs_ incluem os seguintes campos: _timestamps_, utilizador, operação, recurso e resultado;
3. Os _logs_ são armazenados de forma segura e à prova de alterações;
4. Acesso aos _logs_ é restrito com base na hierarquia de permissões;
5. *Administradores* podem auditar operações para fins de segurança.

### Implementações de Segurança:
- (3, 4) Armazenamento seguro de logs à prova de alterações **(SEG27)**.
- (4) Sistema de acesso restrito aos logs baseado em hierarquia **(SEG28)**.
- (1, 2, 5) Registros detalhados para auditoria completa **(SEG16)**.

---

## Gestão de Falhas e Resiliência do Sistema

Já foi explicado tanto o processo como a implementação ao longo da solução, não é necessário voltar a realçar tal ponto.

---

# Resumo dos métodos criptográficos:

| Key Type       | Algorithm                              | Purpose                             |
|----------------|----------------------------------------|-------------------------------------|
| Master Key     | Derived via PBKDF2 from user password  | User's root key                     |
| File Keys      | AES-256-GCM                            | Individual file encryption          |
| Shared Keys    | Asymmetric RSA                         | Secure key sharing between users    |
| Transport Keys | TLS 1.3                                | Secure client-server communication  |

