# Threat Model

![Threat Model](https://github.com/uminho-mei-es/2425-G8/blob/main/Projs/P1/AnáliseRisco/ThreatModel.png)

## Explicação:

O Threat Model do Secure Vault identifica os principais pontos de interação e os respetivos limites de confiança (“trust boundaries”) dentro do sistema. Este modelo permite uma análise estruturada das potenciais ameaças e dos riscos associados a cada uma dessas interações, facilitando a implementação de medidas de segurança adequadas.

### Estrutura e Trust Boundaries

O sistema baseia-se na interação entre quatro componentes principais:

- **Utilizador (User)**: Ponto de entrada para interagir com o sistema.

- **Aplicação Cliente (CLI)**: Interface utilizada pelo utilizador para executar comandos.

- **Servidor (SRV)**: Responsável por processar os pedidos e gerir a acessibilidade aos recursos.

- **Armazenamento Local (Store)**: Onde os ficheiros e metadados são mantidos.

Os limites de confiança identificados no modelo são:

- **User/CLI**: Delimita a interação entre o utilizador e a aplicação cliente, sendo um ponto crítico para ataques relacionados com roubo de credenciais e acesso não autorizado ao dispositivo.

- **CLI/SRV**: Define a comunicação entre o cliente e o servidor, onde podem ocorrer ataques de interceção, injeção de comandos e reutilização de tokens de autenticação.

- **SRV/Store**: Representa a interação entre o servidor e o armazenamento local, exigindo garantias de integridade, confidencialidade e controlo adequado de acessos.

Este modelo fornece uma visão estruturada das superfícies de ataque e das vulnerabilidades que precisam de ser abordadas no design e implementação do sistema Secure Vault.

# Identificação de Ameaças e Riscos

## 1. Análise tendo em conta a conexão Utilizador - CLI

### Ameaças
- Captura de credenciais através do uso de _"programas de espionagem"_ sem permissão do utilizador legítimo; 
- Manipulação da interface do cliente (CLI) para mandar comandos não autorizados;
- Acesso não autorizado à sessão ativa do utilizador através do dispositivo físico.

### Riscos
- Comprometimento das credenciais de autenticação;
- Execução de operações de forma não intencional pelo utilizador legítimo;
- Acesso não autorizado ao cofre digital devido ao uso de um dispostivo desprotegido.

## 2. Análise tendo em conta a conexão Cliente-Servidor

### Ameaças
- Ataques Man-in-the-Middle interceptando a comunicação;
- Ataque reutilizando comandos ou tokens capturados de forma a replicar o processo pelo qual o utilizador legítimo passa para aceder ao sistema;
- Ataques de injeção nos comandos enviados ao servidor;
- Roubo de informações devido ao uso do sistema quando conectado com um rede não segura.

### Riscos
- Exposição de dados durante a transmissão;
- Execução de comandos forjados através de ter os privilégios do utilizador legítimo;
- Interceptação das chaves criptográficas durante a troca inicial.

## 3. Análise tendo em conta a conexão Servidor-Armazenamento

### Ameaças
- Acesso direto ao armazenamento contornando o servidor;
- Manipulação de metadados para conseguir ter controlo sobre as permissões de acesso;
- Corrupção da integridade dos dados armazenados.

### Riscos
- Exposição dos dados ao atacante sem que ele tenha que passar pela segurança do servidor
- Exposição de conteúdo cifrado;
- Exposição de metadados sensíveis;
- Perda de dados ou indisponibilidade do sistema.

## 4. Ameaças e Riscos ao Componente Servidor (SRV)

### Ameaças
- Elevação de privilégios no servidor;
- Ataques de DDoS com a intenção de fazer com que o serviço fique indisponível;
- Exploração de vulnerabilidades na segurança do servidor;

### Riscos
- Acesso não autorizado aos recursos armazenados.
- Interrupção do serviço para todos os utilizadores devido a ataques DDoS.
- Exposição de chaves e tokens geridos pelo servidor.

## 5. Ameaças ao Componente Cliente (CLI)

### Ameaças
- O atacante analisa a arquitetura do sistema para conseguir achas falhas no sistema;
- Manipulação do cliente para contornar validações locais;
- Instalação de versões adulteradas da aplicação, em vez da versão legítima.

### Riscos
- Criação de clientes com intenções maliciosas para explorar as vulnerabilidades do sistema;
- Exposição local das chaves de cifra dos utilizadores.

## 6. Ameaças ao Modelo de Autenticação e Autorização

### Ameaças
- Ataques de força bruta às credenciais.
- O atacante pode fazer com que o utilizador legítimo se autentique à sessão com um **ID** forjado, passando-se assim pelo utilizador legítimo;
- O atacante captura o **ID** da sessão do utilizador e usa-a, passando-se assim pelo utilizador legítimo;
- Falsificação de identidade através de manipulação de tokens;
- Falhas na verificação de permissões em recursos compartilhados.

### Riscos
- Acesso não autorizado a contas de utilizadores legítimos;
- Escalada de privilégios horizontal (acesso a outros utilizadores de forma indevida);
- Escalada de privilégios vertical (obtenção de permissões elevadas de forma indevida).

## 7. Ameaças à Confidencialidade dos Dados

### Ameaças
- Ataque de força bruta ao cofre digital (tentativa e erro);
- O atacante descobre o método de encriptação devido à análise do comportamento do computador face ao sistema;
- Análise de tráfego para obter informações sobre metadados e padrões de transmissão.

### Riscos
- Exposição do conteúdo de ficheiros confidenciais.
- Comprometimento do modelo de end-to-end encryption, ou seja, um terceiro interveniente pode ter acesso aos dados que seriam exclusivamente conhecidos pelos dois utilizadores;
- Revelação de informações sensíveis mesmo sem acesso direto ao conteúdo.

## 8. Ameaças à Integridade e Rastreabilidade

### Ameaças
- Modificação não autorizada de logs de auditoria;
- Manipulação de timestamps e registos de operações;
- Remoção seletiva de eventos de auditoria.

### Riscos
- Impossibilidade de rastrear acessos e modificações não autorizadas;
- Comprometimento dos logos que levam ao facto de não se poder investigar em caso de problemas;
- Alterações silenciosas em dados armazenados sem possibilidade de detecção.

## 9. Ameaças à Gestão de Chaves

### Ameaças
- Derivação insegura de chaves a partir de senhas fracas (KDF pouco robusco e facilmente previsível);
- Armazenamento inadequado das chaves de cifra;
- Vulnerabilidades no compartilhamento de chaves entre utilizadores legítimos.

### Riscos
- Comprometimento das chaves mestras dos utilizadores;
- Acesso aoconteúdo cifrado após comprometimento da chave;
- Impossibilidade de reverter a atribuição de permissões feitas.

## 10. Ameaças Específicas ao Modelo de Partilha

### Ameaças
- Confusão de permissões em estruturas hierárquicas complexas, onde à confusão do sistema a quais ficheiros o utilizador pode ter acesso;
- _Race conditions_ na verificação e aplicação de permissões;
- Revogação incompleta de acesso a recursos compartilhados.

### Riscos
- Acesso não intencional a recursos protegidos;
- Vazamento de dados devido a políticas de partilha mal configuradas;
- Permanência de acesso mesmo após revogação formal.
