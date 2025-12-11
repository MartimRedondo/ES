# Relatório de Implementação - Análise Comparativa

## Introdução

Este relatório não visa explicar o que foi desenvolvido, uma vez que essa tarefa já foi realizada na primeira fase, no ficheiro [documento de solução](../P1/README.md). O propósito deste documento é **documentar as alterações** realizadas em nosso código quando comparado com:

1. A proposta de solução inicial;
2. Em determinados casos, as mudanças em relação ao protótipo.

## Metodologia de Análise

Para garantir que o documento é sucinto e de fácil análise e facilitar, seguiu-se uma estrutura organizada em forma de checklist. Cada elemento da proposta original será avaliado da seguinte forma:

- ✅ **Implementado conforme planejado**;
- ❌ **Alteração na implementação**.

Para cada item marcado com ❌, terá um _link_ para a secção do documento que explica detalhadamente:
- O que foi efetivamente implementado;
- As razões que motivaram tal mudança;
- Análise de impacto (quando aplicável).

Após esta análise estruturada, será incluidas algumas considerações adicionais sobre aspectos importantes que, por alguma razão, não foram aboradadas durante o documento.

## Análise Comparativa

A seguir, apresentamos os elementos da solução proposta com sua respectiva avaliação:

| Ferramentas/Tecnologias |  |  |
|----------|--------|--------------|
| Fluxo de Registro de Utilizadores | ✅ |  |
| Validação de email e senha (SEG1, SEG2) | ✅ |  |
| Armazenamento seguro de senhas (SEG3) | ✅ |  |
| Verificação por email (SEG4) | ❌ | [Ver detalhes](#alteracao_verificacao_email) |
| Comunicação segura TLS 1.3 + HMAC (SEG23) | ❌ | [Ver detalhes](#alteracao_HMAC) |
| Fluxo de Autenticação | ❌ | [Ver detalhes](#alteracao_fluxo_autenticação) |
| Autenticação multifator (SEG8) | ❌ | [Ver detalhes](#alteracao_2fa) |
| Bloqueio após tentativas falhas (SEG9) | ❌ | [Ver detalhes](#alteracao_xTentativas) |
| Tokens de sessão e renovação (SEG10, SEG26) | ✅ | |
| Fluxo de Gestão do Cofre Digital | ✅ |  |
| Isolamento de cofres (SEG13) | ✅ |  |
| Sistema de filas e limite de requests (SEG32-34) | ❌ | [Ver detalhes](#alteracao_limites) |
| Fluxo de Gestão de Ficheiros e Pastas | ✅ |  |
| Controle de acesso baseado em utilizadores (SEG15) | ✅ |  |
| Registro de operações para auditoria (SEG16) | ❌ | [Ver detalhes](#alteracao_auditoria) |
| Fluxo de Encriptação de Dados | ✅ |  |
| Encriptação AES-256-GCM (SEG29) | ✅ |  |
| Derivação de chaves via KDF (SEG30) | ✅ |  |

| Implementação dos Comandos |  |  |
|----------|--------|--------------|
| Comando UPLOAD | ✅ | [Ver detalhes](#alteracao_comando_upload) |
| Comando SHARE | ✅ | [Ver detalhes](#alteracao_comando_share) |
| Comando READ | ✅ | [Ver detalhes](#alteracao_comando_read) |
| Comando APPEND | ✅ | [Ver detalhes](#alteracao_comando_append) |
| Comando WRITE | ✅ | [Ver detalhes](#alteracao_comando_write) |

##  Alterações 


<!-- OPA -->

<a id="alteracao_verificacao_email"></a>
### Alteração 1

**Proposta original:**
> Verificação de email com token único e expirável (24 horas) (SEG4)

**Implementação atual:**
    O sistema implementado não possui um mecanismo de verificação por email. O registro é concluído imediatamente após enviar os dados ao servidor, sem o passo de confirmação por email.

**Motivação:**
1. Simplificação do fluxo de registro inicial;
2. Possíveis limitações na configuração de um servidor SMTP para envio de emails;
3. Foco em estabelecer os mecanismos essenciais de encriptação e autenticação, em prol de perda de características que não são de importância extrema.


<!-- OPA -->

<a id="alteracao_HMAC"></a>
### Alteração 2 

**Proposta original:**
>  Comunicação segura via TLS 1.3 e HMAC (SEG23)

**Implementação atual:**
    O sistema usa TLS 1.3, contudo não usa HMAC, em contra partida usa uma biblioteca proposta pelo professor (HTTPX e Typer), não substitui o HMAC de forma direta, mas ao usar estas biblitoecas integrar o HMAC tornar-se-ia algo complementar, sem grandes benefícios.

**Motivação:**
1. Bibliotecas que substitui indiretamente o HMAC;
2. Praticamente a mesma segurança;
3. Implementação mais simples e modular.


<!-- OPA -->

<a id="alteracao_fluxo_autenticação"></a>
### Alteração 3 

**Proposta original:**
> O fluxo completo de autenticação incluía verificação de credenciais, solicitação de segundo fator, geração de token de sessão e gestão do ciclo de vida do token

**Implementação atual:**
    O fluxo implementado utiliza um sistema baseado em nonce para autenticação. O cliente solicita um nonce do servidor, combina este nonce com a senha cifrada e envia para autenticação. O sistema mantém sessões ativas por terminal, mas com uma estrutura simplificada em comparação à proposta original.

**Motivação:**
1. Implementação de um mecanismo eficaz de desafio-resposta com nonce, exclusivo da etapa login, visto que é um dos pontos mais críticos do nosso sistema, por possíveis ataques de replay;
2. Simplificação do processo mantendo a segurança da transferência de credenciais;
3. Adaptação baseada nos requisitos práticos do sistema


<!-- OPA -->

<a id="alteracao_2fa"></a>
### Alteração 4

**Proposta original:**
> Autenticação multifator (SEG8)

**Implementação atual:**
    O código não implementa autenticação multifator. A autenticação é baseada apenas em email/senha + nonce.

**Motivação:**
1. Simplicação para mais tempo e foco no que realmente é de importância maior.


<!-- OPA -->

<a id="alteracao_xTentativas"></a>
### Alteração 5 

**Proposta original:**
> Bloqueio de conta após três tentativas falhas (SEG9)

**Implementação atual:**
    Não existe mecanismo implementado para contagem e bloqueio de tentativas falhas de login.

**Motivação:**
1. Simplicação para mais tempo e foco no que realmente é de importância maior.


<!-- OPA -->

<a id="alteracao_limites"></a>
### Alteração 6

**Proposta original:**
> Sistema de filas para quando há um acumular de muitos pedidos (SEG34) e limite de Rating para utilizadores legítimos de 100 pedidos por minuto (SEG32)

**Implementação atual:**
    O código não implementa limites de requisições ou sistema de filas para gerenciar alto volume de pedidos.

**Motivação:**
1. Simplicação para mais tempo e foco no que realmente é de importância maior.


<!-- OPA -->

<a id="alteracao_auditoria"></a>
### Alteração 7

**Proposta original:**
> Registro de todas as operações para auditoria (SEG16)

**Implementação atual:**
    O sistema implementado possui apenas logs de console para debug, mas não implementa um sistema completo de auditoria com registro persistente de todas as operações.

**Motivação:**
1. Simplicação para mais tempo e foco no que realmente é de importância maior.

<!-- OPA -->

##  Alterações na Implementação dos Comandos

<a id="alteracao_comando_upload"></a>
### Comando UPLOAD 

**Proposta original:**
    Utilizador envia um ficheiro ou pasta encriptada com uma chave AES e a chave AES encriptada com a sua chave pública.

**Implementação atual:**
    A implementação seguiu a proposta inicial.

**Motivação:**
1. Esta abordagem garante que o servidor não tem acesso ao conteúdo dos ficheiros.
2. Facilita a partilha de acessos, dado que, para conceder acesso a outro utilizador, basta o proprietário do ficheiro encriptar novamente a chave AES com a chave pública do utilizador em questão.

<!-- OPA -->

<a id="alteracao_comando_share"></a>
### Comando SHARE 

**Proposta original:**

- O utilizador solicita à API a chave utilizada para encriptar o ficheiro ou pasta que pretende partilhar.

- Esta chave é recebida encriptada com a sua própria chave pública, sendo então desencriptada com a respetiva chave privada.

- Em seguida, encripta novamente a chave, desta vez com a chave pública do utilizador com quem pretende partilhar o conteúdo, garantindo que apenas esse utilizador consegue desencriptá-la.

- SAs permissões concedidas são guardadas num ficheiro JSON, o que permite associar um ficheiro ou pasta a um determinado utilizador com permissões específicas.

**Implementação atual:**
    A implementação seguiu, na generalidade, a proposta inicial, com uma exceção.
    Estava previsto que a base de dados guardasse apenas um ficheiro ou pasta original, associando a este múltiplas chaves de acesso conforme as permissões fossem atribuídas. No entanto, o que foi implementado foi a criação de uma cópia do ficheiro (idêntica à original, por estar encriptada com a mesma chave) para cada utilizador a quem foi concedido o acesso.

**Motivação:**
1. A utilização da chave AES, em conjunto com o ficheiro JSON, permite garantir todos os requisitos especificados: a chave garante que apenas os utilizadores autorizados têm acesso ao conteúdo, e o ficheiro JSON permite ao servidor verificar se um determinado utilizador possui permissões para executar determinadas operações.
2. Relativamente à alteração introduzida (criação de uma instância de ficheiro por utilizador com acesso), esta foi adotada desde o início do desenvolvimento. De forma a evitar uma reestruturação significativa na articulação do comando SHARE com os restantes, a decisão foi mantida. Importa ainda referir que esta alteração não compromete a funcionalidade pretendida.

<!-- OPA -->

<a id="alteracao_comando_read"></a>
### Comando READ  

**Proposta original:**
    O utilizador recebe o ficheiro encriptado com a chave AES, bem como a chave AES encriptada com a sua chave pública. Após desencriptar a chave, utiliza-a para desencriptar o ficheiro. No final, o ficheiro desencriptado é guardado localmente.

**Implementação atual:**
    A implementação corresponde à proposta original. 

**Motivação:**
1. Os ficheiros, além de circularem encriptados, são também armazenados no servidor de forma encriptada, garantindo que o servidor não tem acesso ao seu conteúdo.

<!-- OPA -->

<a id="alteracao_comando_append"></a>
### Comando APPEND 

**Proposta original:**
    O utilizador recebe a chave AES (encriptada com a sua chave pública) utilizada para encriptar o ficheiro ou pasta que pretende modificar. Após desencriptar esta chave, utiliza-a para encriptar uma nova versão do ficheiro/pasta, que contém a informação adicional.
    No caso de um ficheiro, o conteúdo de outro ficheiro com a mesma extensão é adicionado no final. O ficheiro é então re-encriptado com a mesma chave e guardado na base de dados com o mesmo nome.
    Se for uma pasta, é adicionado um novo ficheiro ou subpasta.

**Implementação atual:**
    A implementação seguiu a proposta inicial. No entanto, como existem múltiplas instâncias de cada ficheiro/pasta na base de dados (uma por utilizador com acesso), todas as instâncias têm de ser atualizadas.

**Motivação:**
1. Garante-se assim que os utilizadores com acesso anterior continuam a ter acesso ao ficheiro/pasta, uma vez que a mesma chave AES é utilizada.

<!-- OPA -->

<a id="alteracao_comando_write"></a>
### Comando WRITE 

**Proposta original:**
    O utilizador recebe a chave AES (encriptada com a sua chave pública) utilizada para encriptar o ficheiro ou pasta que pretende reescrever. Após desencriptar esta chave, utiliza-a para encriptar uma nova versão do ficheiro/pasta, que é posteriormente guardada na base de dados com o mesmo nome do original.

**Implementação atual:**
    A implementação seguiu a proposta original. No entanto, tal como no comando APPEND, todas as instâncias do ficheiro/pasta têm de ser atualizadas.

**Motivação:**
1. Esta abordagem permite manter o acesso dos utilizadores previamente autorizados, dado que a chave AES permanece inalterada.

<!-- OPA -->

## Considerações Adicionais

Apesar de várias funcionalidades secundárias não terem sido implementadas — como verificação de email, autenticação multifator ou mecanismos de limitação de pedidos —, o projeto manteve o foco naquilo que é fundamental: a confidencialidade, a integridade e a partilha segura de ficheiros.

As decisões de simplificação foram sempre tomadas de forma consciente, privilegiando uma arquitetura funcional, modular e facilmente extensível. Em muitos casos, os componentes não implementados podem ser adicionados futuramente com impacto mínimo no núcleo do sistema.

## Conclusão

Este relatório apresentou uma análise comparativa entre a proposta inicial e a implementação efetiva do sistema. Foram identificadas e justificadas as principais alterações, tendo sempre em vista a eficácia, segurança e simplicidade do desenvolvimento.

Embora nem todos os requisitos da proposta original tenham sido implementados, os mecanismos essenciais de segurança e partilha foram concretizados com sucesso. A solução garante que os dados dos utilizadores permanecem privados e controlados, mesmo quando partilhados, tirando partido de criptografia assimétrica e simétrica de forma eficaz.

O resultado final é um sistema robusto e seguro, com uma base sólida para futuras extensões, incluindo auditoria, controlo de tentativas de acesso e autenticação multifator.
