* Funcional 1: Registo de utilizadores através dos dados como email, nome e palavra-passe.
    - **SEG1**: Implementar validação de formato de email (regex) com verificação de unicidade.
    - **SEG2**: Implementar validador de senha que exige que no mínimo haja 8 caracteres, 1 maiúscula, 1 minúscula, 1 número e 1 símbolo.
    - **SEG3**: Armazenar palavras-passe usando hashing com salt.
    - **SEG4**: Implementar mecanismo de verificação de email com token único e com data de expiração (24 horas).
    - **SEG5**: Implementar sanitização de inputs, ou seja, evitar que os dados tenham características de metadados.

* Funcional 2: Identificador único atribuido a cada utilizador aquando do registo.
    - **SEG6**: Utilizar algoritmos comprovados (UUID v4 ou ULID) para gerar identificadores únicos.
    - **SEG7**: Garantir que o identificador único não possa ser alterado,falsificado ou acedido de forma indevida.

* Funcional 3: Autenticação do utilizador usando os dados fornecidos no registo.
    - **SEG8**: Implementar autenticação multifator ou métodos equivalentes.
    - **SEG9**: Garantir políticas de bloqueio de conta após três tentativas falhas.
    - **SEG10**: Garantir uma gestão segura de sessões com tokens de sessão gerados de forma aleatória e expiração automática após 5 min.
    - **SEG11**: Configurar TLS 1.3 em todos os endpoints de autenticação.
    - **SEG12**: Implementar rate limiting de 10 tentativas por minuto por IP.

* Funcional 4: Gestão do Cofre Digital, o utilizador consegue gerir as pastas e ficheiros do seu cofre.
    - **SEG13**: Garantir o isolamento dos cofres, de forma que cada utilizador só possa aceder ao seu próprio cofre, excepto quando há autorização de poder ser partilhado.
    - **SEG14**: Proteger metadados sensíveis (data de criação, histórico de acessos,...) com registos de acesso e auditoria.

* Funcional 5: Gestão de Ficheiros e Pastas, onde os utilizadores podem criar, modificar e remover ficheiros ou pastas no seu cofre.
    - **SEG15**: Garantir que apenas o proprietário ou utilizadores autorizados possam modificar ou remover ficheiros e pastas, através de políticas de controlo de acesso e autenticação.
    - **SEG16**: Implementar um mecanismo de registo (logging) de todas as operações realizadas nos ficheiros e pastas, para que seja possível auditar e monitorizar o acesso e as alterações realizadas.
    - **SEG17**: Garantir que há proteção contra remoções acidentais, com a criação de um mecanismo de "LIXO", onde os ficheiros eliminados possam ser recuperados por 30 dias.

* Funcional 6: Organização Hierárquica, onde os utilizadores organizam ficheiros e pastas hierarquicamente, dentro do seu cofre.
    - **SEG18**: Implementar verificação de permissões em cascata na hierarquia de pastas.
    - **SEG19**: Implementar verificações de consistência a cada operação de modificação hierarquica.

* Funcional 7: Partilha de Recursos entre utilizadores.
    - **SEG20**: Implementar read, append, write com verificação em tempo real.
    - **SEG21**: Garantir que as alterações de acesso não fazem com que haja a escalada indevida de privilégios.
    - **SEG22**: Implementar logs de auditoria para todas as alterações de permissões.
 
* Funcional 8: Comunicação Cliente-Servidor (CLI-SRV).
    - **SEG23**: Garantir que toda a comunicação entre cliente e servidor seja encriptad(TLS).
    - **SEG24**: Garantir a integridade e autenticidade das mensagens com uso de HMAC.
    - **SEG25**: Garantir a validação de certificados, ou seja, verificar se um certificado digital é autêntico, válido e confiável.
    - **SEG26**: Garantir que há o renovar e o expirar de sessões de forma adequada.

* Funcional 9: Rastreabilidade e Auditoria .
    - **SEG27**: Garantir que os logs sejam armazenados de forma segura e sejam à prova de alterações não autorizadas.
    - **SEG28**: Implementar sistema de acesso restrito aos logs baseado em hierarquia.

* Funcional 10: Assegurar que o servidor não conhece as mensagens
    - **SEG29**: Implementar um método de encriptação para todos os ficheiros (AES-256-GCM).
    - **SEG30**: Configurar KDF baseada na senha do utilizador.
    - **SEG31**: Implementar armazenamento seguro de chaves com encriptação assimétrica

* Funcional 11: O utilizador deve conseguir usar o sistema independente da situação.
    - **SEG32**: Implementar rate limiting de 100 requisições por minuto por utilizador autenticado
    - **SEG33**: Configurar detecção de padrões anómalos com limite de 200 requisições/minuto de um único IP
    - **SEG34**: Implementar sistema de filas para pedidos intensivos.
