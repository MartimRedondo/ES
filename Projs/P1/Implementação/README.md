# Implementação

Numa primeira circunstância fizemos um documento a explicar a nossa solução ideal e o objetivo nesta fase é implementar um protótipo, neste ficheiro irá ser descrita a solução e, possivelmente, algumsa mudanças que foram tomadas.

## Explicação do que está feito

No protótipo apresentado temos que ter noção que os nossos clientes e servidor são pastas que têm a seguinte organização:

- DB/
  - User1/
    - OWNER/
      - FILES/
        - file1.txt.encrypted
        - ...
      - KEYS/
        - file1.txt.key.encrypted
    - SHARED_WITH/
      - USER2/
        - file2.txt.encrypted
        - (outros ficheiros partilhados do USER2)
      - (outros USERS podem partilhar)
    - permissions.json
  - (Outros USERS com a mesma estrutura de ficheiros;
     FILES e KEYS podem estar vazias se não houver uploads)
    
---

- DB_USER/
  - USER1/
    - encrypted/
      - (ficheiros temporários)
    - keys/
      - chave_privada.pem
      - chave_publica.pem
    - file1.txt
  - USER2/
    - encrypted/
      - (ficheiros temporários)
    - keys/
      - chave_privada.pem
      - chave_publica.pem
    - file2.txt

DB diz respeito ao Server e DB_USER ao inúmero utilizadores.
O que acontece é que o USER precisa de ter aquela exata estrutura, caso se queira logar ao servidor, a conexão ao servidor começa sempre como um registo (se ele ainda não estiver registado) onde terá que dar os dados e terá que passar por uma validação tanto no módulo cliente como no módulo servidor. Caso o registo seja efetuado, este poderá logar-se à sua conta dando os dados, no nosso protótipo, isto não está implementado da forma ideal, pois ele tem que se logar 2 vezes para conseguir se efetivamente logar (numa primeira instância, gera-se um nonce para se ter uma ligação segura onde não há outra pessoa a apoderar-se da sessão e depois numa segunda instância, com ajuda do nonce, efetua-se efetivamente o lognin). 

Já dentro do próprio **Cofre Digital** o user pode fazer algums decisões, como ver os ficheiros que estão no servidor e que são dele, pode fazer upload de ficheiros para o servidor. Dentro do menu do ficheiro, pode atribuir permissões, ver quem tem acesso àquele ficheiro e ler (todas as outras funcionalidades não estão implementadas), ele ainda pode aceder a ficheiros que outros utilizadores lhe partilharam.

## Segurança

Apesar de não se ter implementado tudo, houve bastante atenção á segunraça, primeiramente a conexão usa TLS1.3 + HMAC em **TODAS** as mensagens entre user-server.

No registo há a verificação do formato do email, da força da password, da unicidade do email e o uso de argon2 para guardar a password de forma segura.

No login há a criação de um nonce para não ser possível apoderar-se da sessão do user e há a verificação da password.

Para os ficheiros, decidiu-se usar como proposto AES-256-GCM para a chave que encripta o ficheiro e, ao contrário, da solução usou-se um par de chaves RSA únicas para cada **User** onde a chave AES-256-GCM seria encriptada, esta chave encriptada é enviada ao servidor em conjunto com o ficheiro encriptado. Quando se quer atribuir permissões, a mensagem é enviada para o servidor, o servidor coloca essa informação num .json (existe 1 por user registado no server) e depois envia-se a chave encriptada do ficheiro que se quer dar permissão para o cliente, o cliente decripta essa chave com a sua chave privada e depois? A nossa decisão foi, todos os clientes após um registo bem sucedido criam um par de chaves púlicos e enviam a chave pública para o server e assim, o owner consegue cifrar essa chave com a chave pública do user que terá acesso ao ficheiro, a nova chave então é passada para o servidor e irá para a pasta SHARED_WITH em conjunto com o ficheiro encriptado.

Caso o user queira ter acesso ao ficheiro, pede a chave e o ficheiro que estão no SHARED_WITH, decrita a chave com a sua chave privada e, depois, decripta o ficheiro com a chave que conseguiu na decriptação.
