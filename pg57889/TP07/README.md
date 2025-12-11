# Resolução do TP07

Ainda não está completamente feito. Requisitos:

 * Ajustar o conteúdo dos certificados de forma apropriada; (DONE)
 * Imprimir informação sobre os algoritmos criptográficos utilizados (*cipher-suite* adoptada) (NOT DONE)
 * Ajustar o código para funcionalidade de *Chat* (permitir diálogo entre Cliente/Servidor) (DONE)
 * Forçar a adopção da versão 1.3 do protocolo TLS; (DONE)
 * [EXTRA] Implementar modo de **autenticação mútua** (NOT DONE)
 * [EXTRA] Considerar que a CA `EC` serve como critério para ligação dos clientes (+/-)

Para gerar os certificados e as chaves usamos os seguintes comandos no terminal:

## Gera o certificado CA

`openssl req -new -x509 -days 365 -nodes -out ca.crt -keyout ca.key -subj "/C=BR/ST=Rio de Janeiro/L=Niteroi/O=UFF/OU=Midiacom/CN=MyCA"` 

## Problemas:

Apesar de se gerar a ca.key, ainda não se usa no código, contudo, na versão final, irá se usar.

## Gera uma chave privada e um CSR para o Server

`openssl req -new -nodes -out server.csr -keyout server.key -subj "/C=BR/ST=Rio de Janeiro/L=Niteroi/O=UFF/OU=Midiacom/CN=127.0.0.1"`

## Problemas:

O CSR ainda não está a ser usado, nem sei como poderá ser aplicado, mas irei explorar mais o problema e tentar ver se será útil e o porquê e onde poderá ser útil.

## Assina o certificado do server com o CA

`openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365`

## Problemas:

Como se pode ver, ainda há coisas a melhorar e outras a serem implementadas, na versão final, espera-se ter todos os problemas resolvidos e todas as dúvidas retiradas.
