INSTRUÇÕES PARA RODAR O CÓDIGO DEPOIS DE DAR GIT CLONE AO REPOSITÓRIO:

Para cbc_mac.py:
- python3 cbc_mac.py tag key hm  
- python3 cbc_mac.py check key hm tag

Para o cbc_mac_attack.py:
- python3 cbc_mac_attack.py

Para cbc_mac_rnd.py:
- python3 cbc_mac_rnd.py tag key hm  
- python3 cbc_mac_rnd.py check key hm tag


-------------------------------------------------//----------------------------------------------------------------------

## PERGUNTA:

Show how to attack the `cbc_mac_rnd` construction


## RESPOSTA:

1. Obtenção de um Tag Válido
  - Vamos conseguir obter um tag válido (IV₁, T₁) para uma mensagem M₁ .
  - Este tag foi gerado corretamente usando a chave secreta K (que estará num ficheiro).

2. Preparação para Falsificação
  - Com uma nova mensagem M₂ vamos autenticá-la de forma fraudulenta, mas como?
  - Para simplificar a explicação vamos considerar mensagens de um único bloco.

3. Cálculo da Mensagem Fraudulenta
  - Para uma mensagem de um único bloco, a falsificação funciona assim:

    -> O CBC-MAC padrão com IV zero para uma mensagem M seria:

        T = E(M ⊕ 0) onde E é a função de cifragem com a chave K
    
    -> O CBC-MAC com IV aleatório para uma mensagem M seria:

        T = E(M ⊕ IV)
    
  - Para forjar uma mensagem M₂' que produza o tag T₁ com o IV₁:
    
    -> Queremos: `E(M₂' ⊕ IV₁) = T₁`
    
    -> Sabemos que: `E(M₁ ⊕ IV₁) = T₁`
    
    -> LOGO: `M₂' ⊕ IV₁ = M₁ ⊕ IV₁`
    
    -> Ou seja: `M₂' = M₁`


Para mensagens de múltiplos blocos, o ataque é mais complexo mas segue o mesmo princípio
