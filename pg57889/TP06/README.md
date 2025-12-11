## Resolução do TP06

Ao fazer a alínea do IND-CPA, acabei por usar um "cifra determinística" (XOR + NONCE) e verificou-se que sim o adversário tem 50%, em média, de chances de "ganhar" e uma pequena vantagem (quase 0).

Na alínea referente ao ataque IND-CPA, bastaria reutilizar o código do IND-CPA e remover o NONCE da função de encriptação para tornar a cifra completamente determinística.
Nessa situação, o adversário teria 100% de sucesso e uma vantagem de 1, pois conseguiria identificar diretamente qual mensagem foi cifrada, visto não haver nenhum elemento de aleatoriedade.

Este resultado evidencia a insegurança da cifra sem NONCE, demonstrando um ataque IND-CPA bem-sucedido.
