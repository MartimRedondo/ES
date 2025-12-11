## O challenge 35 traz a seguinte pergunta:

### O que acontece se usarmos um g malacioso que:

  - seja igual a 1:
      1. Qualquer expoente que Alice/Bob escolham resulta em 1;
      2. Logo, a chave compartilhada será sempre igual.
         
  - seja igual a p:
      1. 37^x mod 37 = 0;
      2. A chave resultante é sempre 0.
         
  - seja igual a p-1:
      1. (36^𝑥 mod37) será 1 se 𝑥 for par, ou 36 se 𝑥 for ímpar;
      2. Logo a chave compartilhada é facilmente previsível pelo invasor.
