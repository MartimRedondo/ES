## Breve explicação:

Irá se explicar a estrutura da pasta e, por sua vez, como foi feito o levantamento de requisitos.

## Explicação da estrutura:

  * Pasta **public** diz respeito à pasta gerada depois de correr:
    
      `doorstop publish all ./public`
    
    onde o objetivo é gerar o HTML que conterá a organização dos requisitos feitos em doorstop, esta pasta não é fundamental, visto que pode ser substituída pelo comando:
    
      `doorstop-server`
    
    mas decidiu-se deixar para haver mais de uma forma de testar o levantamento de requisitos com doorstop
  *






**Nota**: 
> Por algum motivo não se consegue acrescentar os ficheiro .doorstop.yml tanto à pasta **requisitos/funcionais** como à pasta **requisitos/segurança**, apesar de ser um ficheiro simples, sem eles é impossível testar o levantamento de requisitos feitos em doorstop, por esse motivo deixamos 2 alternativas:
>
> 1 -> depois do git clone a própria pessoa irá criar os ficheiros e colocar o código (estará aqui)
> 
> 2 -> em vez de usar o doorstop para ver o levantamento de requisitos, poderá usar o req.md que contem o mesmo conteúdo.

**.doorstop.yml** (para a pasta **requisitos/funcionais**:

```py
settings:
  digits: 3
  itemformat: yaml
  prefix: FUNC
  sep: ''
```

**.doorstop.yml** (para a pasta **requisitos/segurança**:

```py
settings:
  digits: 3
  itemformat: yaml
  parent: FUNC
  prefix: SEG
  sep: ''
```
