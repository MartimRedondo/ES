# Secure Vault (2ª fase)

Este projecto consiste na 2ª fase da implementação do "Cofre Digital". Se na [primeira fase](cofre.md) do projecto, a ênfase foi colocado no "levantamento de requisitos"; "análise de risco"; "desenho da solução" e "prototipagem inicial", nesta segunda fase pretende-se colocar o foco em:
 - **Implementação integral da solução** - que consistirá por uma *WebAPI* responsável pela funcionalidade do sistema (o que anteriormente se designava por *servidor*), uma aplicação cliente que interage com essa API;
 - **Documentação** - tanto da API e applicação cliente desenvolvida, como do próprio código;
 - **Levantamento e análise de dependências (Software Bill of Materials)**

O prazo de entrega do projecto é ~~**9/5/2025 (23:59)**~~ **11/5/2025 (23:59)**

## Implementação

Ao nível da implementação, deve-se atender aos requisitos identificados na fase anterior, assim como no desenho da solução aí apresentado. Note no entanto que durante a concretização do projecto pode surgir a necessidade de refinar algum desses aspectos, decorrentes das opções de implementação entretanto tomadas -- nesse caso, os documentos anteriormente produzidos devem ser devidamente ajustados, detalhando o que foi alterado e respectiva justificação.

Sugere-se a adopção da linguagem *Python* para a implementação da solução. Destacam-se ainda alguns aspectos de devem ser tidos em conta no desenvolvimento da solução, nomeadamente:
 - especial atenção à validação de *input*, assim como na adopção de boas práticas de programação segura;
 - adoptar preferencialmente formatos baseados em *JSON* e *JWT*;
 - os mecanismos de autenticação e autorização devem ser suportados por protocolos standard, como o *OAuth 2.0* ou *OIDC*;
 - para a aplicação cliente, que irá interagir com a *WebAPI*, sugere-se manter uma *interface* minimal de linha de comando.

**Ferramentas:** 

Tal como na primeira fase do projecto, recomendam-se algumas ferramentas que poderão auxiliar na realização das tarefas pedidas. Nomeadamente:
 - [FastAPI](https://fastapi.tiangolo.com) - como *framework* adoptado para a realização da *WebAPI*. Este *framework* encontra-se muito bem documentado, dispondo de numerosos exemplos que deverão auxiliar no desenvolvimento do projecto. Para além disso, o *framework* disponibiliza um suporte muito interessante ao nível da geração de documentação, assim como na validação de dados (recorrendo ao *package* `Pydantic` mencionado abaixo).
 - [Typer](https://typer.tiangolo.com) - para o cliente (linha de comando). Trata-se de um *package* do mesmo autor do `FastAPI` (e que partilha parte do *codebase*), pelo que é a opção óbvia em termos de consistencia do projecto. 
 - [CycloneDX (python)](https://github.com/CycloneDX/cyclonedx-python) - SBOMs for python.

**Bibliotecas:** 

Para além das ferramentas mencionados, as bibliotecas abaixo enumeradas podem ser úteis:
 - [Pydantic](https://docs.pydantic.dev/latest/) - biblioteca de validação de dados (incorporada no *framework* FastAPI).
 - [PyJWT](https://pyjwt.readthedocs.io/en/stable/) - JSON Web Tokens.
 - [joserfc](https://github.com/authlib/joserfc) - uma implementação do *Javascript Object Signing and Encryption (JOSE)*.
 - [httpx](https://www.python-httpx.org) - suporte a pedidos `http` assíncronos.


## Recursos adicionais:
 - https://escape.tech/blog/how-to-secure-fastapi-api/
 - https://curity.io/resources/learn/jwt-best-practices/
 - https://www.youtube.com/watch?v=6hTRw_HK3Ts
 - https://www.youtube.com/watch?v=PfvSD6MmEmQ
 - https://www.linkedin.com/pulse/creating-authentication-system-fastapi-using-openid-oidc-parasuraman-7ezgc
 - https://www.scottbrady.io/oauth/why-the-resource-owner-password-credentials-grant-type-is-not-authentication-nor-suitable-for-modern-applications
