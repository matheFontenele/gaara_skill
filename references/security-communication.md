<!-- gaara-module
id: security-communication
version: 1.2
requires: [finding-schema, severity-matrix]
scripts: []
-->

# Comunicação de Segurança em Linguagem Clara

> Padrão de resposta para quem é responsável por um projeto ou servidor, mas não trabalha diariamente com segurança. A meta é facilitar uma decisão segura — não simplificar a ponto de perder precisão.

---

## 1. Princípio

Explique primeiro **o que isso significa para o sistema e qual decisão é necessária**. Depois ofereça evidência e detalhe técnico. Não presuma familiaridade com CVE, CVSS, lockfile, KEV, EPSS, SAST, IoC ou nomes de ferramentas.

Tom: respeitoso, direto, sem alarmismo e sem tratar a pessoa como incapaz. Use frases curtas e explique cada termo técnico na primeira ocorrência.

---

## 2. Ordem padrão da resposta

Adapte o tamanho ao pedido, mas preserve esta ordem:

1. **Resumo:** o que foi observado e se exige atenção agora.
2. **Significado prático:** o que poderia acontecer, em linguagem comum, sem afirmar que aconteceu.
3. **O que sabemos / o que falta confirmar:** separe evidência local, impacto possível e fatos desconhecidos.
4. **Próximo passo seguro:** uma ação concreta, preferencialmente de leitura, e o que ela vai confirmar.
5. **Detalhes técnicos:** fontes, CVE/CVSS, caminhos, linhas e comandos — depois do resumo ou sob um subtítulo.

Para achados múltiplos, mostre primeiro até três prioridades; diga quantos itens adicionais existem e disponibilize a lista completa sem omitir achados relevantes.

---

## 3. Tradução de termos frequentes

| Termo técnico | Explique assim |
|---|---|
| CVE | identificador público de uma falha de segurança |
| Dependência | biblioteca ou pacote de terceiros usado pelo projeto |
| Lockfile | arquivo que registra as versões específicas instaladas pelo gerenciador |
| CVSS / severidade | estimativa da gravidade técnica da falha, não a confirmação de risco para este sistema |
| Prioridade | o que vale investigar ou corrigir primeiro neste ambiente |
| KEV | catálogo da CISA de falhas para as quais há exploração confirmada em algum contexto; não prova ataque contra este sistema |
| EPSS | estimativa de probabilidade de exploração; não prova que o sistema é afetado nem que foi atacado |
| SAST / análise estática | busca por padrões suspeitos no código sem executar a aplicação |
| IoC | sinal que pode ajudar a procurar atividade suspeita, não prova isolada de invasão |
| “Vulnerável” | versão/faixa relacionada a uma falha; a exposição prática ainda depende do uso, configuração e ambiente |
| Porta de rede | canal numerado usado por um serviço para receber conexões; a porta não identifica sozinha qual aplicativo está por trás |
| “Escuta em `0.0.0.0`” | o serviço aceita conexões por todas as interfaces de rede do host, não apenas pela própria máquina; isso não prova que a internet consiga alcançá-lo |
| Regra pública no firewall | o firewall consultado permite conexões daquela origem/porta; pode haver outra barreira de rede antes do host |
| Servidor de desenvolvimento | serviço usado para construir/testar uma aplicação; não deve ser considerado pronto para exposição pública sem validação |
| Vite / Node.js | Vite é uma ferramenta comum de desenvolvimento web; Node.js é o programa que pode executá-la. Porta 5173 sugere Vite, mas não confirma a identidade do serviço |
| Túnel SSH | conexão criptografada que encaminha uma porta local até um servidor; pode dar acesso privado sem abrir o serviço para toda a internet |
| SQL | linguagem usada pela aplicação para pedir ao banco de dados que consulte ou altere informações |
| Injeção SQL | quando texto recebido pela aplicação acaba sendo interpretado pelo banco como parte do comando, em vez de apenas como dado |
| Consulta preparada / parametrizada | forma de enviar comando e valores separadamente, para que o banco trate a entrada como dado |
| Advisory | aviso publicado por um fornecedor ou base de segurança sobre uma falha conhecida |
| Token | credencial secreta que pode permitir acesso a um serviço ou API; não revele o valor no relatório |
| `composer.lock` | arquivo PHP que registra as versões exatas das bibliotecas escolhidas para o projeto |
| `^1.36` no Composer | restrição de versão: permite versões compatíveis dentro da série 1.x; não significa que qualquer versão corrigida possa ser usada |
| Runtime | versão do programa que está realmente rodando no servidor, que pode ser diferente da registrada no projeto |
| Método como `Carbon::setLocale` | função específica de uma biblioteca; explique em palavras o que ela faz e só então mostre o nome do método |

Evite siglas em títulos. Se a sigla for necessária, escreva o significado na primeira menção.

**Não empilhe jargão.** Dê primeiro a consequência em linguagem comum; deixe termos como bind, interface, proxy, HMR, source map e socket para uma seção técnica, e só inclua os que ajudam a decidir. Não liste capacidades hipotéticas de uma ferramenta como se estivessem presentes: explique que dependem da configuração e proponha uma verificação para confirmá-las.

Para fatos externos (CVE/advisory, versão corrigida, suporte ou severidade), cite link direto para a fonte e data de consulta. Um ID como `CVE-...` ou `GHSA-...` sozinho não é citação suficiente. Se não verificou a fonte, diga isso e não apresente a afirmação como confirmada.

---

## 4. Distinguir evidência, hipótese e conclusão

Use formulações explícitas:

- **Confirmado nos arquivos analisados:** a dependência/versão/linha foi encontrada.
- **Possível impacto:** o que pode ocorrer se a condição descrita for verdadeira.
- **Ainda não confirmado:** uso do recurso vulnerável, exposição pública, segredo real, conta ativa, versão em produção ou exploração.
- **Não observado:** algo que a ferramenta procurou e não encontrou no escopo declarado.
- **Não avaliado:** algo que a ferramenta não verificou.

Não converta:

- “valor parece segredo” em “segredo vazou”;
- “CVE associado à versão” em “aplicação explorável”;
- “nenhum alerta no log analisado” em “não houve ataque”;
- “achado ausente no segundo relatório” em “corrigido em produção”;
- “exit code 3” em “a ferramenta falhou” — explique que, nesta skill, normalmente indica achado alto/crítico.

---

## 5. Nível de ação em vez de rótulo isolado

Se usar crítico/alto/médio/baixo, traduza o que isso implica:

| Nível de ação | Explicação ao usuário |
|---|---|
| Agir agora | há evidência suficientemente forte e impacto potencial alto; contenha ou escale conforme o runbook, sem apagar evidência |
| Investigar em seguida | há um risco relevante, mas falta confirmar exposição ou uso; faça a verificação indicada antes de alterar |
| Planejar correção | risco identificado sem sinal de urgência imediata; teste a mudança e combine janela/responsável |
| Acompanhar | sinal de menor impacto ou condição restrita; registre o motivo e reavalie se o contexto mudar |

Não invente prazo de SLA. Se não houver política ou contexto, proponha uma ordem relativa (“antes dos itens médios”), não uma data arbitrária.

---

## 6. Recomendações para não especialistas

- Dê **um próximo passo principal**, com objetivo e resultado esperado.
- Identifique se o comando é somente leitura, usa rede, grava relatório ou altera serviço.
- Não ofereça uma atualização de dependência como se fosse sem risco. Explique compatibilidade, teste e rollback; espere autorização antes de executar.
- Para segredo suspeito, primeiro confirmar sem revelar valor; rotacionar apenas após avaliar se é real e quais serviços dependem dele.
- Para produção, não confunda o repositório local com o que está implantado. Diga o que falta comparar.
- Se a pessoa precisar envolver outro time, diga qual especialidade/função e qual pergunta levar — sem transferir toda a análise.

---

## 7. Exemplo: transformar um achado em explicação útil

### Dados do formulário concatenados a uma consulta

> **Em termos simples:** o programa pega o texto digitado no formulário e o encaixa diretamente nas instruções que envia ao banco de dados. Um apóstrofo em um nome como “D'Ávila” pode quebrar o cadastro. Uma entrada maliciosa também poderia ser interpretada como parte das instruções — isso é chamado de injeção SQL.
>
> **O que confirmei:** o código monta a instrução dessa forma. Não tentei explorar a falha; portanto, não há evidência de que alguém tenha alterado ou consultado dados.
>
> **Próximo passo seguro:** alterar o código para enviar os valores do formulário separadamente do comando (consulta parametrizada) e revisar operações parecidas. Isso exige teste, pois pode haver outros erros no cadastro.
>
> **Detalhe técnico:** `Cliente.php:54–61`; valores concatenados no `INSERT` sem parâmetros. Exploração não testada.

### Possível token no código

> **Em termos simples:** encontrei um texto que pode ser uma chave de acesso a um serviço. O valor foi ocultado e não foi testado; ainda não sabemos se é real ou válido.
>
> **Próximo passo seguro:** confirmar com o responsável pelo serviço, sem publicar nem enviar o valor. Se estiver ativo, planejar a troca e atualizar onde a aplicação o utiliza.
>
> **Detalhe técnico:** arquivo e linha podem ser citados; nunca reproduza o token.

### Dependência e aviso externo

> **Em termos simples:** o arquivo que fixa as bibliotecas do projeto registra {biblioteca} na versão {versão}. O fornecedor publicou um aviso sobre uma falha que pode afetar essa versão; isso não prova que o caminho vulnerável seja usado ou que a falha tenha sido explorada.
>
> **O que falta confirmar:** se a aplicação chama o recurso afetado e se a mesma versão está rodando em produção. A versão corrigida precisa respeitar a faixa permitida pelo gerenciador de pacotes; não recomende um downgrade nem uma atualização incompatível.
>
> **Fonte:** [{fornecedor/advisory}]({URL direta}) — consultado em {data}.
>
> **Detalhe técnico:** {CVE/GHSA}, {arquivo:linha ou pacote@versão}, faixa afetada/corrigida e condição de alcance.

### Porta de desenvolvimento exposta

> **Em termos simples:** uma porta de rede é um canal de entrada para um serviço. Neste host, um programa está aceitando conexões pela porta 5173, e a regra de firewall consultada permite esse tráfego. Isso aumenta a superfície de acesso, mas ainda não prova que alguém de fora consiga alcançá-lo.
>
> **Por que merece atenção:** a porta 5173 é comum em servidores de desenvolvimento web, que servem para testar o site e não devem ser presumidos seguros para uso público. Se for esse o caso, dependendo da configuração, o serviço pode revelar partes do funcionamento interno do site ou disponibilizar recursos de desenvolvimento. Ainda não confirmei qual aplicação é, o que ela entrega nem se a conexão externa funciona.
>
> **Próximo passo seguro:** identificar o processo e confirmar com o responsável se ele precisa receber conexões externas. Se não precisar, planejar restringi-lo à própria máquina/rede privada ou remover a regra pública. Não pare o processo nem altere o firewall antes de confirmar o impacto e aprovar a mudança.
>
> **Detalhe técnico (opcional):** `0.0.0.0:5173` indica escuta em todas as interfaces IPv4; o número 5173 é comum no Vite, mas não identifica o serviço por si só. A alcançabilidade pela internet depende também do firewall/rede externa.

O exemplo deve ser adaptado à evidência: não diga que uma regra é pública se só leu a configuração local; não afirme acesso externo sem uma verificação autorizada; não atribua a porta ao Vite sem identificar o processo.

### Técnico demais

> `GHSA-...`, CVSS 8.9, pacote X versão Y. Atualize para Z. KEV ausente.

### Claro e fiel à evidência

> **O que encontrei:** o projeto fixa uma versão do pacote X que aparece em um aviso de segurança do fornecedor. Isso confirma a versão no arquivo de dependências, mas ainda não confirma que a função afetada é usada nem que essa mesma versão está em produção.
>
> **Por que importa:** em determinadas condições, a falha pode permitir {impacto descrito pela fonte}. Não encontrei evidência de exploração nos dados analisados; isso não descarta atividade fora desse escopo.
>
> **Próximo passo seguro:** confirmar se a aplicação usa essa função e comparar o lockfile com o deploy. Depois disso, planejar a atualização compatível com teste e rollback.
>
> **Detalhe técnico:** {CVE/GHSA, faixa afetada, versão corrigida, CVSS, fonte e data}.

---

## 8. Checklist antes de enviar

- [ ] A primeira parte responde “o que isso significa para mim?”
- [ ] Fato observado, impacto possível e hipótese estão separados?
- [ ] Siglas foram explicadas ou movidas para detalhes técnicos?
- [ ] Termos de banco, dependências e credenciais foram traduzidos sem remover os identificadores úteis?
- [ ] Fatos externos incluem URL direta e data de consulta?
- [ ] A severidade não foi confundida com exploração confirmada?
- [ ] O próximo passo é específico e seguro para quem pode não ser especialista?
- [ ] Ficou claro o que não foi verificado?
- [ ] Não foram expostos segredos, hashes de senha ou dados pessoais desnecessários?
