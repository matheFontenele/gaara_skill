<!-- gaara-module
id: security-communication
version: 1.0
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

Evite siglas em títulos. Se a sigla for necessária, escreva o significado na primeira menção.

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
- [ ] A severidade não foi confundida com exploração confirmada?
- [ ] O próximo passo é específico e seguro para quem pode não ser especialista?
- [ ] Ficou claro o que não foi verificado?
- [ ] Não foram expostos segredos, hashes de senha ou dados pessoais desnecessários?
