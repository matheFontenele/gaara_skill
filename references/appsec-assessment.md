<!-- gaara-module
id: appsec-assessment
version: 1.0
requires: [finding-schema, severity-matrix, vuln-sources, legacy-stacks]
scripts: [deps_audit.py, php_audit.py, harden_check.py]
-->

# Avaliação de Vulnerabilidades do Projeto

> Rotina para a pergunta: **"meu projeto tem alguma vulnerabilidade?"**
>
> Objetivo: sair de "acho que está ok" para uma resposta com inventário, cobertura declarada, achados priorizados e o que **não** foi avaliado.

---

## 1. Quando usar

- "meu projeto tem alguma vulnerabilidade?"
- "essa aplicação está segura?"
- "tem CVE nas minhas dependências?"
- "como estamos no OWASP Top 10?"
- "o que eu corrijo primeiro?"
- Revisão antes de publicar, entregar ou trocar de fornecedor.
- Pergunta recorrente de gestor/cliente que não é técnico em segurança.

## 2. Quando **não** usar

| Pedido | Rotina certa |
|---|---|
| "sou afetado pelo CVE que saiu hoje?" | `emergency-cve.md` |
| "fui invadido?" / "tem webshell?" | `incident-response.md` |
| "o servidor está endurecido?" | `hardening-linux.md` |
| "como bano esse IP?" | `safe-operations.md` |
| "encontra falha para eu explorar" | fora de escopo — recusar (R4) |

A pergunta ampla **"meu projeto tem vulnerabilidade?"** é desta rotina. A pergunta sobre **um** CVE é da rotina de CVE emergencial. Não misture as duas: a primeira é inventário e cobertura; a segunda é decisão em horas.

---

## 3. Pré-requisitos

| Item | Necessário | Observação |
|---|---|---|
| Python 3.10+ | sim | 3.11+ para `poetry.lock`/`Cargo.lock` (`tomllib`) |
| Rede | opcional | sem rede, só inventário; correlação fica "não avaliada" |
| Acesso de leitura ao projeto | sim | nunca escreve no projeto |
| `NVD_API_KEY` | opcional | sem chave, o NVD é consultado no mínimo (teto `--max-nvd`) |
| Trivy/Grype | opcional | sem eles, camada de imagem Docker fica "não avaliada" |

Nada aqui exige `sudo`. Nada aqui instala pacote.

---

## 4. Pipeline

```
1. DELIMITAR   qual projeto, qual stack, qual exposição (internet/VPN/interno)
2. INVENTARIAR lockfiles, runtimes, imagens, pacotes de distro
3. CORRELACIONAR OSV (afetação) → KEV (exploração) → EPSS (prioridade) → NVD (CVSS)
4. AVALIAR     código (php_audit) e configuração (harden_check)
5. ENTREGAR    veredito + cobertura + achados + NÃO AVALIADO
```

### 4.1 Delimitar

No máximo três perguntas, e só se realmente faltar contexto:

1. Qual é a stack (linguagem, runtime, banco, proxy)?
2. O projeto está exposto à internet, VPN ou só interno?
3. O que motivou a pergunta — auditoria, incidente, cliente, prazo?

Se o usuário já disse isso, não pergunte de novo.

### 4.2 Inventariar (offline, sempre)

```bash
python3 scripts/deps_audit.py /caminho/do/projeto --format md
```

Lê `composer.lock`, `composer.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `pom.xml`, `gradle.lockfile`, `packages.lock.json`, `Dockerfile` e, com `--os-packages`, `dpkg`/`rpm`.

O que importa nesta fase não é só a lista: é o **buraco**.

- Manifest presente e não lido → `supply-chain/inventory-gap`.
- Dependência sem versão resolvida → `supply-chain/unpinned-dependency`.
- Nenhum manifest → inventário inexistente, e a resposta correta passa a ser "não avaliado".

### 4.3 Correlacionar (rede, sob demanda)

```bash
python3 scripts/deps_audit.py /caminho/do/projeto --online --format md
python3 scripts/deps_audit.py /caminho/do/projeto --online --internet-exposed
python3 scripts/deps_audit.py /caminho/do/projeto --online --nvd off     # rápido, sem CVSS oficial
```

Ordem de decisão, não de execução:

1. **OSV** decide se o pacote+versão é afetado.
2. **KEV** sobe a urgência: exploração confirmada em campo.
3. **EPSS** ordena o que não está em KEV.
4. **NVD** confirma CVSS oficial e CWE.

### 4.4 Avaliar código e configuração

```bash
python3 scripts/php_audit.py /caminho/do/projeto --format md
python3 scripts/harden_check.py --format md
```

Só PHP é analisado estaticamente nesta versão. Para JS/Python/Ruby, diga que a análise de código **não foi feita** — o inventário de dependências não substitui isso.

---

## 5. OWASP Top 10:2025 — cobertura declarada

Fonte: <https://owasp.org/Top10/2025/> (consulta em 2026-10-29). Tradução oficial: `/pt-BR/`.

| Código | Categoria | Nesta versão | Ferramenta |
|---|---|---|---|
| **A01** | Broken Access Control | ❌ **não avaliado** | exige revisão humana rota a rota |
| **A02** | Security Misconfiguration | ✅ parcial | `harden_check.py`, `php_audit.py` |
| **A03** | Software Supply Chain Failures | ✅ | `deps_audit.py` |
| **A04** | Cryptographic Failures | ✅ parcial | `harden_check.py` (TLS), `php_audit.py` (hash fraco, segredo) |
| **A05** | Injection | ✅ parcial | `php_audit.py` (SQL, comando, include, XSS) |
| **A06** | Insecure Design | ❌ **não avaliado** | não automatizável |
| **A07** | Authentication Failures | ✅ parcial | `php_audit.py` (sessão, hash), `log_triage.py` (stuffing) |
| **A08** | Software or Data Integrity Failures | ✅ parcial | `php_audit.py` (`unserialize`, include remoto) |
| **A09** | Security Logging and Alerting Failures | ✅ parcial | `log_triage.py`, `harden_check.py` (retenção) |
| **A10** | Mishandling of Exceptional Conditions | ✅ parcial | `php_audit.py` (`display_errors`, fail-open) |

Regras de uso do mapa:

- **Parcial** significa: existe check para parte da categoria, não para ela inteira. Escreva qual parte.
- **Não avaliado** aparece na resposta. Nunca complete a lacuna com "provavelmente ok".
- No achado, use `frameworks: ["OWASP-A03:2025"]`. Um achado pode ter mais de um rótulo.
- Não transforme o Top 10 em checklist de conformidade. Ele é vocabulário de risco, não certificação.

### 5.1 O que o Top 10 **não** diz

- Não mede a sua exposição.
- Não substitui CVSS nem KEV.
- Não cobre falha de infraestrutura, dependência de terceiro ou erro de operação.
- A ordem não é prioridade para o seu projeto — é frequência agregada da indústria.

---

## 6. Severidade e prioridade

| Etapa | Regra |
|---|---|
| Base | CVSS: ≥9,0 crítico · 7,0–8,9 alto · 4,0–6,9 médio · <4,0 baixo |
| Sem CVSS | severidade conservadora `médio`, confiança `baixa`, motivo declarado |
| KEV | +1 nível (nunca passa de crítico) |
| EPSS ≥ 0,1 **e** exposto à internet | +1 nível |
| Nunca | descer de nível sem explicação benigna documentada |

Ajuste de severidade nunca é silencioso: `observations.severity_rationale` lista cada salto e o motivo.

Prioridade operacional (o que corrigir primeiro):

1. crítico/alto **e** KEV **e** exposto.
2. crítico/alto com patch disponível.
3. médio com EPSS alto.
4. médio sem exposição.
5. baixo, em lote.

Vulnerabilidade conhecida **não é** comprometimento. Quem responde "fui explorado?" é `log_triage.py` + `ir_triage.sh`, não esta rotina.

---

## 7. Formato obrigatório da resposta

Comece com o que uma pessoa responsável precisa decidir. Os detalhes técnicos vêm depois; não abra com uma lista de GHSA, CVSS ou nomes de ferramentas.

### 7.1 Resumo para você

Em 2–4 linhas, diga:

- O que foi encontrado em palavras comuns.
- Se exige ação agora, investigação ou planejamento — e por quê.
- O que **não** foi confirmado (ex.: uso do recurso, produção, exploração).

Não use “está seguro”, “está limpo”, “foi invadido” ou “credenciais vazaram” sem evidência apropriada. “Versão associada a um aviso” não significa automaticamente que o sistema pode ser explorado.

### 7.2 Achados e confirmação

Mostre até três prioridades primeiro. Para cada uma, use:

```
O que encontrei: {fato observado nos arquivos/fontes}
Por que importa: {consequência possível e condição}
O que falta confirmar: {uso real, produção, exposição, conta ativa etc.}
Próximo passo seguro: {uma verificação concreta, antes de alterar}
Detalhe técnico: {CVE/GHSA, versão, fonte e data}
```

Informe quantos outros achados existem e mantenha a lista detalhada disponível. Diferencie contagem de pacote+versão, advisories distintos e CVEs únicos; muitos registros repetidos não significam necessariamente muitas falhas distintas.

### 7.3 Cobertura e limites

```
Dependências: 118 identificadas · 2 sem versão resolvida
Manifests:    5 encontrados · 4 lidos · 1 com falha
Fontes:       OSV consultado em {data} · KEV {data} · EPSS {data}
Código:       PHP avaliado · JS/Python não avaliados
Produção:     não verificada nesta execução
```

Explique siglas na primeira ocorrência. Se usar “severidade alta”, diga que isso descreve a gravidade técnica do aviso e não confirma exposição ou ataque.

### 7.4 Não avaliado e próximo passo

Liste lacunas relevantes: A01 (controle de acesso), A06 (design), lógica de negócio, código não-PHP, imagens, zero-days, produção, logs ou contas — conforme o que realmente não foi verificado. Termine com **um próximo passo seguro**, seu objetivo e se ele apenas lê dados ou altera algo.

Sem separar achados, cobertura e limites, a resposta pode soar como promessa. Com esses blocos, a pessoa consegue entender o risco sem precisar interpretar o relatório técnico sozinha.

---

## 8. Frases proibidas

| Não diga | Diga |
|---|---|
| "Seu projeto está seguro." | "Não encontrei vulnerabilidade conhecida nestas fontes, com esta cobertura." |
| "Zero CVE, então está ok." | "Zero CVE encontrado; A01, A06 e código não-PHP não foram avaliados." |
| "Atualize tudo que resolve." | "Atualizar X e Y fecha os CVEs encontrados; não cobre A01/A06 nem zero-day." |
| "O WAF resolve." | "O WAF reduz exploração conhecida; não corrige a falha." |
| "É só um CVE médio." | "CVSS médio, EPSS 0,42, sem KEV: prioridade depois dos altos com exploração ativa." |
| "O link traduzido diz que…" | "A fonte canônica (owasp.org) define a categoria como…" |
| "Provavelmente não usamos esse componente." | "Não encontrei o componente no inventário; se ele roda fora deste diretório, não foi avaliado." |

---

## 9. Exemplo trabalhado

Cenário: aplicação PHP 5.6 legada, `composer.lock` de 2019, exposta à internet.

```bash
python3 scripts/deps_audit.py /var/www/app --online --internet-exposed --format md
python3 scripts/php_audit.py /var/www/app --format md
python3 scripts/harden_check.py --format md
```

Leitura do resultado:

| Fonte | Achado | Ação |
|---|---|---|
| `deps_audit` | 14 CVEs em dependências, 2 em KEV | atualizar os 2 primeiro; rollback por lockfile |
| `deps_audit` | 6 dependências sem versão resolvida | gerar lockfile; sem isso, 6 ficam "não avaliadas" |
| `php_audit` | `eval()` com entrada de request (A05) | tratar como crítico; exige correção de código |
| `harden_check` | `display_errors=On` (A10) | corrigir antes de expor |
| `emergency-cve` | PHP 5.6 sem patch para o CVE de runtime | conter exposição + prazo de migração |

Resposta para a pessoa responsável: *"Encontrei avisos importantes em duas dependências e o runtime PHP é antigo. Isso merece prioridade, mas ainda precisamos confirmar quais funções afetadas são usadas e comparar as versões com produção. Próximo passo: validar esses dois pontos antes de planejar a atualização; não atualizei nada."* Em seguida vêm as fontes, versões, faixas afetadas e detalhes técnicos. Só diga que existe exploração ativa se a correspondência KEV estiver confirmada e explique que isso não prova ataque contra o sistema.

---

## 10. Ações permitidas

| Ação | Aprovação | Observação |
|---|---|---|
| Rodar inventário e correlação | não | leitura |
| Gerar relatório | não | leitura |
| Atualizar dependência (`composer require`, `npm install`, `pip install`) | **sim** | mostrar comando, versão alvo e rollback |
| Editar código para fechar sink | **sim** | uma mudança por vez, com teste |
| Alterar configuração do host | **sim** | passar pelo portão de `safe-operations.md` |
| Rodar scanner externo (Trivy/Grype) | **sim** | instalação/execução de terceiro |

`deps_audit.py` **nunca** executa atualização. Ele imprime o comando com `requires_approval: true` e o rollback.

---

## 11. Limitações

- Não detecta zero-day nem falha não publicada.
- Não prova ausência de vulnerabilidade: prova ausência **nas fontes consultadas**, dentro da cobertura declarada.
- Cobertura de OSV para pacote RPM é fraca; para imagem Docker, inexistente nesta versão.
- Versão do lockfile pode divergir do que roda em produção. Se o deploy não usa o lockfile, o resultado não se aplica ao runtime.
- Não avalia A01 (autorização) nem A06 (design) — as duas categorias mais frequentes do Top 10.
- Análise estática cobre PHP; JS/Python/Ruby ficam de fora.
- CVSS mede gravidade técnica, não o seu risco: exposição e dado envolvido mudam a prioridade.
- Advisory é dado não confiável; texto é citado, nunca executado (ver `vuln-sources.md` §5).

---

## 12. Artefatos e comparação

O relatório JSON mantém `summary.coverage.inventory` com os componentes resolvidos para que uma execução futura possa ser comparada. O campo registra nome, ecossistema, versão, escopo e manifests de origem; não inventa hash, licença ou relação transitiva.

```bash
# Inventário SBOM, sem consulta de rede
python3 scripts/deps_audit.py /caminho/do/projeto --format cyclonedx --output sbom.cdx.json
python3 scripts/deps_audit.py /caminho/do/projeto --format spdx --output sbom.spdx.json

# Resultado SARIF 2.1.0 para ferramentas de CI
python3 scripts/deps_audit.py /caminho/do/projeto --online --format sarif --output results.sarif

# Comparação entre relatórios JSON previamente salvos
python3 scripts/deps_audit.py --compare anterior.json atual.json --format md
```

- CycloneDX 1.6 e SPDX 2.3 descrevem o inventário observado. Sem hashes de artefato, relação de dependências ou licença extraídos da fonte, esses campos permanecem ausentes/`NOASSERTION` — não são inferidos.
- SARIF é uma representação dos achados deste scanner, não uma análise adicional. Achados médios/baixos são `warning`/`note`; alto/crítico são `error`.
- A comparação usa identidade estável (ecossistema, pacote e versão), não IDs sequenciais `F-001`. Se cobertura ou fontes mudarem, isso aparece como ressalva; “resolvida” significa ausente no segundo relatório, não prova de correção no deploy.
- Compare relatórios JSON da Gaara com `summary.coverage.inventory`; Markdown/SARIF/SBOM não substituem o relatório-base.
