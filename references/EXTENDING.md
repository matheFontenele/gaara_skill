<!-- gaara-module
id: extending
version: 1.0
requires: [finding-schema]
scripts: []
-->

# Como Estender a Gaara

> Guia para adicionar rotinas, ferramentas e padrões **depois** que a skill já existe. O objetivo é que adicionar um módulo seja preencher formulário, não decidir arquitetura.

---

## 1. Regra de ouro

**Um módulo = uma capacidade.**

Não crie módulo por framework (`nist.md`, `iso.md`, `cis.md`) nem por ferramenta redundante. Crie por capacidade (`hardening-linux.md`, `incident-response.md`) e trate framework/ferramenta como **rótulo** dentro dela.

Motivo: dois módulos falando de SSH acabam com limiares diferentes — e o agente responde de forma inconsistente.

---

## 2. Decida o tipo de extensão

| Situação | Tipo | Entrega |
|---|---|---|
| Padrão, framework, boas práticas | **Referência** | 1 arquivo `.md` |
| Ferramenta que só lê dados | **Referência + leitor** | `.md` + script read-only |
| Ferramenta que altera o sistema | **Referência + ação** | `.md` + script com portão de ação |
| Só quer melhorar o julgamento existente | **Edição** | Alterar módulo já existente |

Se você não consegue nomear a capacidade em duas palavras, provavelmente é edição, não módulo novo.

---

## 3. Receita (7 passos)

### Passo 1 — Criar a referência

`references/<capacidade>.md`, com o cabeçalho de módulo:

```markdown
<!-- gaara-module
id: clamav
version: 1.0
requires: [safe-operations]
scripts: [clamav_scan.py]
-->

# ClamAV
```

### Passo 2 — Preencher o esqueleto obrigatório

```markdown
## Quando usar
## Pré-requisitos      (versão, acesso, permissão necessária)
## Coleta              (comandos somente leitura)
## Interpretação       (como virar achado)
## Limiares e falsos positivos
## Ações permitidas
## Limitações
```

Sem `Limitações`, o módulo é rejeitado. Todo módulo mente um pouco se não declarar onde falha.

### Passo 3 — Categorizar os achados

Use apenas categorias da lista fechada em `finding-schema.md` §4. Se nenhuma serve:

1. Verifique se é realmente novo.
2. Se for, adicione a categoria ao schema **primeiro**, com justificativa.
3. Só então use.

Categoria inventada no script quebra o contrato.

### Passo 4 — Escrever o script (se houver)

**Leitor (read-only):**

```
--help / --format json|md / --output / --since / --redact
saída: findings no schema
exit: 0 ok, 1 erro, 2 uso, 3 achado alto/crítico
nunca escreve fora de --output
timeout em chamada externa
```

**Ação (altera o sistema):** além de tudo acima, obrigatoriamente:

- `--dry-run` como padrão; `--apply` para executar;
- `--reason` e `--evidence` obrigatórios;
- allowlist **fail-closed**;
- TTL obrigatório;
- auditoria append-only com `correlation_id`;
- rollback impresso antes da execução;
- jamais `flush`, `--all`, `rm`, edição de config de serviço.

Reutilize o portão descrito em `safe-operations.md` — não reimplemente.

### Passo 5 — Registrar no roteador

Adicione **uma linha** à tabela "Disponível nesta versão" do `SKILL.md`:

```markdown
| "tem vírus no servidor", "malware", "arquivo suspeito" | `references/clamav.md` |
```

Regras da linha:

- Gatilho em linguagem do usuário, não em jargão técnico.
- No máximo ~3 frases de gatilho por linha.
- Se o roteador passar de ~20 linhas, é hora de dividir a skill (§7).

### Passo 6 — Criar teste

Todo módulo entra com **dois** arquivos:

| Arquivo | Conteúdo |
|---|---|
| `tests/corpus/<modulo>-sample.*` | Entrada realista, incluindo um caso benigno |
| `tests/expected/<modulo>-triage.md` | Gabarito: quais achados, com que severidade |

Sem gabarito, não há como saber se a próxima alteração quebrou algo.

### Passo 7 — Validar

- [ ] `--help` funciona
- [ ] JSON valida contra o schema
- [ ] Fixture benigna não gera falso positivo alto
- [ ] Fixture maliciosa gera o achado esperado
- [ ] Nenhum segredo no output
- [ ] Roteador abre o arquivo certo
- [ ] Trigger testado em sessão nova

---

## 4. Exemplo completo — ClamAV

**1. `references/clamav.md`**

```markdown
<!-- gaara-module
id: clamav
version: 1.0
requires: [safe-operations]
scripts: [clamav_scan.py]
-->

# ClamAV

## Quando usar
Suspeita de webshell, arquivo enviado por upload, malware em diretório de upload.

## Pré-requisitos
`clamscan` instalado; leitura no caminho alvo. Base atualizada (`freshclam`).

## Coleta
```bash
clamscan -r --infected --no-summary /var/www/uploads
```

## Interpretação
Cada arquivo infectado vira achado `detection/upload-webshell`, severidade
`critico` se estiver no webroot, `alto` se estiver em quarentena.

## Limiares e falsos positivos
Assinatura genérica (`PHP.Shell.*`) pode acertar código legítimo ofuscado.
Sempre correlacionar com data de modificação e acesso HTTP.

## Ações permitidas
Mover para quarentena (com aprovação). Nunca apagar antes de coletar hash.

## Limitações
Não detecta webshell ofuscada sob medida. Não substitui revisão de código.
Não enxerga arquivo em memória.
```

**2. `scripts/clamav_scan.py`** — roda `clamscan`, converte saída em findings.

**3. Roteador:**

```markdown
| "tem vírus no servidor", "malware", "arquivo suspeito" | `references/clamav.md` |
```

**4. Teste:** `tests/corpus/clamav-sample.txt` (saída simulada) + gabarito.

---

## 5. Adicionando padrões e frameworks

Não crie módulo. Adicione **rótulo** ao controle que já existe:

```yaml
- id: ssh-permit-root
  framework: [CIS-5.2.8, NIST-AC-6, ISO-A.9.2.3]
  check: sshd -T | grep -q '^permitrootlogin no'
  severity: alto
```

| Framework | Onde encaixa |
|---|---|
| CIS Benchmark | `hardening-linux.md` + registry do `harden_check.py` |
| NIST 800-61 | `incident-response.md` (fases) |
| NIST 800-53 | rótulos nos controles de hardening |
| ISO 27001 | rótulos nos controles + seção de evidência |
| OWASP ASVS | revisão de aplicação |
| OWASP LLM Top 10 | `legacy-stacks.md` / app com IA |
| MITRE ATT&CK | campo `mitre` de cada achado |
| LGPD | `safe-operations.md` §8 |

Assim você responde auditoria sem fragmentar conhecimento.

---

## 6. Regras de nomenclatura

| Item | Padrão | Exemplo |
|---|---|---|
| Referência | `kebab-case.md` | `hardening-linux.md` |
| Script leitor | `<fonte>_<verbo>.py` | `wazuh_pull.py` |
| Script de ação | `<alvo>_guard.py` | `f2b_guard.py` |
| Categoria | `<prefixo>/<kebab>` | `detection/ssh-brute-force` |
| Fixture | `<modulo>-sample.<ext>` | `wazuh-sample.json` |
| Gabarito | `<modulo>-triage.md` | `wazuh-triage.md` |

---

## 7. Quando dividir a skill

Sinais de que a Gaara ficou grande demais:

- roteador com mais de ~20 linhas;
- mais de ~15 referências;
- `SKILL.md` acima de ~200 linhas;
- dois módulos com sobreposição > 30%.

Aí separe em skills irmãs por domínio, mantendo o núcleo:

```
gaara            → escopo, regras, roteador, severidade, schema
gaara-forensics  → IR pesado, memória, disco
gaara-compliance → CIS, ISO, evidências de auditoria
gaara-appsec     → revisão de código, OWASP
```

Elas podem se referenciar. Enquanto estiver abaixo do limite, um único skill com roteador é mais simples — e mais confiável.

---

## 8. Anti-padrões

| Anti-padrão | Consequência |
|---|---|
| Colocar conteúdo no `SKILL.md` | Infla contexto e piora a decisão |
| Módulo sem seção de limitações | Promete mais do que entrega |
| Script que despeja saída bruta | O modelo alucina a interpretação |
| Ação sem portão de aprovação | Fura o modelo de segurança |
| Categoria nova sem atualizar o schema | Quebra o contrato |
| Dois módulos com limiares diferentes | Resposta inconsistente |
| Ferramenta que você não usa | Peso morto nunca testado |
| Módulo ofensivo | Fora de escopo — recusar |

---

## 9. Versionamento

- Mudança de conteúdo: `version: 1.1` no cabeçalho do módulo.
- Mudança de contrato (schema, campos): `schema_version` nova e migração dos scripts.
- Mudança na `description` do `SKILL.md`: **sempre** reexecutar o teste de trigger — é ela que decide quando a skill carrega.
- Registrar toda mudança no histórico de decisões do documento de planejamento.

---

## 10. Checklist de aceite de módulo novo

- [ ] Cabeçalho `gaara-module` preenchido
- [ ] Esqueleto completo, incluindo limitações
- [ ] Categorias da lista fechada
- [ ] Script segue a interface comum
- [ ] Ações passam pelo portão (se houver ação)
- [ ] Uma linha no roteador
- [ ] Fixture benigna + fixture maliciosa
- [ ] Gabarito escrito
- [ ] JSON valida contra o schema
- [ ] Sem segredo no output
- [ ] Trigger testado em sessão nova
