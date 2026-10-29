<!-- gaara-module
id: finding-schema
version: 1.0
requires: []
scripts: []
-->

# Schema de Achado

> Contrato único de saída da Gaara. Todo script — presente ou futuro — emite **este** formato. É o que permite plugar ferramentas novas sem reescrever relatório, severidade ou lógica de ação.

---

## 1. Por que existe

Sem schema, cada script vira um dialeto: um usa "high", outro "Alto", outro só texto livre. Aí o agente precisa reinterpretar caso a caso — e erra.

Com schema:

- a matriz de severidade aplica igual a tudo;
- o relatório é gerado uma vez, para qualquer fonte;
- testes comparam JSON, não texto;
- adicionar ferramenta = adicionar adaptador, não mexer no núcleo.

---

## 2. Estrutura

```json
{
  "schema_version": "1.0",
  "scan": {
    "id": "gaara-20261024-0001",
    "tool": "log_triage",
    "host": "srv-legado",
    "started_at": "2026-10-24T02:00:00Z",
    "finished_at": "2026-10-24T02:03:12Z",
    "window": { "from": "2026-10-23T02:00:00Z", "to": "2026-10-24T02:00:00Z" },
    "sources": ["/var/log/auth.log"],
    "limits": { "bytes_read": 262144, "lines_read": 8123, "truncated": false }
  },
  "findings": [
    {
      "id": "F-001",
      "title": "Brute force SSH com spraying",
      "category": "detection/ssh-brute-force",
      "severity": "alto",
      "confidence": "alta",
      "mitre": ["T1110.001", "T1110.003"],
      "frameworks": [],
      "evidence": [
        {
          "source": "auth.log",
          "locator": "linhas 120-260",
          "excerpt": "Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2",
          "redacted": true
        }
      ],
      "observations": {
        "count": 130,
        "window_start": "2026-10-24T02:10:00Z",
        "window_end": "2026-10-24T02:41:00Z",
        "actors": ["203.0.113.45"],
        "distinct_users": 8
      },
      "impact": "Tentativa de acesso não autorizado por SSH. Nenhum sucesso observado.",
      "recommendation": {
        "action": "ban",
        "target": "203.0.113.45",
        "ttl_seconds": 86400,
        "command": "fail2ban-client set sshd banip 203.0.113.45",
        "rollback": "fail2ban-client set sshd unbanip 203.0.113.45",
        "requires_approval": true
      },
      "false_positive_notes": "NAT corporativo pode concentrar vários usuários no mesmo IP.",
      "not_observed": ["nenhum Accepted para o IP na janela"]
    }
  ],
  "summary": {
    "verdict": "atencao",
    "counts": { "critico": 0, "alto": 1, "medio": 0, "baixo": 0 },
    "correlations": [
      {
        "key": "203.0.113.45",
        "findings": ["F-001"],
        "note": "IP também aparece em scan de paths"
      }
    ],
    "not_observed": ["nenhuma conexão de saída atribuída à conta web"]
  }
}
```

---

## 3. Campos obrigatórios

### 3.1 `scan`

| Campo | Tipo | Regra |
|---|---|---|
| `id` | string | `gaara-YYYYMMDD-NNNN`, único por execução |
| `tool` | string | Nome do script que gerou |
| `host` | string | Hostname ou identificador |
| `started_at` / `finished_at` | ISO 8601 UTC | Obrigatório |
| `window.from` / `window.to` | ISO 8601 UTC | Janela analisada |
| `sources` | array | Arquivos, comandos ou APIs consultados |
| `limits` | objeto | Volume lido e se houve truncamento |

#### 3.1.1 `scan.artifacts` (opcional, coletor/auditoria)

Coletor de host ou auditor estático pode registrar os arquivos cujas hashes foram calculadas **antes** de qualquer ação:

```json
"artifacts": [
  { "path": "/var/www/html/uploads/foto.php.jpg",
    "sha256": "badec688…",
    "bytes": "43",
    "mtime": "2026-10-24T22:24:03Z" }
]
```

Campo opcional; quando presente, cada `path` aparece uma única vez e a hash confere com o arquivo original. O manifesto `saida.sha256` é a versão em texto para conferência fora do host.

### 3.2 `findings[]`

| Campo | Tipo | Regra |
|---|---|---|
| `id` | string | `F-NNN`, sequencial dentro do scan |
| `title` | string | Curto, específico, sem sensacionalismo |
| `category` | string | Da lista fechada (§4) |
| `severity` | enum | `critico` \| `alto` \| `medio` \| `baixo` |
| `confidence` | enum | `alta` \| `media` \| `baixa` |
| `evidence` | array | **Mínimo 1** item |
| `impact` | string | O que o atacante consegue, na prática |
| `recommendation.action` | enum | §5 |
| `recommendation.requires_approval` | bool | `true` se altera o sistema |
| `false_positive_notes` | string | Quando aplicável |
| `not_observed` | array | Ausências relevantes para a decisão |

Opcionais: `mitre`, `frameworks`, `observations`, `recommendation.command/rollback/ttl_seconds/target`.

### 3.3 `evidence[]`

| Campo | Regra |
|---|---|
| `source` | Arquivo (log ou código), comando, API ou boletim |
| `locator` | Linha, faixa, timestamp ou ID |
| `excerpt` | **≤ 500 caracteres, sempre redigido** |
| `redacted` | `false` apenas se comprovadamente não há segredo |
| `source_type` | `log` \| `code` \| `command` \| `api` \| `advisory` |
| `url` | **Obrigatório quando `source_type = advisory`** |
| `retrieved_at` | Data de consulta da fonte externa (ISO 8601) |

Sem `locator`, a evidência não é verificável — e um achado não verificável não é achado.

`redacted: false` só é aceitável em perícia autorizada (`--redact off --redact-off-reason`). Nesse caso o relatório **não circula** e a guarda segue `safe-operations.md`.

### 3.4 `summary`

| Campo | Regra |
|---|---|
| `verdict` | `estavel` \| `atencao` \| `incidente` |
| `counts` | Deve somar exatamente o total de `findings` |
| `correlations[]` | Cada `findings[]` interno deve existir |
| `not_observed` | Lista de ausências relevantes |
| `coverage` | Opcional (schema 1.1). Cobertura declarada — ver §3.4.1 |

#### 3.4.1 `summary.coverage` (opcional, schema 1.1)

Auditoria de dependências precisa declarar o que conseguiu olhar. Sem isso, "nenhum achado" é indistinguível de "nada foi lido".

```json
"coverage": {
  "manifests_found": 5,
  "manifests_parsed": 4,
  "manifests_failed": 1,
  "dependencies": 118,
  "dependencies_unpinned": 2,
  "docker_images": 1,
  "inventory": [
    { "type": "library", "ecosystem": "npm", "name": "lodash",
      "version": "4.17.20", "scope": "runtime", "pinned": true,
      "sources": ["package-lock.json"] }
  ],
  "queried": 116,
  "with_advisory": 4,
  "skipped_ecosystems": ["rpm"],
  "sources": [
    { "name": "OSV.dev", "url": "https://api.osv.dev/v1/querybatch",
      "retrieved_at": "2026-10-29T14:02:00Z", "stale": false,
      "cached": false, "error": null }
  ],
  "not_evaluated": ["OWASP A01 e A06", "código fora de PHP"]
}
```

Regras:

- `manifests_parsed + manifests_failed == manifests_found`.
- `sources[]` lista **toda** fonte tentada, inclusive a que falhou (`error` preenchido). Fonte indisponível não desaparece do relatório.
- `stale: true` significa cache vencido; o achado que depende dele não pode ser apresentado como atual.
- `not_evaluated[]` é obrigatório quando a cobertura é parcial, e é o que permite responder "não encontrei" sem mentir.
- `inventory[]` (aditivo em 1.1) guarda somente identidade/versão/escopo/origem observados; habilita SBOM e comparação. Hashes, licenças e arestas não observados não devem ser inferidos.

#### 3.4.2 Versões aceitas

`schema_version` `1.0` e `1.1` são válidas. `1.1` é **aditiva**: aceita o prefixo `supply-chain/` em `category`, `coverage` em `summary` e `retrieved_at` em qualquer evidência de API. Um resultado `1.0` continua válido e não precisa ser migrado.

#### 3.4.3 Veredito em auditoria de dependência

`incidente` significa comprometimento observado. Vulnerabilidade conhecida **não** é comprometimento: `deps_audit.py` nunca declara `incidente`, no máximo `atencao`. Quem sustenta `incidente` é a rotina de log/IR.

---

## 4. Categorias (lista fechada)

Prefixo indica a natureza do achado:

| Prefixo | Uso | Exemplos |
|---|---|---|
| `detection/` | atividade observada em log | `ssh-brute-force`, `credential-stuffing`, `scan-enumeration`, `path-traversal`, `rce-runtime`, `sql-injection`, `upload-webshell`, `cryptomining`, `exfiltration-c2`, `api-abuse`, `prompt-injection` |
| `posture/` | configuração do host | `ssh-config`, `firewall`, `permissions`, `tls`, `secrets`, `docker`, `updates` |
| `cve/` | vulnerabilidade conhecida com CVE | `cve-2026-109618` (ID em minúsculas), `exposure`, `patch-state` |
| `supply-chain/` | dependência, inventário e cadeia de suprimentos | `known-vulnerability`, `inventory-gap`, `unpinned-dependency`, `docker-base-image`, `os-package` |
| `legacy/` | stack EOL | `eol-runtime`, `unsupported-dependency`, `migration-blocker` |
| `code/` | fraqueza estática no código | `rce`, `injection`, `upload` |
| `ir/` | resposta a incidente | `persistence`, `lateral-movement`, `evidence-integrity` |
| `meta/` | sobre o próprio agente | `prompt-injection-attempt`, `baseline-poisoning` |

Categoria fora da lista → o schema é inválido. Isso evita taxonomia inventada a cada módulo.

---

## 5. Ações permitidas

| `action` | Efeito | Aprovação |
|---|---|---|
| `none` | Só registrar | Não |
| `monitor` | Acompanhar na próxima janela | Não |
| `investigate` | Coletar mais evidência | Não |
| `escalate` | Passar para humano | Não |
| `ban` | Bloquear IP | **Sim** |
| `unban` | Desbloquear IP | **Sim** |
| `isolate` | Restringir rede/host | **Sim** |
| `patch` | Atualizar componente | **Sim** |
| `migrate` | Plano de migração | **Sim** |
| `rotate-credential` | Revogar credencial | **Sim** |

Regra dura: `requires_approval` é `true` para tudo que não seja `none`, `monitor`, `investigate` ou `escalate`. Um validador deve rejeitar o JSON se essa regra for violada.

---

## 6. Regras de validação

Um resultado só é aceito se **todas** forem verdadeiras:

- [ ] `schema_version` presente e suportada
- [ ] Todo `finding` tem ≥ 1 evidência com `locator`
- [ ] `severity` e `confidence` dentro do enum
- [ ] `category` dentro da lista fechada
- [ ] `excerpt` ≤ 500 caracteres
- [ ] Nenhum segredo em nenhum campo (ver `safe-operations.md` §10)
- [ ] `counts` bate com `findings`
- [ ] `correlations[].findings` referencia IDs existentes
- [ ] `source_type = advisory` tem `url` e `retrieved_at`
- [ ] Evidência de `source_type = api` tem `url` e `retrieved_at`
- [ ] `coverage.manifests_parsed + coverage.manifests_failed == coverage.manifests_found`
- [ ] Nenhum número de CVE citado sem estar na evidência
- [ ] Ação que altera sistema tem `requires_approval: true` e `rollback`

Falha de validação = resultado descartado, não "corrigido no relatório".

---

## 7. Interface dos scripts

Todo script que produz achado segue a mesma linha de comando:

```bash
./script.py --help
./script.py --format json          # padrão: json
./script.py --format md            # relatório legível
./script.py --output /tmp/out.json
./script.py --since 24h
./script.py --redact on|off        # padrão: on; "off" exige justificativa
```

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Executou, nenhum achado alto/crítico |
| `1` | Erro de execução |
| `2` | Uso incorreto |
| `3` | Executou e encontrou achado alto ou crítico |

O código `3` permite usar a skill em CI ou cron com alerta.

### Regras de implementação

- `--help` sempre presente e útil.
- Saída em `stdout`; erro em `stderr`.
- Nunca escrever fora de `--output` (scripts de leitura).
- Stdlib quando possível; dependência extra só se justificada.
- Timeout em qualquer chamada externa.
- Script com rede é **offline por padrão**: só consulta com `--online`, e `--offline` usa apenas cache.
- Determinismo: mesma entrada → mesmo JSON (ordenação estável). Com `--online`, o determinismo vale por snapshot de cache; `retrieved_at` registra a diferença.

---

## 8. Mapeamento para o relatório

| Campo do achado | Onde aparece no relatório |
|---|---|
| `severity` + `confidence` | Primeiras colunas da tabela de achados |
| `title` | Título do achado |
| `evidence[]` | Bloco "Evidência", com fonte e locator |
| `impact` | Bloco "Impacto" |
| `recommendation` | Bloco "Recomendação", com comando copiável |
| `not_observed` | Seção "Não observado" |
| `correlations` | Seção "Correlação" |
| `false_positive_notes` | Nota de rodapé do achado |

Ver `report-templates.md` para o layout final.

---

## 9. Exemplo mínimo válido

```json
{
  "schema_version": "1.0",
  "scan": {
    "id": "gaara-20261024-0002",
    "tool": "harden_check",
    "host": "srv-legado",
    "started_at": "2026-10-24T21:00:00Z",
    "finished_at": "2026-10-24T21:00:04Z",
    "window": { "from": "2026-10-24T21:00:00Z", "to": "2026-10-24T21:00:04Z" },
    "sources": ["sshd -T"],
    "limits": { "bytes_read": 4096, "lines_read": 120, "truncated": false }
  },
  "findings": [
    {
      "id": "F-001",
      "title": "Login de root por senha habilitado",
      "category": "posture/ssh-config",
      "severity": "alto",
      "confidence": "alta",
      "evidence": [
        { "source": "sshd -T", "locator": "permitrootlogin", "excerpt": "permitrootlogin yes", "redacted": true }
      ],
      "impact": "Permite ataque de força bruta direto contra a conta mais privilegiada.",
      "recommendation": {
        "action": "patch",
        "command": "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sshd -t && systemctl reload sshd",
        "rollback": "reverter do backup /etc/ssh/sshd_config.bak",
        "requires_approval": true
      },
      "not_observed": ["PasswordAuthentication já está desabilitado"]
    }
  ],
  "summary": {
    "verdict": "atencao",
    "counts": { "critico": 0, "alto": 1, "medio": 0, "baixo": 0 },
    "correlations": [],
    "not_observed": []
  }
}
```
