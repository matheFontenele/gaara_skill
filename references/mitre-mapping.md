<!-- gaara-module
id: mitre-mapping
version: 1.0
requires: [detection-playbook, finding-schema]
scripts: [log_triage]
-->

# Mapeamento MITRE ATT&CK

> ATT&CK é **vocabulário**, não veredito. Uma técnica descreve *como* o ator agiu; ela não prova que ele agiu, nem mede impacto.

---

## 1. Como usar

- Cite a técnica **só** quando o comportamento observado corresponder a ela.
- Prefira a sub-técnica quando o comportamento for específico (`T1110.003` em vez de `T1110`).
- Use o campo `mitre` do `finding-schema.md`; não invente ID.
- ATT&CK cobre ataque a sistema. **Prompt injection contra o agente não está no ATT&CK** — use MITRE ATLAS (`AML.T0051`) e diga que é outro framework.
- Técnica não altera severidade. Severidade vem do impacto e da confiança.

---

## 2. Categorias da Gaara → técnicas

| Categoria | Técnicas | Quando cabe |
|---|---|---|
| `detection/ssh-brute-force` | `T1110.001`, `T1110.003`, `T1078` | Falhas em volume; spraying por cardinalidade; `T1078` só com sucesso |
| `detection/credential-stuffing` | `T1110.004`, `T1078` | Muitas contas, poucas tentativas, mesmo fingerprint |
| `detection/scan-enumeration` | `T1595`, `T1595.002` | Varredura de paths, métodos, versões |
| `detection/path-traversal` | `T1190`, `T1005`, `T1552.001` | `../`, LFI, leitura de arquivo; `T1552.001` se credencial em arquivo |
| `detection/rce-runtime` | `T1190`, `T1059.004`, `T1105` | Payload de comando, crash de interpretador, download |
| `detection/sql-injection` | `T1190` | Payload SQL; `T1005` se extração confirmada |
| `detection/upload-webshell` | `T1505.003`, `T1105` | Upload aceito e acessível |
| `detection/cryptomining` | `T1496` | Processo de mineração, pool |
| `detection/exfiltration-c2` | `T1041`, `T1071.001`, `T1571` | Saída anômala, beaconing, porta não padrão |
| `detection/api-abuse` | `T1499`, `T1110`, `T1078` | Esgotamento, enumeração de ID, chave comprometida |
| `meta/prompt-injection-attempt` | `AML.T0051` (ATLAS) | Instrução plantada em campo lido pelo agente |
| `meta/baseline-poisoning` | `AML.T0020` (ATLAS) | Envenenamento lento de linha de base |
| `ir/persistence` | `T1053`, `T1543`, `T1547` | Cron, systemd, autostart |
| `ir/lateral-movement` | `T1021`, `T1570` | SSH interno, cópia entre hosts |
| `code/*` | — | Fraqueza estática; vira `detection/*` só se explorada e observada |

> `T1190` (Exploit Public-Facing Application) é o rótulo mais usado e o mais fácil de aplicar errado. Só use quando houver **tentativa de explorar aplicação exposta**, não para qualquer requisição estranha.

Categorias `code/*` (achados estáticos de código) **não recebem técnica ATT&CK**: são fraquezas no código, não comportamento observado. Se o código for efetivamente explorado, o log gera um achado `detection/*`, e aí sim cabe técnica.

---

## 3. Técnicas emitidas pelos scripts

| Script | Técnicas |
|---|---|
| `log_triage.py` | `T1110.001`, `T1110.003`, `T1078`, `T1595`, `T1595.002`, `T1190`, `T1005`, `T1059.004`, `T1505.003`, `T1105`, `AML.T0051` |
| `php_audit.py` | — (código estático, não comportamento observado) |

O campo é opcional. Achado sem técnica é melhor que achado com técnica errada.

---

## 4. O que não fazer

| Erro | Por quê |
|---|---|
| Citar `T1110` para um único erro de senha | Não é força bruta; é ruído |
| Citar `T1078` sem login bem-sucedido | `Valid Accounts` exige uso de credencial válida |
| Citar `T1190` para scan | Scan é `T1595`; exploração é outra etapa |
| Usar ATT&CK para inflar relatório | Técnica não é severidade |
| Inventar sub-técnica | ID errado destrói credibilidade mais que a ausência |
| Misturar ATT&CK e ATLAS sem avisar | São frameworks diferentes; declare qual |

---

## 5. Lacunas de escopo

Este mapeamento cobre Linux server + aplicação web. Fora do escopo atual:

- Cloud (AWS/Azure/GCP) — matriz própria.
- Containers/Kubernetes — matriz própria.
- Windows/AD — fora do escopo da skill.
- Mobile e ICS — fora.

Se o incidente sair desse perímetro, diga que o mapeamento está incompleto em vez de forçar uma técnica.

---

## 6. Exemplo

Achado: 130 falhas SSH de `203.0.113.45`, 8 usuários distintos em 31 minutos, sem sucesso.

```json
{ "mitre": ["T1110.001", "T1110.003"] }
```

- `T1110.001` — tentativa de adivinhar senha.
- `T1110.003` — mesma tentativa distribuída por vários usuários (spraying).
- **Não** entra `T1078`: não houve login válido.

Se houvesse `Accepted password` após as falhas, aí sim:

```json
{ "mitre": ["T1110.001", "T1110.003", "T1078"] }
```

E a severidade subiria para crítico — por causa do acesso, não da técnica.
