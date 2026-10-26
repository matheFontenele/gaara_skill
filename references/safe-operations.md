<!-- gaara-module
id: safe-operations
version: 1.1
requires: [finding-schema]
scripts: [f2b_guard]
-->

# Operações Seguras

> Este arquivo governa a **única** camada que altera o sistema. Se houver conflito entre este documento e qualquer outro, este vence.

---

## 1. Princípios

1. **Menor ação possível.** Ban de IP antes de bloqueio de rede; bloqueio antes de mudança de configuração.
2. **Reversível primeiro.** Prefira o que tem rollback trivial.
3. **Uma mudança por vez.** Duas alterações simultâneas tornam impossível saber o que causou o quê.
4. **Evidência antes da ação.** Preserve o log antes de mexer.
5. **Fail-closed.** Em dúvida sobre allowlist ou validação, **não aja**.
6. **Aprovação humana é obrigatória** para ampliar bloqueio, não uma formalidade. A remoção automática de um TTL já aprovado (`sweep`) é a única exceção — e só reduz bloqueio.

---

## 2. Allowlist

### 2.1 Conteúdo mínimo obrigatório

| Faixa | Motivo |
|---|---|
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC1918 |
| `100.64.0.0/10` | CGNAT (VPN, carrier-grade) |
| `169.254.0.0/16`, `fe80::/10` | Link-local (metadados de cloud) |
| `224.0.0.0/4`, `ff00::/8` | Multicast |
| `fc00::/7` | IPv6 ULA |
| IPs administrativos | `operator_ips` / `protected_ips` no config |
| `$SSH_CONNECTION`, `$SSH_CLIENT` | Detectados automaticamente pelo script; não precisam entrar na config |

### 2.2 Regras

- Formato: lista JSON de IPs/CIDRs, uma entrada por item (`allowlist` em `assets/config.json`). JSON não aceita comentários; use revisão e histórico do arquivo.
- **Fail-closed:** se o arquivo não puder ser lido, não existir ou for inválido → **toda ação de ban é recusada**.
- A allowlist é **configuração revisada**, não um ajuste de runtime: mudanças passam por revisão e ficam fora de um incidente.
- Nunca adicionar IP à allowlist durante um incidente, a menos que seja o próprio operador ficando trancado fora.
- Antes de banir, verificar também: IP de origem em `$SSH_CONNECTION`, IP de banco, IP de monitoração conhecido.

### 2.3 Anti-lockout

Checklist antes de qualquer ban:

- [ ] IP não está na allowlist
- [ ] IP não é o par remoto da sessão SSH atual
- [ ] IP não é o gateway/pseudo-terminal do operador
- [ ] Existe acesso alternativo (console do provedor, VPN, segundo IP)
- [ ] O TTL é curto o suficiente para errar com segurança

---

## 3. TTL

| Severidade | TTL padrão | Máximo sem escalar |
|---|---|---|
| Baixo | 0 (não banir) | — |
| Médio | 1 h | 4 h |
| Alto | 24 h | 72 h |
| Crítico | sem padrão; exige TTL explícito | 72 h com aprovação explícita |

Regras:

- **Nenhum ban permanente** por decisão automática do agente.
- Todo ban tem expiração registrada; `sweep` remove os vencidos.
- Reincidência não duplica TTL automaticamente — exige nova análise.
- Ban de rede inteira (`/24`, ASN) é **proibido**. A ferramenta só aceita IP único; se o usuário pedir rede, recuse e explique o risco de lockout.

---

## 4. Protocolo de aprovação

Antes de executar, apresente **exatamente** isto:

```
AÇÃO PROPOSTA
  Comando:  python3 scripts/f2b_guard.py ban --ip 203.0.113.45 --jail sshd \
            --severity alto --confidence alta --reason "..." --evidence "..." \
            --execute --approved-by <nome>
  Efeito:   bloqueia o IP no jail sshd por 24h
  Alvo:     203.0.113.45 — fora da allowlist, não é sua sessão
  Evidência: 312 falhas SSH entre 02:10 e 02:41 (auth.log)
  Confiança: alta
  Risco:    se for IP compartilhado (NAT/proxy), outros usuários perdem acesso
  Rollback: python3 scripts/f2b_guard.py unban --ip 203.0.113.45 --jail sshd \
            --reason "..." --execute --approved-by <nome>
  Auditoria: /var/log/gaara/audit.jsonl
```

O dry-run do `f2b_guard.py` imprime esse bloco com o comando exato e o TTL. Só execute após um "sim" inequívoco. Silêncio não é aprovação. "Tanto faz" não é aprovação.

---

## 5. Registro de ações

### 5.1 Permitidas (com aprovação)

| Ação | Observação |
|---|---|
| Ban de IP em jail existente | Com TTL e allowlist validados |
| Unban de IP | Só se o próprio agente baniu; ban externo exige decisão humana e comando manual |
| Coleta de evidência | Copiar log para diretório de incidente, com hash |
| Geração de relatório | Sempre permitido |

### 5.2 Proibidas — sempre

- `fail2ban-client unban --all`
- `fail2ban-client flush` / `set <jail> flush`
- Editar `/etc/ssh/sshd_config`
- Alterar firewall global (`ufw disable`, `iptables -F`)
- Apagar ou rotacionar log durante investigação
- `rm`, `truncate`, `shred` em produção
- Instalar/remover pacote
- Reiniciar serviço durante coleta de evidência
- Criar usuário, chave SSH ou tarefa agendada
- Qualquer comando ofensivo

Se o usuário pedir algo desta lista: explique o risco em uma frase, ofereça a alternativa segura e **não execute**.

### 5.3 `f2b_guard.py` — a única via de ban

O script implementa este documento. Ele não substitui o Fail2ban: exige um jail já existente e configurado no host.

**Configuração**

```bash
cp assets/config.example.json assets/config.json
chmod 640 assets/config.json
```

O caminho padrão é `assets/config.json`; `--config` ou `GAARA_F2B_CONFIG` sobrescrevem. A config é **fail-closed**: ausente, ilegível, com chave desconhecida ou sem as faixas obrigatórias da allowlist → nenhuma ação.

| Chave | Regra |
|---|---|
| `client` | executável do `fail2ban-client`; argumentos vão em lista, sem shell |
| `socket` | opcional; caminho absoluto do socket, usado como `-s` |
| `allowed_jails` | lista fechada para `check` e `ban`; jail fora dela é recusado |
| `allowlist` | precisa conter as faixas mínimas da §2.1 |
| `protected_ips` / `operator_ips` | IPs/CIDRs que nunca podem ser banidos |
| `ttl` | `medio`, `alto` e teto global `max` (máximo 72 h) |
| `max_sweep` | quantos bans vencidos remover por execução (1–100) |
| `audit_path` | absoluto; arquivo JSONL criado em modo `0600` |

**Comandos**

```bash
# somente leitura
python3 scripts/f2b_guard.py check --jail sshd
python3 scripts/f2b_guard.py check --jail sshd --ip 203.0.113.45

# dry-run é o padrão: mostra comando, TTL, rollback e auditoria
python3 scripts/f2b_guard.py ban --ip 203.0.113.45 --jail sshd \
  --severity alto --confidence alta \
  --reason "312 falhas SSH em 31 min" --evidence "auth.log:1234-1560"

# executa somente com aprovação explícita na mesma sessão
python3 scripts/f2b_guard.py ban ... --execute --approved-by seu-nome

# remove apenas ban criado por esta ferramenta
python3 scripts/f2b_guard.py unban --ip 203.0.113.45 --jail sshd \
  --reason "falso positivo" --execute --approved-by seu-nome

# remove bans vencidos; dry-run lista o que faria
python3 scripts/f2b_guard.py sweep
python3 scripts/f2b_guard.py sweep --execute --approved-by seu-nome
```

Flags globais (`--config`, `--format json|md`, `--now`) vêm **antes** do subcomando.

**Política aplicada**

- Só IP único. CIDR, nome de host e IPv6 mapeado (`::ffff:...`) são recusados.
- `baixo` não autoriza ban; `critico` exige `--ttl` explícito.
- TTL padrão: médio 1 h (máx. 4 h), alto 24 h (máx. 72 h); nenhum ban passa de 72 h.
- Confiança `baixa` não autoriza ban.
- IP na allowlist, em `protected_ips`, em `operator_ips` ou na sessão SSH atual (`$SSH_CONNECTION`/`$SSH_CLIENT`) é recusado.
- `ban` em IP já banido é recusado sem alterar nada.
- `unban` e `sweep` só agem sobre bans registrados como criados por esta ferramenta. Ban externo continua exigindo decisão humana e comando manual.
- `unban`/`sweep` validam o nome do jail, mas não exigem que ele ainda esteja em `allowed_jails`: remover um bloqueio aprovado é redução de impacto, e o jail pode ter saído da config.
- O estado é confirmado consultando o jail depois do comando. "Comando retornou 0" não basta.
- Falha do cliente, timeout, saída inesperada e falha de auditoria geram exit `1`; violação de política gera exit `2`.

**Auditoria e TTL**

Cada ação grava dois registros JSONL com o mesmo `correlation_id`: `intent` antes do comando e `result` depois. O resultado contém `ok`, `error` ou `not_banned`, além de `verified_banned` e `client_exit`. Motivo e evidência são redigidos antes de gravar.

O Fail2ban não tem TTL portátil por IP. O vencimento fica em `expires_at` na auditoria e é aplicado pelo `sweep`. Por isso:

- execute `sweep` periodicamente (timer/cron) com uma identidade de automação, por exemplo `--approved-by gaara-sweep`;
- `sweep` só remove bans **criados pela ferramenta** e já vencidos;
- se o processo que aprovou o ban não rodar o sweep, o IP continua banido — monitore bans vencidos;
- o Fail2ban não registra a origem do ban. Se o mesmo IP/jail for re-banido **manualmente** antes do vencimento, o `sweep` não consegue distinguir e pode remover esse ban manual ao aplicar o TTL original. Não re-bane manualmente um IP que a ferramenta gerencia; use a ferramenta ou trate o caso explicitamente.

**O que o script nunca faz**

`sudo`, shell, `unban --all`, `flush`, edição de jail, firewall global, instalação de pacote, ban de rede, ban permanente.

---

## 6. Auditoria

### 6.1 Schema

Duas linhas por decisão, mesmo `correlation_id` (quebradas aqui para leitura; no arquivo, uma linha por registro):

```jsonl
{"ts":"2026-10-24T21:00:00Z","tool":"f2b_guard","phase":"intent","action":"ban",
 "correlation_id":"gaara-20261024-0001","ip":"203.0.113.45","jail":"sshd",
 "ttl":86400,"expires_at":"2026-10-25T21:00:00Z","reason":"312 falhas SSH",
 "evidence":"auth.log:1234-1560","severity":"alto","confidence":"alta",
 "approved_by":"user","command":["fail2ban-client","set","sshd","banip","203.0.113.45"],
 "rollback":["fail2ban-client","set","sshd","unbanip","203.0.113.45"]}
{"ts":"2026-10-24T21:00:01Z","phase":"result","result":"ok",
 "client_exit":0,"verified_banned":true,"detail":"IP confirmado"}
```

### 6.2 Regras

- Append-only. Nunca editar registro existente.
- Permissão `0600`, dono = usuário da automação.
- Retenção mínima: 90 dias.
- Um `correlation_id` por decisão, não por comando; `intent` antes, `result` depois.
- Falha também é registrada (`result: error` + motivo).

---

## 7. Rollback

| Ação | Rollback |
|---|---|
| Ban | `python3 scripts/f2b_guard.py unban --ip <ip> --jail <jail> --reason "rollback" --execute --approved-by <nome>` |
| Cópia de evidência | Remover cópia após encerramento (nunca o original) |
| Alteração de config | Reverter do backup feito **antes** |
| Relatório | Corrigir e reemitir; não apagar histórico |

Regra: se você não sabe escrever o rollback, **não tem autorização para executar**.

---

## 8. LGPD e dados pessoais

- **Endereço IP é dado pessoal** quando associado a pessoa natural identificável.
- Base legal típica: legítimo interesse / segurança da informação (art. 7º, IX).
- **Minimização:** registre o necessário para a decisão, não o log inteiro.
- **Finalidade:** segurança e prevenção a fraude. Uso para outra finalidade exige nova base legal.
- **Retenção:** prazo definido (90 dias para auditoria; 6 meses para evidência de incidente, salvo obrigação legal).
- **Acesso:** restrito a quem opera segurança.
- **Compartilhamento:** não enviar IPs a serviços externos de threat intel sem necessidade e sem informar o usuário.
- **Requisição de titular:** encaminhar ao responsável de dados; não responder diretamente.

---

## 9. Evidência

1. Preserve o **original**. Trabalhe sobre cópia.
2. Registre hash (`sha256sum`) no momento da coleta.
3. Anote cadeia de custódia: quem coletou, quando, de onde.
4. Não "limpe" o ambiente para ver se o problema some — isso destrói a prova.
5. Em comprometimento confirmado, a reconstrução do host costuma ser mais segura que a limpeza.

---

## 10. Segredos

- Redija antes de qualquer citação: `password=`, `passwd`, `token`, `Authorization`, `Cookie`, `Set-Cookie`, JWT, chaves privadas, connection strings.
- Nunca cole segredo em relatório, ticket ou chat.
- Se um segredo apareceu em log, ele deve ser considerado **exposto** e rotacionado.
- Ao orientar rotação, liste os sistemas que usam a credencial antes de sugerir a troca.

---

## 11. Janela de mudança

- Ação de contenção pode ocorrer a qualquer hora (é resposta a incidente).
- Ação de hardening segue janela acordada.
- Fora da janela, apenas o que for reversível em menos de 5 minutos.
- Toda mudança planejada tem: objetivo, comando, validação, rollback, responsável.
