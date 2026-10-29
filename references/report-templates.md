<!-- gaara-module
id: report-templates
version: 1.0
requires: [finding-schema]
scripts: []
-->

# Templates de Relatório

> Regras gerais valem para todos os modelos: sem segredo, sem achismo, sem jargão sem tradução. Todo número tem fonte. Todo comando é copiável.

---

## Regras gerais

1. **Comece com resumo para a pessoa responsável:** o que foi encontrado, o que pode significar e qual decisão é necessária.
2. **Separe fato, hipótese e lacuna:** evidência observada ≠ impacto confirmado ≠ comprometimento.
3. **Todo achado tem severidade e confiança**, traduzidas em linguagem prática; CVSS/KEV/EPSS não substituem contexto.
4. **Todo trecho de log é redigido** e citado com arquivo e janela.
5. **"Não observado" e "não avaliado" são diferentes:** diga o que a ferramenta procurou e o que ficou fora do escopo.
6. **Uma recomendação por linha de ação**, com objetivo, esforço e risco; para ações de alteração, peça aprovação.
7. **Nada de "possivelmente talvez".** Se não sabe, escreva exatamente o que falta para saber.
8. **Público define a linguagem:** explique siglas na primeira ocorrência e deixe o detalhe técnico em seção própria.

---

## 1. Digest diário (triagem)

```markdown
# Triagem — {host} — {data}

**Janela:** {início} → {fim}
**Fontes:** auth.log, nginx/access.log, nginx/error.log
**Veredito:** {estável | atenção | incidente em curso}

## Resumo em uma linha
{ex.: 41 mil requisições, 3 IPs acima do limiar, nenhum indício de sucesso.}

## Achados
| # | Sev | Confiança | Achado | Evidência | Ação |
|---|-----|-----------|--------|-----------|------|
| 1 | Alto | Alta | Brute force SSH de 203.0.113.45 | 312 falhas, 02:10–02:41 | Ban 24h (aprovado) |
| 2 | Médio | Média | Scan de paths em /.env, /wp-admin | 88 req, 404 | Monitorar |

## Top talkers
| IP | Requisições | % | Status dominante | Observação |
|----|-------------|---|------------------|------------|

## Autenticação
- Falhas: {n} ({Δ vs. ontem})
- Sucessos: {n}
- Novos IPs com sucesso: {n} — {lista}

## Bans ativos
| IP | Jail | Desde | Expira |
|----|------|-------|--------|

## Não observado
- {ex.: nenhuma conexão de saída atípica; nenhum arquivo novo no webroot}

## Próximo passo
{ação única e concreta}
```

---

## 2. Relatório de incidente

```markdown
# Incidente {ID} — {título curto}

| | |
|---|---|
| **Severidade** | Crítico |
| **Estado** | {em contenção / contido / erradicado / encerrado} |
| **Detectado em** | {timestamp} |
| **Contido em** | {timestamp} |
| **Duração** | {tempo} |
| **Hosts afetados** | {lista} |
| **Dados envolvidos** | {sim/não — se sim, classificar} |

## 1. Resumo executivo
{3–5 linhas. O que aconteceu, o que foi feito, qual o risco residual.}

## 2. Linha do tempo
| Hora (UTC) | Evento | Fonte |
|-----------|--------|-------|
| 21/10 14:07 | Primeiro crash de worker PHP | php-fpm.log |
| 21/10 14:09 | Requisição anômala para /index.php | access.log |

## 3. Vetor de entrada
- **Hipótese principal:** {ex.: CVE-2026-109618 — RCE no core do PHP}
- **Confiança:** {alta/média/baixa}
- **Evidência:** {citar}
- **Hipóteses descartadas:** {lista + por quê}

## 4. IoCs

### Rede
| Tipo | Valor | Contexto |
|------|-------|----------|
| IPv4 | 203.0.113.45 | Origem das tentativas |
| Domínio | exemplo.invalid | Destino de callback |

### Host
| Tipo | Valor | Contexto |
|------|-------|----------|
| Caminho | /var/www/html/up.php | Webshell suspeita |
| Hash SHA256 | {hash} | Arquivo coletado |
| Processo | /tmp/.x/xmrig | Mineração |

### Credenciais
- {quais credenciais devem ser rotacionadas}

## 5. Escopo do comprometimento
| Ativo | Acesso? | Evidência | Confiança |
|-------|---------|-----------|-----------|

## 6. Ações tomadas
| Hora | Ação | Executor | Resultado | Rollback |
|------|------|----------|-----------|----------|

## 7. Erradicação e recuperação
- [ ] Host reconstruído a partir de imagem limpa
- [ ] Credenciais rotacionadas
- [ ] Vetor fechado (patch / contenção / migração)
- [ ] Verificação pós-recuperação (7 dias)

## 8. Lições e preventivas
| Ação | Prioridade | Prazo | Responsável |
|------|-----------|-------|-------------|

## 9. Anexos
- Evidências coletadas (com hash e cadeia de custódia)
- Logs recortados da janela do incidente
```

---

## 3. Relatório de postura / hardening

```markdown
# Postura de segurança — {host} — {data}

**Score:** {0–100} ({Δ vs. última avaliação})
**Ambiente:** {SO, versão, stack, exposição}

## Top 5 correções (ordem de impacto)

| # | Correção | Risco atual | Esforço | Risco da mudança | Rollback |
|---|----------|-------------|---------|------------------|----------|
| 1 | Desabilitar login root via SSH | Alto | 5 min | Baixo | Reverter linha no sshd_config |
| 2 | Restringir acesso ao PHP legado por IP | Crítico | 15 min | Médio (usuários externos) | Remover bloco allow/deny |

## Detalhamento

### SSH
| Verificação | Estado | Esperado | Evidência |
|-------------|--------|----------|-----------|
| PermitRootLogin | `yes` ❌ | `no` | `sshd -T` |
| PasswordAuthentication | `no` ✅ | `no` | `sshd -T` |

### Firewall
{...}

### Runtime e patches
| Componente | Versão | Estado | Observação |
|-----------|--------|--------|------------|
| PHP | 5.6.40 | EOL ❌ | Sem correção para CVE-2026-109618 |

### Permissões e segredos
{...}

### TLS
{...}

## Drift desde a última avaliação
| Item | Antes | Agora | Ação |
|------|-------|-------|------|

## O que está bem
{lista curta — reconhecer o que já está correto evita desmotivação}

## Limitações desta avaliação
- {ex.: sem acesso ao banco; sem baseline de tráfego}
```

---

## 4. Sumário executivo (para quem não é técnico)

```markdown
# Segurança — {sistema} — {data}

## Situação
{uma frase direta sem siglas: o que foi observado e o nível de ação necessário}

## O que isso significa para o sistema
{consequência possível, sem afirmar que aconteceu; explique as condições}

## O que sabemos e o que falta confirmar
- **Confirmado:** {fato observado e onde}
- **Ainda não confirmado:** {uso em produção / exposição / conta ativa / exploração}

## Próximo passo seguro
{uma verificação específica, o que ela confirma e se é somente leitura}

## O que precisa de decisão
| Decisão | Recomendação | Risco/impacto da mudança |
|---|---|---|

## Limites desta avaliação
{o que não foi analisado; não use “não houve ataque” se só analisou um recorte de log}

## Anexo técnico
{CVE, CVSS, caminhos/linhas, fontes, datas, comandos e link para relatório técnico}
```

---

## 5. Tabela de IoCs (padrão reutilizável)

| Tipo | Valor | Contexto | Confiança | Fonte |
|------|-------|----------|-----------|-------|
| IPv4 | | | | |
| IPv6 | | | | |
| Domínio | | | | |
| URL | | | | |
| User-Agent | | | | |
| Hash SHA256 | | | | |
| Caminho | | | | |
| Processo | | | | |
| Conta | | | | |

Ao exportar IoCs, **remova dados pessoais desnecessários** e informe a finalidade.

---

## 6. Relatório de vulnerabilidades do projeto

```markdown
# Vulnerabilidades conhecidas — {projeto} — {data}

## Resumo para você
{em português claro: o que foi encontrado, se há urgência e o que não está confirmado}

## O que isso pode significar
{impacto possível, explicando condições; não afirmar exploração ou vazamento sem evidência}

## Próximo passo seguro
{uma verificação concreta antes de atualizar, rotacionar segredo ou alterar produção}

## Detalhes técnicos
{veredito técnico, CVE/GHSA, CVSS, versões, evidência, fontes e datas}

## Cobertura
| Item | Valor |
|---|---|
| Dependências identificadas | {n} |
| Sem versão resolvida | {n} |
| Manifests lidos / encontrados | {n} / {n} |
| Fontes consultadas | OSV {data} · KEV {data} · EPSS {data} · NVD {data} |
| Código avaliado | PHP: {n} arquivos · outros: não avaliado |
| Host avaliado | não nesta execução |

## Achados prioritários
| Prioridade em palavras | O que foi encontrado | O que falta confirmar | Próxima verificação |
|---|---|---|---|

## Ordem de correção
1. {crítico + KEV + exposto}
2. {crítico/alto com patch}
3. {médio com EPSS alto}

## Não avaliado
- OWASP A01 (controle de acesso) e A06 (design)
- código fora de PHP
- camadas de imagem Docker
- zero-day e falha não publicada

## Próximo passo
{uma ação concreta, objetivo e indicação se é leitura/rede/alteração; dono e prazo só se conhecidos}

> Vulnerabilidade conhecida não é comprometimento. Exploração exige correlação com log e host.
```
