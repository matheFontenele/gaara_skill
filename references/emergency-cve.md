<!-- gaara-module
id: emergency-cve
version: 1.0
requires: [severity-matrix, safe-operations, legacy-stacks]
scripts: []
-->

# Resposta a CVE Emergencial

> Rotina para quando sai uma vulnerabilidade crítica e você precisa decidir rápido: **eu sou afetado? o que faço nas próximas horas?**
> Objetivo: sair de "notícia assustadora" para "decisão registrada" em menos de 30 minutos.

---

## 1. Quando usar

- CVE crítico (CVSS ≥ 9) em componente que você usa.
- Divulgação com exploração ativa confirmada.
- Aviso de fornecedor, CERT ou distribuição.
- Suspeita de comprometimento compatível com CVE recém-divulgado.

## 2. Quando **não** usar

- CVE sem componente correspondente no seu inventário → registrar e encerrar.
- Vulnerabilidade que exige acesso já privilegiado, em sistema não exposto → tratar no ciclo normal.
- Boletim sem fonte primária (blog aleatório, grupo de Telegram) → confirmar antes de agir.

---

## 2.1 Regras de evidência externa

Esta rotina vive de fatos que **não estão no seu host**: número de CVE, versão corrigida, data, atribuição, mitigação oficial. Errar aqui é pior do que errar num log, porque a decisão seguinte custa dinheiro e disponibilidade.

### Hierarquia de fonte

1. **Boletim do fornecedor** (ex.: `php.net/archive`).
2. **Registro oficial** (NVD/CVE, CERT nacional).
3. **Distribuição** (advisory do Debian/Ubuntu/RHEL).
4. **Fornecedor de LTS/backport** (quando aplicável).
5. **Imprensa especializada** — só para contexto, nunca como base de decisão.

Se a informação não está em 1–3, ela não é fato ainda.

### Regras

- **Nunca cite número de CVE que você não leu.** Se não tem certeza, diga: "não tenho fonte para esse CVE".
- **Separe o que é afirmado do que é inferência.** "O fornecedor afirma X" ≠ "eu deduzo X".
- **Mitigação só se estiver no boletim.** E, mesmo assim, rotule como redução de dano.
- **Nunca transforme mitigação em correção.** Se o fornecedor diz "nenhuma configuração mitiga", diga exatamente isso.
- **Declare a data da informação.** O leitor precisa saber se você leu o boletim hoje ou semana passada.
- **Versão afetada precisa de certeza.** "Provavelmente afetado" é confiança baixa, não fato.

### Frases proibidas e o que dizer no lugar

| Não diga | Diga |
|---|---|
| "Desabilitar X fecha a exploração." (sem escopo) | "Desabilitar X bloqueia os caminhos confirmados de {CVE}, segundo {fonte}; não cobre variantes e não substitui a correção." |
| "Não existe mitigação." | "Não existe **correção**. Mitigações parciais documentadas: X, Y. Nenhuma torna a instalação segura." |
| "Também existe o CVE-2026-XXXXX." | "Não tenho fonte para esse CVE; vou verificar antes de citar." |
| "A exploração acontece desde antes do patch." | "Exploração confirmada a partir de {data}, segundo {fonte}." |
| "Aplique o patch no PHP 5." | "Não existe patch para PHP 5 e não vai existir." |
| "O CERT recomenda..." | "O CERT publicou {recomendação} em {data} — {URL}." |
| "Provavelmente é explorável." | "Confiança média: o fornecedor não testa esse branch; a inferência vem do código de ciclo de request." |

---

## 3. Fases e prazos

| Fase | Prazo | Objetivo |
|---|---|---|
| **I. Inventário** | 0–30 min | Onde isso existe? |
| **II. Exposição** | 0–30 min | Quem alcança? |
| **III. Contenção** | 0–2 h | Reduzir janela de risco |
| **IV. Verificação** | 0–4 h | Já fomos explorados? |
| **V. Correção/Migração** | 1–30 dias | Fechar o vetor |
| **VI. Registro** | contínuo | Decisão rastreável |

---

## 4. Fase I — Inventário

Você não pode proteger o que não sabe que tem.

```bash
# PHP (host)
php -v 2>/dev/null
php -i 2>/dev/null | grep -i "Server API"
dpkg -l 2>/dev/null | grep -iE "php|libapache2-mod-php" \
  || rpm -qa 2>/dev/null | grep -i php

# Containers
docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null
docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null

# Processos em execução
ps -eo user,pid,cmd | grep -Ei "php|httpd|apache|nginx" | grep -v grep

# Versão dentro de um container específico
docker exec <container> php -v
```

**Não esqueça:** ambientes de homologação, cron, workers de fila, APIs internas, appliances com PHP embutido (painéis, NAS, câmeras), e o notebook do dev que roda o mesmo stack.

### 4.1 Planilha de inventário

| Host | Componente | Versão | SAPI/Modo | Exposto? | Dono | Ação |
|---|---|---|---|---|---|---|

---

## 5. Fase II — Exposição

Para cada ativo afetado, determine:

1. **Alcançável da internet?** (IP público, port forward, CDN)
2. **Requer autenticação?** (a maioria dos CVE críticos de RCE, não)
3. **Precisa de configuração específica?** (módulo, `mod_php`, extensão)
4. **Quem usa?** (cliente externo, interno, só bot)

A combinação **"exposto + sem autenticação + sem patch"** é o cenário que exige ação no mesmo dia.

---

## 6. Fase III — Contenção

Ordene por eficácia, não por facilidade.

### 6.1 Se existe correção oficial

1. Aplicar o patch.
2. **Reiniciar o serviço** — patch em disco sem restart não vale nada.
3. Verificar versão após o restart.
4. Confirmar que o processo em execução é o binário novo (não um worker antigo remanescente).

```bash
# Exemplo: verificar se o worker realmente reiniciou
systemctl status php8.3-fpm --no-pager
ps -eo pid,lstart,cmd | grep php-fpm
php -v
```

### 6.2 Se não existe correção (stack EOL)

Não existe configuração que **corrija**. Existem mitigações parciais documentadas pelo fornecedor — elas bloqueiam caminhos de ataque conhecidos, não a classe inteira. O CERT-EU é explícito: reduzem exposição a caminhos específicos, mas "não tornam a instalação segura".

| Ordem | Ação | Efeito |
|---|---|---|
| 1 | Restringir acesso por IP / VPN / autenticação na borda | Elimina a exposição — controle mais forte |
| 2 | Tirar do ar | Elimina o risco; custo de disponibilidade |
| 3 | Mitigação parcial documentada pelo fornecedor (ex.: `session.upload_progress.enabled=0`) | Bloqueia caminhos confirmados; não cobre variantes |
| 4 | WAF com regras virtuais | Reduz, não elimina |
| 5 | Isolamento (container, sem egress, read-only) | Limita o dano pós-exploração |
| 6 | Monitoração intensificada | Detecta, não previne |

**Nunca** apresente os itens 3–6 como equivalentes a patch. São redução de dano — e a diferença entre "bloqueia este caminho" e "cobre a classe" precisa estar escrita.

### 6.3 O que não fazer

- Baixar patch de fonte não oficial.
- Compilar fork aleatório.
- "Desabilitar a função vulnerável" quando a falha é no core.
- Confiar em CDN como solução.
- Reiniciar e considerar resolvido sem verificar exploração.

---

## 7. Fase IV — Verificação de exploração

Assuma que pode ter sido explorado. Procure **dois tipos** de sinal.

### 7.1 Sinais diretos do tipo de falha

| Tipo de CVE | Sinal |
|---|---|
| Corrupção de memória / RCE no interpretador | `SIGSEGV`, `AH00051`, OOM súbito, worker reiniciando |
| Injeção de comando | processo filho de shell do servidor web |
| Desserialização | objeto estranho em log, erro de classe |
| Path traversal | 200 em payload de traversal |
| Autenticação bypass | acesso a rota protegida sem login prévio |

### 7.2 Sinais indiretos de pós-exploração

```bash
# Processos filhos do servidor web
ps -ef --forest | grep -EA3 "apache2|httpd|php-fpm|php-cgi|nginx"

# Conexões de saída da conta de serviço
ss -tunp state established | grep -Ei "php|apache|www-data|nginx"

# Arquivos novos no webroot
find /var/www -type f -newermt "-7 days" -printf "%TY-%Tm-%Td %TH:%TM  %p\n" | sort

# Executáveis em diretórios temporários
find /tmp /var/tmp /dev/shm -type f -perm -u+x 2>/dev/null

# Persistência
crontab -l 2>/dev/null; ls -la /etc/cron.* 2>/dev/null
ls -la ~/.ssh /var/www/.ssh 2>/dev/null
```

### 7.3 Interpretação

| Resultado | Conclusão |
|---|---|
| Nenhum sinal + logs íntegros | Exploração não observada (não é prova de ausência) |
| Tentativas sem sucesso | Contenção funciona; manter |
| Qualquer sinal de pós-exploração | **Comprometimento.** Passar para resposta a incidente |
| Logs ausentes ou truncados | Tratar como suspeito; possível anti-forense |

**Importante:** ausência de sinal não prova ausência de comprometimento. Se não havia logging adequado, a resposta honesta é "não é possível afirmar".

---

## 8. Fase V — Correção ou migração

| Situação | Caminho |
|---|---|
| Patch oficial disponível | Aplicar e verificar |
| Versão EOL com backport de distribuição | Avaliar; documentar a origem |
| Versão EOL sem backport | Conter + plano de migração com prazo |
| Sistema sem código-fonte | Substituir; não há correção possível |

Ver `legacy-stacks.md` para o caminho de migração.

---

## 9. Fase VI — Registro

Toda decisão vira registro. Mínimo:

```markdown
# CVE-{ano}-{numero} — Decisão

- **Data da análise:**
- **Componente / versão:**
- **Afetado?** sim / não / parcial
- **Exposto?** internet / VPN / interno / offline
- **Correção disponível?** sim / não / backport
- **Ação tomada:** {contenção, patch, isolamento}
- **Exploração observada?** sim / não / inconclusivo
- **Confiança:** alta / média / baixa
- **Risco residual:**
- **Prazo de correção definitiva:**
- **Responsável:**
```

---

## 10. Exemplo trabalhado — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

| Item | Valor |
|---|---|
| Divulgação | 21/10/2026 |
| Tipo | RCE não autenticado no core do PHP |
| CVSS | 9.2 |
| Mecanismo | 109618: corrupção por falha de memória durante o setup do request. 109619: estado global que sobrevive ao request e é usado pelo próximo worker |
| Afetados | Toda instalação PHP que serve requisição: `mod_php`, PHP-FPM, `php-cgi`, LiteSpeed, FrankenPHP |
| PHP 5 | **Afetado, sem correção e sem backport** |
| PHP 7.4 / 8.0 / 8.1 | EOL, mas o PHP publicou backport **mínimo de código-fonte** para esta falha. Exige compilar; não é release nem pacote |
| Corrigido | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Mitigação por config | Nenhuma **corrige**. Existem mitigações parciais documentadas, com escopo limitado (ver 10.1) |
| Maior risco | `mod_php`, porque a exploração ocorre antes do código da aplicação |
| Terceiro CVE | CVE-2026-115560, divulgado em 23/10. Sem patch; exige configuração incomum de sessão |

### 10.1 Mitigações parciais documentadas

Fonte: CERT-EU Security Advisory 2026-018 (v1.2, 23/10/2026) e boletim do PHP.
Frase do próprio CERT-EU: *"Only an update fully fixes these vulnerabilities. The measures below reduce exposure to specific attack paths but do not make an installation safe."*

| CVE | Mitigação | Escopo real |
|---|---|---|
| 109618 (OOM) | `memory_limit=-1` via `php_admin_value`, impedindo override pela aplicação | Remove o gatilho controlável de OOM; falha de alocação subjacente ainda pode alcançar o código vulnerável |
| 109618 | `post_max_size` baixo (8M sem upload, 32M com) e `upload_max_filesize` menor | Reduz a superfície de parsing multipart |
| 109618 | Limites de tamanho, campos e partes no proxy | Complementa, não substitui |
| 109619 | `session.upload_progress.enabled=0` + restart de todos os workers | Bloqueia os caminhos de sessão confirmados, **não outras variantes** |
| 109619 | `fatal_error_backtraces=0` (PHP 8.5) | Bloqueia apenas o caminho confirmado de backtrace |
| 115560 | `session.upload_progress.enabled=0` até o próximo release regular | Proteção completa para esse vetor específico |

Regras de aplicação:

- Use `php_admin_flag` / `php_admin_value`. `ini_set()` não serve — e no 115560 ele é justamente parte do vetor.
- **Reinicie** todos os workers. Reload não basta.
- Verifique na SAPI que atende, não no CLI. Ver 10.3.
- Para disponibilidade, use limite de cgroup/container. **Não** use `RLIMIT_AS`/`RLIMIT_DATA`, que podem disparar a falha de alocação vulnerável.
- Nenhuma dessas medidas significa "resolvido". A correção é 8.2.35+, 8.3.36+, 8.4.27+ ou 8.5.12+.

### 10.2 SAPI: o risco não é o mesmo em todo lugar

Fonte: GHSA-w8hw-w9fx-j79w (PHP), consultado em 25/10/2026.

| SAPI | Situação no 109618 | Por quê |
|---|---|---|
| `mod_php` (Apache) | **Exploit completo validado** | O Apache chama o shutdown do request mesmo quando o startup falhou; o estado inválido é processado antes de qualquer código da aplicação |
| PHP-FPM | Suscetível por análise de código; **sem exploit completo demonstrado** | O FPM encerra o filho quando o startup falha, cortando o caminho |
| FrankenPHP | **Provavelmente suscetível** | Chama o shutdown incondicionalmente, como o `mod_php` |
| `php-cgi` / LiteSpeed (LSAPI) | Modela o FPM; exploit dependente da aplicação | Caminho específico, não validado |

Consequência prática: em `mod_php`, exposição à internet é urgência de horas. Em FPM continua crítico, mas o caminho conhecido não está demonstrado ponta a ponta — o que **não** autoriza relaxar.

### 10.3 Como descobrir a SAPI sem se enganar

`php -i` na CLI **sempre** responde `Command Line Interface`. Ele reporta a SAPI do próprio binário, não a do processo que atende.

```bash
# Debian/Ubuntu: quais SAPIs existem para a versão
phpquery -v 5.6 -s apache2; phpquery -v 5.6 -s fpm

# FPM
php-fpm5.6 -i | grep -i "Server API"

# Apache com mod_php
apache2ctl -M 2>/dev/null | grep -i php

# o que está realmente rodando
ps -eo user,pid,cmd | grep -Ei "php-fpm|apache2|httpd" | grep -v grep
```

Em container, rode **dentro** do container que atende — não no host.

### Aplicação da rotina

1. **Inventário:** versão no processo em execução + SAPI real (10.3). Em `mod_php`, prioridade máxima.
2. **Afetado:** qualquer versão < a corrigida da sua branch; PHP 5 sempre.
3. **Exposição:** internet aberta → contenção hoje.
4. **Contenção (PHP 5):** allowlist de IP ou autenticação na borda; egress bloqueado; FPM em vez de `mod_php` se possível.
5. **Verificação:** pico de `SIGSEGV` a partir de 21/10; processos filhos; conexões de saída; arquivos novos.
6. **Decisão:** migrar para 8.x em prazo definido; registrar risco aceito no intervalo.

**Frase que deve aparecer na resposta ao usuário:** *"Não existe correção para PHP 5 e não vai existir. O que reduz risco é tirar da exposição e isolar; o que resolve é migrar."*

---

## 11. Checklist final

- [ ] Inventário levantado (hosts, containers, homologação)
- [ ] Versões confirmadas no processo **em execução**, não só no disco
- [ ] Exposição classificada
- [ ] Correção oficial verificada
- [ ] Se EOL: contenção aplicada e prazo definido
- [ ] Exploração verificada em duas frentes (direta e indireta)
- [ ] Evidência preservada
- [ ] Registro de decisão escrito
- [ ] Responsável e prazo nomeados
