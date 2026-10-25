<!-- gaara-module
id: hardening-linux
version: 1.0
requires: [finding-schema, severity-matrix, safe-operations]
scripts: [harden_check]
-->

# Hardening Linux e Detecção de Drift

> Este módulo responde a "meu servidor está endurecido?" com **evidência**, **score explicável** e **drift desde um baseline**. Ele não altera nada. Toda correção sugerida é uma recomendação que exige aprovação.

---

## 1. O que este módulo faz

O `scripts/harden_check.py` faz uma auditoria **somente leitura** de um host Linux. Ele coleta:

- configuração efetiva do SSH (`sshd -T` quando disponível; senão, o arquivo);
- firewall local (UFW, nftables, firewalld, iptables);
- parâmetros de kernel e de rede em `/proc/sys`;
- permissões de arquivos sensíveis (`/etc/shadow`, chaves SSH, sudoers, `/root`, `/etc/ssl/private`);
- contas com UID 0;
- protocolos TLS em Nginx/Apache;
- containers Docker publicados, privilegiados, em rede do host e socket;
- portas de banco/admin escutando em todas as interfaces;
- estado de atualizações (`reboot-required`, `unattended-upgrades`);
- opcionalmente, permissão de `.env` e arquivos de configuração da aplicação.

Ele **não**:

- executa `sudo`, instala pacote, reinicia serviço ou edita configuração;
- roda scanner de vulnerabilidade ou consulta CVE;
- substitui auditoria de compliance, pentest ou revisão de código.

O resultado é um **JSON no schema de achado** (`finding-schema.md`) ou um relatório Markdown em português.

---

## 2. Como executar

```bash
# Relatório legível
./scripts/harden_check.py --format md --output /tmp/postura.md

# Inventário inicial (primeira execução é baseline, não anomalia)
./scripts/harden_check.py --write-baseline /tmp/gaara-baseline.json

# Comparar com o baseline
./scripts/harden_check.py --baseline /tmp/gaara-baseline.json --format md

# Aplicação específica: checa permissão de .env/config
./scripts/harden_check.py --app-root /var/www/app --format md

# Imagem/rootfs offline (não executa comandos do host)
./scripts/harden_check.py --root /mnt/imagem --format md
```

Para reprodutibilidade em teste:

```bash
./scripts/harden_check.py --now 2026-10-25T12:00:00Z --host srv-legado
```

Códigos de saída: `0` sem achado alto/crítico; `1` erro ou baseline inválido; `2` uso incorreto; `3` há achado alto/crítico.

### 2.1 Flags

| Flag | Efeito |
|---|---|
| `--root DIR` | audita uma árvore alternativa; donos não são avaliados e comandos são desativados |
| `--app-root DIR` | inclui permissão de `.env`, `wp-config.php`, `config.php` etc. |
| `--ssh-config PATH` | usa outro `sshd_config` (relativo à raiz) |
| `--baseline PATH` | compara o estado atual com um baseline e reporta drift |
| `--write-baseline PATH` | grava o inventário atual em JSON `0600` |
| `--no-commands` | não executa `sshd`, `ufw`, `nft`, `iptables`, `ss`, `docker` |
| `--redact on/off` | redação de segredos; `off` exige `--redact-off-reason` |

`--root` desativa comandos do host de propósito: misturar arquivos de uma imagem com o `docker ps` do host produziria um relatório enganoso.

---

## 3. Score

O score é **relativo aos controles avaliados**, não uma nota absoluta de segurança.

1. Cada controle tem um peso.
2. `fail` perde o peso inteiro; `warn` perde metade.
3. `pass` não perde; `unknown` e `na` não entram no peso avaliado.
4. `score = round(100 * (peso_avaliado - perda) / peso_avaliado)`.
5. Se menos de 40% do peso total foi avaliado, o score é `null` (`insuficiente`). Isso evita "100/100" porque o script não conseguiu ler nada.

No relatório aparecem:

- **Score:** 0–100 ou "não calculado";
- **Cobertura:** peso avaliado / peso total;
- **Veredito:** `estavel`, `atencao` ou `incidente`, derivado dos achados;
- **Top 5 correções:** priorizadas por severidade e peso.

Faixas de leitura (heurística, não certificação): 90–100 boa; 70–89 razoável; 40–69 fraca; 0–39 crítica. O veredito e os achados mandam mais que o número.

### 3.1 Pesos e severidades

| Controle | Peso | Falha |
|---|---:|---|
| `ssh.permit_root_login` | 10 | alto (chave/senha de root) |
| `ssh.password_authentication` | 10 | alto |
| `ssh.permit_empty_passwords` | 15 | crítico |
| `ssh.max_auth_tries` | 5 | médio (5–6 é aviso baixo) |
| `ssh.pubkey_authentication` | 5 | médio |
| `ssh.x11_forwarding` | 2 | aviso baixo |
| `firewall.enabled` | 12 | alto |
| `kernel.aslr` | 8 | alto (0) / médio (1) |
| `net.syncookies` | 4 | médio |
| `net.accept_redirects` | 5 | médio |
| `net.rp_filter` | 3 | baixo |
| `fs.protected_links` | 5 | médio |
| `kernel.info_leak` | 3 | aviso baixo |
| `perm.shadow` | 15 | crítico |
| `perm.passwd` / `perm.group` | 10 / 5 | crítico / alto |
| `perm.sudoers` | 6 | crítico se gravável; aviso se modo frouxo |
| `perm.root_home` | 4 | médio |
| `perm.sshd_config` | 6 | crítico se gravável |
| `perm.ssh_host_keys` | 10 | crítico |
| `perm.ssl_private` | 6 | alto |
| `accounts.uid0` | 15 | crítico |
| `secrets.app_files` | 8 | alto (somente com `--app-root`) |
| `tls.protocols` | 8 | alto (TLS 1.0/1.1/SSL) |
| `docker.socket` | 8 | crítico se outro escreve; alto se outro lê |
| `docker.published_high_risk` | 12 | alto |
| `docker.published_app` | 4 | aviso médio |
| `docker.privileged` | 8 | alto |
| `docker.host_network` | 6 | alto |
| `net.listening` | 10 | alto |
| `updates.reboot` | 4 | aviso médio |
| `updates.unattended` | 2 | aviso baixo |

Controles não aplicáveis (por exemplo, sem SSH instalado) não são inventados nem penalizados; entram como `unknown`/`na` e aparecem em "Não observado".

---

## 4. O que cada bloco verifica

### 4.1 SSH

- Usa `sshd -T` se o binário estiver disponível e acessível; isso mostra a configuração **efetiva**, incluindo `Include` e defaults da distribuição.
- Se não for possível, lê `sshd_config` e `Include` recursivamente, com **primeiro valor vencendo** (semântica do OpenSSH). Blocos `Match` são anotados e não avaliados.
- Verifica: root login, senha, senha vazia, `MaxAuthTries`, chave pública e X11.
- Sem `sshd` nem arquivo, o bloco é `unknown`, não "seguro".

Cuidado: `PermitRootLogin prohibit-password` é tratado como **aviso**, não como falha; ainda permite root por chave. `PasswordAuthentication no` não protege se o serviço real for outro SSH ou se houver outro caminho de administração.

### 4.2 Firewall

- Lê `ENABLED` em `/etc/ufw/ufw.conf` e, quando possível, `ufw status`.
- Procura regras em `nft`, `iptables` e `firewalld`.
- `ufw` configurado como habilitado mas sem status efetivo é **pass com confiança média**, não prova de bloqueio.
- Firewall de nuvem/security group **não é visível**; o relatório sempre ressalva isso.
- O script nunca executa `ufw enable`; a recomendação avisa do risco de lockout e exige acesso de console.

### 4.3 Kernel e rede

- ASLR (`randomize_va_space`) 0 é alto; 1 é aviso.
- SYN cookies, redirects ICMP, reverse path filter e proteções de hardlink/symlink.
- `kptr_restrict`/`dmesg_restrict` são avisos baixos de exposição de informação.
- Mudanças de sysctl são sensíveis; o relatório mostra comando e rollback, mas nada é aplicado.

### 4.4 Permissões

- `/etc/shadow`: qualquer acesso de outros, escrita de grupo ou dono/grupo inesperado é crítico. Grupo aceito: `root` ou `shadow`.
- `/etc/passwd`, `/etc/group`: escrita de grupo/outros é crítica.
- `/etc/sudoers`: escrita é crítica; modo diferente de 0440/0400 é aviso. Grupo deve ser root no host real.
- `/root`: acesso de grupo/outros é médio.
- `sshd_config`: escrita de grupo/outros é crítica.
- Chaves `ssh_host_*_key`: leitura/escrita por outros é crítica; grupo deve ser root.
- `/etc/ssl/private`: acesso de outros é alto.
- UID 0 extra é crítico; a recomendação é **investigar/escalar**, não remover a conta automaticamente.
- Em `--root`, donos e grupos não são avaliados (a árvore pode ter sido montada por outro usuário). O relatório registra essa limitação.

### 4.5 TLS

- Lê `ssl_protocols` (Nginx) e `SSLProtocol` (Apache) em configurações habilitadas.
- Sinaliza TLS 1.0/1.1/SSL como alto.
- `all -SSLv3 -TLSv1 -TLSv1.1` é reconhecido como moderno; `all` sem negar os antigos é aviso.
- Não avalia ciphers, curvas, HSTS, validade de certificado ou cadeia. Para isso use `openssl s_client`, `certbot certificates` e o monitoramento de expiração. Se o TLS termina em proxy/CDN, o host pode não ter configuração local e o controle é `na`.

### 4.6 Docker e portas

- `docker ps` identifica portas publicadas em `0.0.0.0`/`[::]`.
- Portas de banco/admin (MySQL, PostgreSQL, Redis, Mongo, Elasticsearch, memcached, RabbitMQ, Docker API, RDP/VNC etc.) são alto.
- Outras portas publicadas (por exemplo 8080/8081/8501) são **aviso médio**: podem ser o acesso público desejado.
- `docker inspect` sinaliza `Privileged=true` e `NetworkMode=host`.
- Socket Docker com escrita de outros é crítico; leitura de outros é alto. Pertencer ao grupo `docker` já equivale a root — revise quem está no grupo.
- `ss -lntH` cobre serviços fora do Docker; `/proc/net/tcp{,6}` é fallback. Portas já atribuídas ao Docker são deduplicadas.

### 4.7 Atualizações

- `reboot-required` é aviso médio; não reinicia nada.
- `unattended-upgrades` desabilitado é aviso baixo.
- O script **não** consulta CVE, não baixa metadata e não substitui `apt list --upgradable`/`needrestart`. Para emergência de CVE, use `emergency-cve.md`.

---

## 5. Baseline e drift

### 5.1 Primeira execução é inventário

Sem baseline, o relatório mostra o estado atual. Não há "anomalia" — só inventário. A gravação é explícita:

```bash
./scripts/harden_check.py --write-baseline /tmp/gaara-baseline.json
```

O arquivo é JSON, modo `0600`, e contém apenas valores de controle (sem segredo, sem conteúdo de `.env`). O script recusa gravar em symlink e exige que o diretório exista.

### 5.2 Segunda execução detecta mudança

```bash
./scripts/harden_check.py --baseline /tmp/gaara-baseline.json --format md
```

O JSON inclui `summary.drift`:

```json
{
  "changed": 1,
  "regressions": 1,
  "improvements": 0,
  "score_before": 92,
  "score_after": 84,
  "score_delta": -8,
  "items": [
    {
      "key": "secrets.app_files",
      "before": "segredos sem acesso de outros",
      "after": ".env modo=0644",
      "direction": "regressao"
    }
  ]
}
```

Direções: `regressao` (pass → fail/warn), `melhoria` (fail/warn → pass), `alteracao` (valor mudou sem trocar de faixa), `nao_avaliado` (controle ficou desconhecido/removido).

O baseline deve ser versionado fora do host ou em local controlado. Baseline de outro host é aceito, mas o relatório avisa; não trate drift entre hosts diferentes como incidente.

### 5.3 O que o drift não detecta

- Mudança de conteúdo de arquivo que não altera o valor do controle (ex.: uma regra de firewall adicionada fora do que o parser lê).
- Novo container sem porta publicada.
- Novo usuário sem UID 0.
- Alteração de código da aplicação.
- Ataque em andamento.

Drift é **regressão de configuração observável**, não detecção de intrusão. Combine com `log_triage.py` e `ir_triage.sh`.

---

## 6. Correções: como recomendar

Toda recomendação de mudança deve incluir:

1. **Evidência** do controle e o valor atual.
2. **Impacto** em uma frase para não especialista.
3. **Comando copiável**, quando seguro.
4. **Risco da mudança** (ex.: lockout, cliente antigo, serviço sem TLS).
5. **Rollback** (backup + reload).
6. **Aprovação explícita** na mesma sessão.

Exemplos:

| Achado | Correção segura | Risco | Rollback |
|---|---|---|---|
| root login SSH | `PermitRootLogin no`, testar `sshd -t`, recarregar | perder acesso se não houver outro usuário/chave | restaurar backup e recarregar |
| firewall desabilitado | `ufw default deny incoming`, liberar SSH, `ufw enable` | lockout se a porta SSH não for liberada | `ufw disable` via console |
| ASLR 0 | `sysctl -w kernel.randomize_va_space=2` + persistir | baixo | voltar valor antigo |
| `/etc/shadow` 0644 | `chmod 0640` e `chown root:shadow` | baixo | restaurar backup |
| container com DB publicado | remover `ports:` do compose e recriar, ou `ufw deny <porta>/tcp` | app deixa de ser acessado | restaurar compose/regra |
| TLS 1.0 | `ssl_protocols TLSv1.2 TLSv1.3` + reload | cliente antigo perde acesso | backup + reload |
| UID 0 extra | bloquear conta e investigar antes de remover | pode quebrar automação | reverter bloqueio |

Nunca aplique todas as correções de uma vez. Uma mudança por vez, com evidência preservada e rollback testado.

---

## 7. Limitações declaradas

- **Heurístico.** Score e pesos não são certificação; são priorização.
- **Somente leitura.** Não corrige, não instala, não reinicia, não usa sudo.
- **Cobertura parcial.** Sem permissão de root, `ufw status`, `nft`, `iptables`, `ss` e Docker podem ficar `unknown`.
- **`--root`** não avalia donos/grupos e desativa comandos; é para imagem/rootfs, não para substituir auditoria do host vivo.
- **Firewall externo** (security group, proxy, CDN) não é visto.
- **TLS** cobre protocolos em Nginx/Apache; não cobre certificado, ciphers, HSTS ou terminação em proxy.
- **Docker** cobre portas publicadas, privilégio e rede do host; não faz scan de imagem nem análise de vulnerabilidade de dependência.
- **Atualizações** cobre estado local, não CVE nem changelog.
- **Aplicação** só é olhada com `--app-root` e apenas permissão de arquivos de segredo comuns; conteúdo não é lido.
- **Drift** é de configuração observável, não de comportamento ou intrusão.

Para CVE, EOL e código PHP, use `emergency-cve.md`, `legacy-stacks.md` e `php_audit.py`.
