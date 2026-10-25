<!-- gaara-module
id: legacy-stacks
version: 1.1
requires: [finding-schema, severity-matrix]
scripts: [php_audit]
-->

# Stack Legada e Fim de Vida (EOL)

> Regra que governa este arquivo (R7): **se não existe patch, não existe "aplique o patch".** Diga isso na primeira resposta. O caminho é conter, isolar, monitorar e migrar.

---

## 1. O que "EOL" significa na prática

Fim de vida (*end of life*) significa que o projeto não emite mais correção de segurança. Não é "versão antiga"; é **versão que continuará vulnerável para sempre**.

| Runtime | Fim do suporte de segurança |
|---|---|
| PHP 5.6 (última da linha 5) | dez/2018 |
| PHP 7.0 | jan/2019 |
| PHP 7.1 | dez/2019 |
| PHP 7.2 | nov/2020 |
| PHP 7.3 | dez/2021 |
| PHP 7.4 | nov/2022 |
| PHP 8.0 | nov/2023 |
| PHP 8.1 | dez/2025 |
| PHP 8.2 | dez/2026 |
| PHP 8.3 | dez/2027 |
| PHP 8.4 | dez/2028 |

O mesmo raciocínio vale para Python 2, Node antigo, Java 8 sem vendor LTS, MySQL 5.7, OpenSSL 1.0.

### 1.1 Consequência que muita gente ignora

Uma falha **no interpretador** não é corrigível pela aplicação. Não adianta revisar o código, usar prepared statements ou "tirar o `eval`". Se a corrupção acontece antes do seu código rodar — como no PHP2Shell —, nenhuma prática de programação protege.

### 1.2 EOL não é monolítico

"Sem suporte" não significa a mesma coisa para todo branch. Antes de dizer "não há correção", identifique qual dos três casos:

| Caso | Exemplo | O que existe |
|---|---|---|
| Sem backport, sem perspectiva | PHP 5.x | Nada. Migrar ou conter |
| Backport mínimo do projeto | PHP 7.4, 8.0 e 8.1 no PHP2Shell | Código-fonte em branch específico; exige compilar. Não é release nem pacote |
| Backport de distribuição / LTS | RHEL, Ubuntu ESM, Debian LTS | Pacote atualizado pelo vendor; confira o changelog |

Dizer "EOL, logo não há patch" para um 7.4 que recebeu backport de fonte é tão errado quanto dizer "tem patch" para um 5.6. Confirme **por branch**, no boletim.

---

## 2. Estrutura de decisão

Pergunte, nesta ordem:

1. **Está exposto à internet?**
2. **Que dados ele toca?** (pessoal, financeiro, credencial, nenhum)
3. **Existe caminho de migração em quanto tempo?** (dias, semanas, meses, nunca)
4. **Há indício de comprometimento?**

| Exposição | Dados sensíveis | Migração viável | Estratégia |
|---|---|---|---|
| Internet aberta | Sim | > 30 dias | **Conter hoje**: autenticação na frente ou IP allowlist. Tratar como risco crítico aceito formalmente |
| Internet aberta | Não | > 30 dias | Conter + WAF + isolamento; prazo de migração |
| Internet aberta | Qualquer | ≤ 30 dias | Migrar com urgência; conter no intervalo |
| Restrito (VPN/interno) | Qualquer | meses | Isolar, monitorar, planejar migração |
| Restrito | Não | anos | Aceitar risco documentado + isolamento |

**"Aceitar o risco" só é legítimo se estiver escrito, com dono e prazo.** Risco aceito verbalmente é risco ignorado.

---

## 3. Controles compensatórios (em ordem de eficácia)

### 3.1 Nível 1 — Reduzir exposição

O controle mais eficaz, e o mais barato.

```nginx
# Nginx: restringir por IP na frente do vhost legado
location / {
    allow 203.0.113.0/24;   # VPN / escritório
    allow 198.51.100.10;    # IP administrativo
    deny all;
    proxy_pass http://127.0.0.1:8080;
}
```

Ou autenticação na borda (Basic Auth, mTLS, SSO via proxy). Se o sistema é interno, isso resolve a maior parte do risco.

### 3.2 Nível 2 — Isolar o processo

Assuma que a execução de código vai acontecer. O objetivo passa a ser **limitar o que o atacante consegue fazer depois**.

| Controle | Efeito |
|---|---|
| Container com FS read-only | Impede persistência por arquivo |
| Usuário não-root, sem capabilities | Reduz escalada |
| **Sem saída de rede** (egress deny) | Mata reverse shell e exfiltração |
| AppArmor/seccomp negando `execve` | Impede execução de shell — o mais forte |
| `open_basedir` | Limita leitura de arquivo |
| Pool FPM separado por vhost | Isola entre aplicações |
| `/tmp` com `noexec,nosuid,nodev` | Impede binário em tmp |

Exemplo de egress restrito (iptables):

```bash
# Permitir apenas DNS e repositórios; bloquear o resto da saída
iptables -A OUTPUT -m owner --uid-owner www-data -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner www-data -p tcp --dport 443 -d 198.51.100.0/24 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner www-data -j REJECT
```

### 3.3 Nível 3 — `php.ini` endurecido

```ini
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log
allow_url_include = Off
allow_url_fopen = Off
open_basedir = /var/www/app:/tmp
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork,dl,symlink,link,posix_kill,posix_setuid
session.use_strict_mode = 1
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Lax
upload_max_filesize = 4M
post_max_size = 8M
max_execution_time = 30
```

**Limitações honestas:**
- `disable_functions` **não é fronteira de segurança** — há bypass conhecido via `putenv`/`LD_PRELOAD` e via extensões.
- `allow_url_fopen=Off` quebra integrações; teste antes.
- `open_basedir` deve incluir diretório de sessão e de upload, senão a aplicação quebra.

### 3.4 Nível 4 — WAF

ModSecurity + OWASP CRS reduz ruído e bloqueia payloads conhecidos. **Não protege contra corrupção de memória no interpretador.** Serve para o que vem depois: download de ferramenta, webshell, callback.

### 3.5 Nível 5 — Monitoração

Sem detecção, contenção é fé. Mínimo viável:
- alerta de `SIGSEGV`/OOM em worker;
- alerta de processo filho do servidor web;
- alerta de conexão de saída da conta de serviço;
- alerta de arquivo novo no webroot;
- revisão semanal de log (rotina de triagem).

### 3.6 Mitigação específica de CVE ativo

Os controles 3.1–3.5 reduzem o raio de dano, mas **não bloqueiam caminho de exploração conhecido**. Quando existe CVE ativo no runtime, há uma camada adicional:

- Consulte `emergency-cve.md` §10.1, que lista as mitigações parciais documentadas pelo fornecedor, com escopo declarado.
- Exemplo — PHP2Shell em runtime EOL:
  - `php_admin_flag[session.upload_progress.enabled] = off` — bloqueia os caminhos de sessão confirmados, não variantes.
  - `memory_limit = -1` via `php_admin_value`, com limite de cgroup como fronteira de disponibilidade.
  - `post_max_size` baixo e `upload_max_filesize` menor que ele.
- Aplique com `php_admin_*`, nunca `ini_set()`. Reinicie os workers.
- Nenhuma delas substitui a correção — e em runtime EOL não existe correção.

Não responda "não há nada a fazer até migrar". Isso é falso e induz à inação.

---

## 4. `mod_php` vs `PHP-FPM`

| | `mod_php` | `PHP-FPM` |
|---|---|---|
| Onde roda | Dentro do processo Apache | Processo separado por pool |
| Impacto de crash | Derruba o Apache inteiro | Afeta o pool |
| Isolamento entre vhosts | Fraco | Bom (pools distintos) |
| Exploração antes do app | Sim, no processo do servidor | Sim, no worker |
| Recomendação | Evitar em legado exposto | Preferir |

Migrar de `mod_php` para FPM já reduz o raio de dano, mesmo sem trocar a versão do PHP.

---

## 5. Padrões perigosos em código PHP antigo

Lista de verificação para revisão manual ou para o `php_audit.py`:

### Execução e inclusão
- `eval()`, `assert()` com string, `create_function()`
- `preg_replace()` com modificador `/e`
- `include`/`require` com `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
- `include` com extensão `.inc` acessível via web
- `unserialize()` de dado de usuário (object injection)
- `$$variavel`, `extract()` sem allowlist de chaves

### Banco de dados
- `mysql_query()` com concatenação
- `mysqli_query()` / `PDO::query()` com interpolação
- Ausência de prepared statements

### Arquivo e upload
- `move_uploaded_file()` sem validar extensão e MIME real
- Upload para diretório dentro do webroot com execução permitida
- `file_get_contents()`/`readfile()` com path de usuário
- Download por parâmetro `file=`

### Sessão e autenticação
- `md5()` / `sha1()` para senha
- Comparação com `==` em hash (type juggling)
- Session ID em URL
- Ausência de `session_regenerate_id()` no login
- Cookie sem `HttpOnly`/`Secure`

### Configuração
- Credencial em repositório (`.env`, `config.php` versionado)
- `display_errors=On` em produção
- `register_globals` dependido implicitamente
- `error_reporting` expondo caminho interno
- Backup acessível (`/backup.zip`, `/db.sql`, `*.bak`)

### Sintaxe incompatível com PHP 8 (bloqueia migração)
- `mysql_*`, `ereg*`, `split()`, `each()`, `create_function()`
- `mcrypt_*`
- Construtor estilo PHP 4
- Short tags `<?`
- `{}` para acesso a índice de string

### 5.1 Auditoria automatizada

```bash
python3 scripts/php_audit.py /var/www/app --format md
python3 scripts/php_audit.py app/ --include-vendor --output /tmp/php-audit.json
```

O script é **somente leitura** e cobre o subconjunto lexical de alto sinal:

- execução controlada por request (`eval`, `system`, `unserialize`, `preg_replace /e`);
- inclusão de arquivo, `extract()` e SQL concatenado com superglobal;
- upload sem validação visível;
- segredos literais em PHP, `.env` e `Dockerfile`, hash rápido de senha e chave privada;
- runtime PHP 5/7 em `composer.json`, `Dockerfile`, `.php-version` e `.tool-versions`;
- funções removidas no PHP 7/8, `$HTTP_RAW_POST_DATA` e acesso com `$var{0}`.

Ele **não** segue fluxo entre arquivos, não executa o código e não substitui um parser completo. Ficam para revisão manual: construtor estilo PHP 4, short tags, `assert()` com string, `$$variavel`, validação em runtime e lógica de negócio. `vendor/` é ignorado por padrão; use `--include-vendor` para auditar dependências instaladas.

Achados de EOL usam a ação `migrate` e segredos usam `rotate-credential`: ambos exigem aprovação explícita e rollback. O script não executa nenhuma das duas coisas.

---

## 6. Caminho de migração

### 6.1 Medir antes de prometer

```bash
# 1. Inventário de incompatibilidades (PHP 7/8)
composer require --dev phpcompatibility/php-compatibility
vendor/bin/phpcs -p . --standard=PHPCompatibility --runtime-set testVersion 8.3

# 2. Automação de parte da conversão (avaliar caso a caso)
composer require --dev rector/rector
vendor/bin/rector process src --dry-run
```

### 6.2 Estratégia

| Situação | Abordagem |
|---|---|
| App pequena (< 20k linhas) | Migração direta em branch, com testes |
| App média | Container com PHP 8 + correção incremental por módulo |
| App grande / sem testes | **Estrangulamento**: proxy na frente, migrar rota por rota, manter legado atrás de autenticação |
| App sem código-fonte ou com encoder | Reescrita; não há migração possível |

### 6.3 Ordem segura

1. Congelar features (só correção crítica).
2. Criar ambiente de homologação com PHP 8.
3. Rodar análise de compatibilidade e estimar esforço.
4. Corrigir bloqueios (`mysql_*` primeiro).
5. Testar fluxo crítico, não "a aplicação toda".
6. Migrar com *canary* e rollback pronto.
7. Desligar o legado — **não deixar rodando "por garantia"**, porque vira o elo mais fraco.

---

## 7. O que não fazer

| Prática | Por que é ruim |
|---|---|
| Instalar "patch" de origem desconhecida | Backdoor garantida |
| Compilar fork não oficial do PHP | Sem auditoria, sem suporte, risco alto |
| "Só desabilitar a função vulnerável" | Não funciona contra corrupção no core |
| Esconder atrás de CDN e considerar resolvido | Camada extra, não correção |
| Confiar em `disable_functions` como fronteira | Bypass conhecido |
| Manter o legado acessível "para o cliente antigo" | Vetor permanente |
| Aceitar risco sem registrar | Risco invisível para a organização |

---

## 8. Registro de risco aceito (obrigatório)

```markdown
# Aceite de Risco — {sistema}

- **Ativo:** {host / aplicação}
- **Vulnerabilidade:** {CVE / classe de falha}
- **Por que não corrigimos agora:** {motivo técnico ou de negócio}
- **Controles compensatórios ativos:** {lista + data de verificação}
- **Risco residual:** {alto / médio / baixo} — {justificativa}
- **Dono do risco:** {nome / cargo}
- **Prazo de revisão:** {data}
- **Plano de saída:** {migração / descomissionamento} até {data}
```

Sem dono e sem prazo, não é aceite de risco — é negligência documentada.
