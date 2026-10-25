#!/usr/bin/env bash
# ir_triage.sh — coleta somente leitura de sinais de comprometimento.
#
# Não mata processo, não bloqueia rede, não apaga arquivo, não reinicia serviço.
# Tudo o que faz é ler, agregar, redigir e calcular hash do que encontrou.
#
# Uso:
#   ./ir_triage.sh
#   ./ir_triage.sh --output /tmp/ir.json
#   ./ir_triage.sh --root /mnt/imagem --format md
#   ./ir_triage.sh --since 14 --no-live
#
# Códigos de saída: 0 limpo | 1 erro | 2 uso | 3 achado alto/crítico

set -uo pipefail

VERSION="1.0"
TOOL="ir_triage"
ROOT="/"
OUTPUT=""
FORMAT="json"
SINCE_DAYS=7
LIVE="auto"
REDACT="on"
REDACT_REASON=""
WEBROOTS=()
TIMEOUT=15
MAX_WEB_FILES=3000
MAX_ITEMS=25

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Opções:
  --root DIR       analisa uma árvore alternativa (imagem montada, container parado)
  --webroot DIR    adiciona um diretório web a vasculhar (repetível)
  --output FILE    grava o relatório; também grava FILE.sha256 com o manifesto
  --format json|md saída (padrão: json)
  --since DIAS     janela de arquivos recentes (padrão: 7)
  --no-live        não lê processo, rede nem docker
  --redact on|off  redação de segredos (padrão: on); off exige justificativa
  --help           esta ajuda

Somente leitura. Requer bash, coreutils, find, grep, awk e python3.
Alguns sinais (processo, rede, docker) exigem root; sem root, o script
declara a limitação em vez de fingir que verificou.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="${2:-}"; shift 2 ;;
        --webroot) WEBROOTS+=("${2:-}"); shift 2 ;;
        --output) OUTPUT="${2:-}"; shift 2 ;;
        --format) FORMAT="${2:-}"; shift 2 ;;
        --since) SINCE_DAYS="${2:-}"; shift 2 ;;
        --no-live) LIVE="0"; shift ;;
        --redact) REDACT="${2:-}"; shift 2 ;;
        --redact-off-reason) REDACT_REASON="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "erro: opção desconhecida: $1" >&2; exit 2 ;;
    esac
done

case "$FORMAT" in json|md) ;; *) echo "erro: --format deve ser json ou md" >&2; exit 2 ;; esac
case "$REDACT" in on|off) ;; *) echo "erro: --redact deve ser on ou off" >&2; exit 2 ;; esac
if [ "$REDACT" = "off" ] && [ -z "$REDACT_REASON" ]; then
    echo "erro: --redact off exige --redact-off-reason" >&2
    exit 2
fi
case "$SINCE_DAYS" in ''|*[!0-9]*) echo "erro: --since deve ser um número de dias" >&2; exit 2 ;; esac
[ -d "$ROOT" ] || { echo "erro: --root não é diretório: $ROOT" >&2; exit 1; }
[ "$(uname -s 2>/dev/null)" = "Linux" ] || { echo "erro: escopo é Linux" >&2; exit 2; }

ROOT="$(cd "$ROOT" && pwd)"
if [ "$ROOT" = "/" ]; then R=""; else R="$ROOT"; fi
if [ "$ROOT" != "/" ] && [ "$LIVE" = "auto" ]; then LIVE="0"; fi
[ "$LIVE" = "auto" ] && LIVE="1"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gaara-ir.XXXXXX")" || exit 1
FINDINGS="$WORK/findings.tsv"
MANIFEST="$WORK/manifest.tsv"
: > "$FINDINGS"
: > "$MANIFEST"
trap 'rm -rf "$WORK"' EXIT

STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST="$(hostname 2>/dev/null || echo desconhecido)"
[ "$ROOT" != "/" ] && HOST="root:$ROOT"
UID_NOW="$(id -u 2>/dev/null || echo 1)"

clean() { printf '%s' "${1:-}" | tr '\n\r\t' '   ' | tr -d '\037'; }

emit() {
    # 16 campos separados por US (0x1f)
    local sev="$1" conf="$2" cat="$3" title="$4" src="$5" loc="$6" ex="$7"
    local imp="$8" act="$9" cmd="${10}" rb="${11}" tgt="${12}" fp="${13}"
    local nobs="${14}" mit="${15}" stype="${16}"
    printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
        "$(clean "$sev")" "$(clean "$conf")" "$(clean "$cat")" "$(clean "$title")" \
        "$(clean "$src")" "$(clean "$loc")" "$(clean "$ex")" "$(clean "$imp")" \
        "$(clean "$act")" "$(clean "$cmd")" "$(clean "$rb")" "$(clean "$tgt")" \
        "$(clean "$fp")" "$(clean "$nobs")" "$(clean "$mit")" "$(clean "$stype")" >> "$FINDINGS"
}

hash_file() {
    local path="$1" sum size mtime
    [ -f "$path" ] && [ -r "$path" ] || { printf 'indisponivel'; return; }
    sum="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')" || sum=""
    [ -n "$sum" ] || { printf 'indisponivel'; return; }
    size="$(stat -c '%s' -- "$path" 2>/dev/null || echo '?')"
    mtime="$(date -u -d "@$(stat -c '%Y' -- "$path" 2>/dev/null || echo 0)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo '?')"
    printf '%s\t%s\t%s\t%s\n' "$path" "$sum" "$size" "$mtime" >> "$MANIFEST"
    printf '%s' "$sum"
}

is_private() {
    case "$1" in
        10.*|127.*|192.168.*|169.254.*|::1|fe80:*|fc00:*|fd00:*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------- webshell

scan_webshells() {
    local roots=() f base sev conf note strong double writable suspicious
    if [ ${#WEBROOTS[@]} -gt 0 ]; then
        for candidate in "${WEBROOTS[@]}"; do
            # com --root, um caminho absoluto é interpretado dentro da árvore analisada
            if [ -n "$R" ]; then
                case "$candidate" in
                    "$R"/*) ;;
                    /*) candidate="$R$candidate" ;;
                esac
            fi
            [ -d "$candidate" ] && roots+=("$candidate")
        done
    else
        for candidate in "$R/var/www" "$R/srv/www" "$R/usr/share/nginx/html" \
                         "$R"/home/*/public_html "$R"/home/*/www "$R"/home/*/htdocs; do
            [ -d "$candidate" ] && roots+=("$candidate")
        done
    fi
    [ ${#roots[@]} -eq 0 ] && return

    local p1='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|gzuncompress)'
    local p2='(eval|assert|system|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*[$]_(POST|GET|REQUEST|COOKIE)'
    local p3='preg_replace[[:space:]]*\([^;]*/e'
    local p4='create_function[[:space:]]*\('
    local p5='[$]_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\('
    local p6='call_user_func(_array)?[[:space:]]*\([[:space:]]*[$]_(POST|GET|REQUEST|COOKIE)'

    local count=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        count=$((count + 1))
        [ "$count" -gt "$MAX_WEB_FILES" ] && break
        case "$f" in *.php|*.phtml|*.phar|*.php3|*.php4|*.php5|*.php7|*.inc|*.php.*) ;; *) continue ;; esac

        strong=0; double=0; writable=0; suspicious=0
        if grep -EIlq -e "$p1" -e "$p2" -e "$p3" -e "$p4" -e "$p5" -e "$p6" -- "$f" 2>/dev/null; then
            strong=1
        fi
        case "$f" in
            *.php.jpg|*.php.jpeg|*.php.png|*.php.gif|*.php.txt|*.php.pdf|*.php.zip|*.phtml.jpg|*.phar.jpg)
                double=1 ;;
        esac
        case "$f" in
            */uploads/*|*/upload/*|*/cache/*|*/sessions/*|*/images/*) writable=1 ;;
        esac
        base="$(basename -- "$f")"
        case "$base" in
            *shell*|*cmd*|*upload*|*wso*|*c99*|*r57*|*b374k*|*alfa*|*pws*|*spy*) suspicious=1 ;;
        esac

        [ "$strong" = 1 ] || [ "$double" = 1 ] || continue
        # eval/ofuscação isolado em código de terceiros é comum: só reporta se houver
        # contexto de escrita, modificação recente, nome suspeito ou extensão dupla.
        if [ "$strong" = 1 ] && [ "$double" = 0 ]; then
            case "$f" in
                */vendor/*|*/node_modules/*)
                    [ "$writable" = 1 ] || [ "$suspicious" = 1 ] || continue ;;
                *)
                    if [ "$writable" = 0 ] && [ "$suspicious" = 0 ]; then
                        [ -n "$(find "$f" -newermt "-${SINCE_DAYS} days" 2>/dev/null)" ] || continue
                    fi ;;
            esac
        fi

        local matched=""
        [ "$strong" = 1 ] && matched="padrão de execução dinâmica"
        [ "$double" = 1 ] && matched="${matched:+$matched; }extensão dupla"

        if [ "$writable" = 1 ]; then
            sev="critico"; conf="alta"
        else
            sev="alto"; conf="media"
        fi
        note="CMS legado e licenciamento comercial usam eval/ofuscação. Confirme o conteúdo e o hash antes de remover."
        emit "$sev" "$conf" "detection/upload-webshell" \
            "Possível webshell: $base" "$f" "arquivo; sha256=$(hash_file "$f")" \
            "$matched" \
            "Arquivo com execução dinâmica acessível pelo servidor web. Pode permitir execução remota de comando." \
            "escalate" "" "" "" "$note" "conteúdo não foi executado" "T1505.003" "log"
    done < <(timeout 25 find "${roots[@]}" -xdev -type f -size -2M \
                \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php.*' -o -name '*.inc' \) \
                2>/dev/null | head -n "$MAX_WEB_FILES")
}

# ---------------------------------------------------------------- persistência

scan_persistence() {
    local f line sev
    local re='(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|/dev/shm/|base64[[:space:]]+-d|/tmp/[A-Za-z0-9._/-]+|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e'

    if [ -s "$R/etc/ld.so.preload" ]; then
        while IFS= read -r line; do
            case "$line" in ''|'#'*) continue ;; esac
            emit "critico" "alta" "ir/persistence" "ld.so.preload ativo" \
                "$R/etc/ld.so.preload" "linha; sha256=$(hash_file "$R/etc/ld.so.preload")" "$line" \
                "Biblioteca pré-carregada em todos os processos. Mecanismo clássico de rootkit/userland hooking." \
                "escalate" "" "" "" "" "não é possível saber a origem pelo arquivo" "T1574.006" "log"
            break
        done < "$R/etc/ld.so.preload"
    fi

    local cron_files=("$R/etc/crontab")
    for d in "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" "$R/etc/cron.weekly" "$R/etc/cron.monthly" "$R/var/spool/cron" "$R/var/spool/cron/crontabs"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do cron_files+=("$f"); done < <(find "$d" -xdev -type f 2>/dev/null)
    done
    for f in "${cron_files[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r line; do
            case "$line" in ''|'#'*) continue ;; esac
            echo "$line" | grep -Eq "$re" || continue
            if echo "$line" | grep -Eq '(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh'; then sev="critico"; else sev="alto"; fi
            emit "$sev" "alta" "ir/persistence" "Tarefa agendada suspeita" \
                "$f" "linha; sha256=$(hash_file "$f")" "$line" \
                "Execução periódica de comando com download ou caminho temporário. Persistência típica pós-comprometimento." \
                "escalate" "" "" "" "Automação legítima pode usar curl; confirme dono e finalidade." "" "T1053.003" "log"
        done < "$f"
    done

    # systemd criado/modificado na janela
    for d in "$R/etc/systemd/system" "$R/lib/systemd/system"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            grep -Eq 'ExecStart=.*(curl|wget|/tmp/|/dev/shm/|bash -c|python[0-9.]* -c)' "$f" 2>/dev/null || continue
            emit "alto" "media" "ir/persistence" "Unidade systemd suspeita" \
                "$f" "arquivo; sha256=$(hash_file "$f")" "$(grep -m1 'ExecStart=' "$f" 2>/dev/null)" \
                "Serviço com execução a partir de download ou diretório temporário." \
                "escalate" "" "" "" "Unidade criada por pacote legítimo pode ter o mesmo formato; confirme o pacote." "" "T1543.002" "log"
        done < <(timeout 10 find "$d" -xdev -type f -name '*.service' -newermt "-${SINCE_DAYS} days" 2>/dev/null)
    done

    # chaves SSH
    while IFS= read -r f; do
        [ -s "$f" ] || continue
        emit "medio" "alta" "ir/persistence" "Chave SSH modificada na janela" \
            "$f" "arquivo; sha256=$(hash_file "$f")" "$(head -n 1 "$f")" \
            "Chave pública adicionada ou alterada recentemente. Pode ser acesso persistente do atacante." \
            "investigate" "" "" "" "Pode ser rotação legítima de chave. Confirme com o dono da conta." "" "T1098.004" "log"
    done < <(timeout 10 find "$R/root/.ssh" "$R/home" "$R/etc/ssh" -xdev -type f \
                \( -name 'authorized_keys' -o -name 'authorized_keys2' \) \
                -newermt "-${SINCE_DAYS} days" 2>/dev/null)
}

# ---------------------------------------------------------------- contas

scan_accounts() {
    local f="$R/etc/passwd" bad
    [ -f "$f" ] || return
    bad="$(awk -F: '$3==0 && $1!="root" {print $1}' "$f" 2>/dev/null)"
    if [ -n "$bad" ]; then
        emit "critico" "alta" "ir/persistence" "Conta com UID 0 além do root" \
            "$f" "linha; sha256=$(hash_file "$f")" "usuário(s): $(echo "$bad" | tr '\n' ' ')" \
            "Conta com privilégio total, possivelmente criada para persistência." \
            "escalate" "" "" "" "" "" "T1136.001" "log"
    fi
    if [ -n "$(find "$f" -newermt "-1 day" 2>/dev/null)" ]; then
        emit "medio" "media" "ir/persistence" "Base de contas alterada nas últimas 24h" \
            "$f" "arquivo; sha256=$(hash_file "$f")" "mtime recente" \
            "Criação, remoção ou alteração de conta. Correlacione com mudança aprovada." \
            "investigate" "" "" "" "Pode ser criação legítima de usuário." "" "T1136" "log"
    fi
    local sudoers=("$R/etc/sudoers")
    if [ -d "$R/etc/sudoers.d" ]; then
        while IFS= read -r f; do sudoers+=("$f"); done < <(find "$R/etc/sudoers.d" -xdev -type f 2>/dev/null)
    fi
    for f in "${sudoers[@]}"; do
        [ -f "$f" ] || continue
        grep -Eq 'NOPASSWD' "$f" 2>/dev/null || continue
        emit "medio" "alta" "posture/permissions" "sudo sem senha configurado" \
            "$f" "linha; sha256=$(hash_file "$f")" \
            "$(grep -m1 'NOPASSWD' "$f" 2>/dev/null)" \
            "Elevação de privilégio sem autenticação. Se a conta for comprometida, o impacto é imediato." \
            "investigate" "" "" "" "Pode ser automação legítima; confirme a necessidade." "" "T1548.003" "log"
    done
}

# ---------------------------------------------------------------- temporários

scan_temp_exec() {
    local d f base magic
    for d in "$R/tmp" "$R/var/tmp" "$R/dev/shm"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            base="$(basename -- "$f")"
            case "$base" in
                xmrig|kinsing|kdevtmpfsi|dbused|masscan|zgrab|hydra)
                    emit "alto" "alta" "detection/cryptomining" "Binário conhecido em diretório temporário" \
                        "$f" "arquivo; sha256=$(hash_file "$f")" "$base" \
                        "Executável de mineração/varredura em local temporário. Sinal forte de comprometimento." \
                        "escalate" "" "" "" "" "" "T1496" "log" ;;
                *)
                    [ -n "$(find "$f" -newermt "-${SINCE_DAYS} days" 2>/dev/null)" ] || continue
                    # Objetos de memória compartilhada e caches também têm bit de execução.
                    # Só reporta binário ELF ou script com shebang.
                    magic="$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
                    case "$magic" in 7f454c46|2321*) ;; *) continue ;; esac
                    emit "medio" "media" "detection/rce-runtime" "Executável em diretório temporário" \
                        "$f" "arquivo; sha256=$(hash_file "$f")" "$base" \
                        "Arquivo executável em /tmp, /var/tmp ou /dev/shm. Pode ser ferramenta baixada pelo atacante." \
                        "investigate" "" "" "" "Scripts legítimos de instalação também usam /tmp; verifique dono e origem." "" "T1105" "log" ;;
            esac
        done < <(timeout 10 find "$d" -xdev -type f -perm /111 -size -20M 2>/dev/null | head -n "$MAX_ITEMS")
    done
}

# ---------------------------------------------------------------- processos

scan_processes() {
    [ "$LIVE" = "1" ] || return
    local pid ppid user etimes comm args pcomm
    while IFS=' ' read -r pid ppid user etimes comm args; do
        [ -n "${pid:-}" ] || continue
        case "$comm" in ir_triage.sh|grep|awk|ps|sed|timeout|find) continue ;; esac
        # AppImage/Chromium montam em /tmp por projeto; não é sinal de comprometimento.
        case " $args " in
            *"/tmp/.mount_"*|*"/tmp/.org.chromium."*|*"/tmp/.com.google.Chrome"*) continue ;;
        esac
        local hit="" sev="alto" cat="detection/rce-runtime"
        case "$comm" in
            xmrig|kinsing|kdevtmpfsi|dbused) hit="minerador conhecido"; sev="alto"; cat="detection/cryptomining" ;;
        esac
        if [ -z "$hit" ] && echo " $args " | grep -Eq ' (/tmp/|/var/tmp/|/dev/shm/|memfd:)'; then
            hit="execução a partir de diretório temporário"
        fi
        if [ -z "$hit" ] && echo " $args " | grep -Eq '(bash[[:space:]]+-i|nc[[:space:]]+-e|socat.*EXEC|python[0-9.]*[[:space:]]+-c.*socket|perl[[:space:]]+-e)'; then
            hit="shell reverso ou execução inline"
        fi
        [ -n "$hit" ] || continue

        pcomm="$(ps -o comm= -p "$ppid" 2>/dev/null | tr -d ' ')"
        case "$pcomm" in
            apache2|httpd|nginx|php-fpm*|lsphp*)
                sev="critico"; hit="processo filho do servidor web: $hit" ;;
        esac
        emit "$sev" "media" "$cat" "Processo suspeito" "ps" "pid $pid (ppid $ppid)" \
            "$comm $args" \
            "Processo com característica de execução pós-exploração. Confirme binário, dono e origem." \
            "investigate" "" "" "" "Ferramenta administrativa legítima pode coincidir; valide com o time." \
            "processo pode já ter terminado" "T1059.004" "command"
    done < <(timeout 10 ps -eo pid=,ppid=,user=,etimes=,comm=,args= 2>/dev/null | head -n 400)
}

# ---------------------------------------------------------------- rede

scan_network() {
    [ "$LIVE" = "1" ] || return
    command -v ss >/dev/null 2>&1 || return

    local line peer proc dport rip comm pid
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        peer="$(echo "$line" | awk '{print $5}')"
        rip="${peer%:*}"; rip="${rip#[}"; rip="${rip%]}"
        dport="${peer##*:}"
        proc="$(echo "$line" | sed -n 's/.*users:((\"\([^\"]*\)\",pid=\([0-9]*\).*/\1 \2/p')"
        comm="${proc%% *}"; pid="${proc##* }"
        [ -n "$comm" ] || comm="desconhecido"
        case "$dport" in 3333|5555|7777|14444|45700)
            emit "alto" "media" "detection/exfiltration-c2" "Conexão para porta de pool de mineração" \
                "ss" "pid ${pid:-?} $comm" "$line" \
                "Conexão estabelecida para porta usada por pool de mineração." \
                "investigate" "" "" "" "Porta pode ser coincidente; confirme destino e processo." "" "T1496" "command" ;;
        esac
        case "$comm" in
            apache2|httpd|nginx|php-fpm*|lsphp*|www-data)
                if ! is_private "$rip"; then
                    emit "critico" "media" "detection/exfiltration-c2" "Saída de rede a partir da conta web" \
                        "ss" "pid ${pid:-?} $comm" "$line" \
                        "Servidor web com conexão estabelecida para destino público. Pode ser C2 ou exfiltração." \
                        "investigate" "" "" "" "Integração legítima com API externa produz o mesmo sinal; confirme destino." \
                        "sem root, o processo pode não ser atribuído" "T1041" "command"
                fi ;;
        esac
    done < <(timeout 10 ss -H -tunp state established 2>/dev/null | head -n 400)

    local listen
    listen="$(timeout 10 ss -H -tln 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $4}' | sort -u | head -n 30)"
    if [ -n "$listen" ]; then
        emit "baixo" "alta" "posture/firewall" "Serviços escutando em todas as interfaces" \
            "ss" "ss -tln" "$(echo "$listen" | tr '\n' ' ')" \
            "Serviços acessíveis por qualquer interface. Exposição depende do firewall e da rede." \
            "investigate" "" "" "" "Pode ser intencional (proxy, app pública). Confirme com a topologia." "" "T1046" "command"
    fi
}

# ---------------------------------------------------------------- binário apagado

scan_deleted_binaries() {
    [ "$LIVE" = "1" ] || return
    local link pid target
    local -A seen=()
    for link in /proc/[0-9]*/exe; do
        [ -L "$link" ] || continue
        pid="${link#/proc/}"; pid="${pid%/exe}"
        target="$(readlink "$link" 2>/dev/null)" || continue
        case "$target" in
            *"(deleted)"*)
                [ -n "${seen["$target"]:-}" ] && continue
                seen["$target"]=1
                emit "medio" "alta" "ir/evidence-integrity" "Binário em execução foi apagado" \
                    "proc" "pid $pid" "$target" \
                    "Processo roda de arquivo removido do disco. Comum após atualização sem restart; também usado para esconder binário." \
                    "investigate" "" "" "" "Atualização de pacote sem restart produz o mesmo efeito." "" "T1070.004" "command" ;;
        esac
    done
}

# ---------------------------------------------------------------- logs

scan_logs() {
    local auth="$R/var/log/auth.log" size mtime
    if [ ! -f "$auth" ]; then
        auth="$R/var/log/secure"
    fi
    [ -f "$auth" ] || return
    size="$(stat -c '%s' "$auth" 2>/dev/null || echo 0)"
    if [ "$size" = "0" ]; then
        emit "alto" "alta" "ir/evidence-integrity" "Log de autenticação vazio" \
            "$auth" "arquivo; sha256=$(hash_file "$auth")" "0 bytes" \
            "Log de autenticação sem conteúdo. Pode ser rotação, falha de serviço ou limpeza por atacante." \
            "investigate" "" "" "" "Rotação mal configurada produz o mesmo efeito." "" "T1070.002" "log"
    elif [ -n "$(find "$auth" -newermt "-${SINCE_DAYS} days" 2>/dev/null)" ]; then
        :
    else
        mtime="$(date -u -d "@$(stat -c '%Y' "$auth")" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        emit "medio" "media" "ir/evidence-integrity" "Log de autenticação sem atualização" \
            "$auth" "arquivo; sha256=$(hash_file "$auth")" "última modificação: ${mtime:-?}" \
            "Log sem escrita na janela. Pode indicar serviço parado ou logging desviado." \
            "investigate" "" "" "" "Host sem SSH ativo não escreve auth.log; confirme se o serviço existe." "" "T1562.002" "log"
    fi
}

# ---------------------------------------------------------------- docker

scan_docker() {
    [ "$LIVE" = "1" ] || return
    command -v docker >/dev/null 2>&1 || return
    timeout 5 docker info >/dev/null 2>&1 || return

    local line name privileged pidmode netmode mounts
    while IFS='|' read -r name privileged pidmode netmode mounts; do
        [ -n "$name" ] || continue
        if [ "$privileged" = "true" ] || [ "$pidmode" = "host" ] || [ "$netmode" = "host" ]; then
            emit "alto" "alta" "posture/docker" "Container com privilégio excessivo" \
                "docker" "container $name" "privileged=$privileged pid=$pidmode net=$netmode" \
                "Container com acesso ampliado ao host. Uma exploração na aplicação vira comprometimento do host." \
                "investigate" "" "" "" "Pode ser requisito de ferramenta específica; documente e restrinja." "" "T1611" "command"
        fi
        case "$mounts" in
            *"=>/,"*|*"=>/etc,"*|*"=>/root,"*|*"=>/home,"*|*"/var/run/docker.sock"*)
                emit "alto" "alta" "posture/docker" "Container com mount sensível do host" \
                    "docker" "container $name" "$mounts" \
                    "Mount de raiz, configuração, home ou socket do Docker. Dá ao container controle equivalente ao host." \
                    "investigate" "" "" "" "Mount de código-fonte é comum; avalie o que exatamente está exposto." "" "T1611" "command" ;;
        esac
    done < <(timeout 15 docker ps -q 2>/dev/null | while read -r id; do
        timeout 5 docker inspect --format '{{.Name}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.NetworkMode}}|{{range .Mounts}}{{.Source}}=>{{.Destination}},{{end}}' "$id" 2>/dev/null
    done | head -n 50)

    local ports
    ports="$(timeout 10 docker ps --format '{{.Ports}}' 2>/dev/null | grep -o '0\.0\.0\.0:[0-9]*' | sort -u | head -n 20)"
    if [ -n "$ports" ]; then
        emit "medio" "alta" "posture/docker" "Container publicado em todas as interfaces" \
            "docker" "docker ps" "$(echo "$ports" | tr '\n' ' ')" \
            "Porta de container publicada em 0.0.0.0. Exposição depende do firewall do host." \
            "investigate" "" "" "" "Publicação intencional é comum; confirme se a porta precisa ser pública." "" "T1046" "command"
    fi
}

# ---------------------------------------------------------------- execução

scan_webshells
scan_persistence
scan_accounts
scan_temp_exec
scan_logs
scan_processes
scan_network
scan_deleted_binaries
scan_docker

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

python3 - "$FINDINGS" "$MANIFEST" "$FORMAT" "$HOST" "$STARTED" "$ROOT" "$SINCE_DAYS" "$UID_NOW" "$OUTPUT" "$VERSION" "$LIVE" "$REDACT" "$REDACT_REASON" <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

findings_path, manifest_path, fmt, host, started, root, since, uid_now, output, version, live, redact_mode, redact_reason = sys.argv[1:14]
script_dir = os.environ.get("SCRIPT_DIR", "")

sys.path.insert(0, script_dir)
try:
    from log_triage import redact, excerpt, sanitize, validate, SEVERITY_RANK, CONFIDENCE_RANK, CATEGORIES
except Exception:  # script movido sozinho: redação mínima
    print("aviso: log_triage.py não encontrado; usando validação e redação mínimas", file=sys.stderr)
    def sanitize(text):
        return "".join(f"\\x{ord(c):02x}" if ord(c) < 32 or ord(c) == 127 else c for c in text)

    def redact(text):
        text = text.replace("\r", " ").replace("\n", " ")
        text = re.sub(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[=:]\s*\S+", r"\1=[REDACTADO]", text)
        text = re.sub(r"(?i)\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+", r"\1: [REDACTADO]", text)
        text = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "[EMAIL]", text)
        return sanitize(text)

    def excerpt(text, limit=500):
        safe = redact(text)
        return safe if len(safe) <= limit else safe[: limit - 1] + "…"

    SEVERITY_RANK = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
    CONFIDENCE_RANK = {"alta": 0, "media": 1, "baixa": 2}
    CATEGORIES = None

    def validate(result):
        return []

REDACTED = redact_mode != "off"
if not REDACTED:
    print(f"aviso: redação desativada — {redact_reason}", file=sys.stderr)


def safe_excerpt(text: str, limit: int = 500) -> str:
    if REDACTED:
        safe = redact(text)
    else:
        safe = sanitize(text.replace("\r", " ").replace("\n", " "))
    return safe if len(safe) <= limit else safe[: limit - 1] + "…"


NO_APPROVAL = {"none", "monitor", "investigate", "escalate"}

findings = []
with open(findings_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\x1f")
        if len(parts) < 16:
            continue
        sev, conf, cat, title, source, locator, ex, impact, action, command, rollback, target, fp, notobs, mitre, stype = parts[:16]
        rec = {"action": action, "requires_approval": action not in NO_APPROVAL}
        if command:
            rec["command"] = command
        if rollback:
            rec["rollback"] = rollback
        if target:
            rec["target"] = target
        item = {
            "title": title,
            "category": cat,
            "severity": sev,
            "confidence": conf,
            "evidence": [{
                "source": source,
                "locator": locator,
                "excerpt": safe_excerpt(ex),
                "redacted": REDACTED,
                "source_type": stype or "command",
            }],
            "impact": impact,
            "recommendation": rec,
            "not_observed": [x for x in notobs.split(";") if x],
        }
        if mitre:
            item["mitre"] = [x.strip() for x in mitre.split(",") if x.strip()]
        if fp:
            item["false_positive_notes"] = fp
        findings.append(item)

findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), CONFIDENCE_RANK.get(f["confidence"], 9), f["title"]))
for index, item in enumerate(findings, 1):
    item["id"] = f"F-{index:03d}"

counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
for item in findings:
    counts[item["severity"]] = counts.get(item["severity"], 0) + 1
verdict = "incidente" if counts["critico"] else "atencao" if counts["alto"] or counts["medio"] else "estavel"

artifacts = []
seen_artifacts = set()
with open(manifest_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 4 and parts[0] not in seen_artifacts:
            seen_artifacts.add(parts[0])
            artifacts.append({"path": parts[0], "sha256": parts[1], "bytes": parts[2], "mtime": parts[3]})

now = datetime.now(timezone.utc)
start = datetime.fromisoformat(started.replace("Z", "+00:00"))
base_sources = ["filesystem", "contas", "persistência", "logs"]
sources = list(base_sources)
if root == "/" and live == "1":
    sources += ["processos", "rede", "docker"]
not_observed = []
if uid_now != "0" and root == "/" and live == "1":
    not_observed.append("sem root: atribuição de processo e leitura de alguns caminhos ficaram limitadas")
if root != "/":
    not_observed.append("modo --root: processos, rede e docker não foram avaliados")
elif live != "1":
    not_observed.append("--no-live: processos, rede e docker não foram avaliados")

bytes_read = 0
for art in artifacts:
    try:
        bytes_read += int(art["bytes"])
    except (TypeError, ValueError):
        pass

result = {
    "schema_version": "1.0",
    "scan": {
        "id": f"gaara-{start.strftime('%Y%m%d')}-ir",
        "tool": "ir_triage",
        "host": host,
        "started_at": started,
        "finished_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window": {
            "from": (start - timedelta(days=int(since))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "to": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "sources": sources,
        "limits": {"bytes_read": bytes_read, "lines_read": len(findings), "truncated": False},
        "artifacts": artifacts,
    },
    "findings": findings,
    "summary": {"verdict": verdict, "counts": counts, "correlations": [], "not_observed": not_observed},
}

errors = validate(result)
if errors:
    for error in errors:
        print(f"schema: {error}", file=sys.stderr)
    sys.exit(1)

if fmt == "md":
    lines = [
        f"# Triagem de incidente — {host}",
        "",
        f"**Veredito:** {verdict}",
        f"**Janela:** {result['scan']['window']['from']} → {result['scan']['window']['to']}",
        f"**Achados:** " + " · ".join(f"{k} {v}" for k, v in counts.items()),
        f"**Artefatos com hash:** {len(artifacts)}",
        "",
        "## Achados",
        "",
    ]
    if not findings:
        lines += ["Nenhum sinal acima do limiar.", ""]
    label = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MÉDIO", "baixo": "BAIXO"}
    for item in findings:
        lines += [
            f"### [{label[item['severity']]}] {item['title']} ({item['id']})",
            "",
            f"- **Categoria:** `{item['category']}`",
            f"- **Confiança:** {item['confidence']}",
        ]
        for ev in item["evidence"]:
            lines.append(f"- **Evidência:** `{ev['source']}` {ev['locator']}: `{ev['excerpt']}`")
        lines += [f"- **Impacto:** {item['impact']}",
                  f"- **Recomendação:** {item['recommendation']['action']}"]
        if item.get("false_positive_notes"):
            lines.append(f"- **Falso positivo:** {item['false_positive_notes']}")
        lines.append("")
    if not_observed:
        lines += ["## Limitações", ""] + [f"- {n}" for n in not_observed] + [""]
    if artifacts:
        lines += ["## Artefatos", "", "| Arquivo | SHA-256 |", "|---|---|"]
        for art in artifacts[:40]:
            lines.append(f"| `{art['path']}` | `{art['sha256']}` |")
        lines.append("")
    output_text = "\n".join(lines)
else:
    output_text = json.dumps(result, ensure_ascii=False, indent=2)

if output:
    Path(output).write_text(output_text + "\n", encoding="utf-8")
    manifest_out = Path(str(output) + ".sha256")
    manifest_out.write_text(
        "".join(f"{a['sha256']}  {a['path']}\n" for a in artifacts),
        encoding="utf-8",
    )
    print(f"relatório: {output}", file=sys.stderr)
    print(f"manifesto: {manifest_out}", file=sys.stderr)
else:
    print(output_text)

high = counts["critico"] + counts["alto"]
sys.exit(3 if high else 0)
PY

status=$?
exit "$status"
