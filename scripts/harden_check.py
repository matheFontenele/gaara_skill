#!/usr/bin/env python3
"""harden_check.py — auditoria de postura somente leitura de host Linux.

Verifica SSH, firewall, kernel, permissões, TLS, Docker, portas expostas,
contas UID 0 e atualizações. Emite JSON no contrato de
references/finding-schema.md ou Markdown para leitura humana.

Somente leitura. Não instala, não altera configuração, não reinicia serviço e
nunca usa sudo. Comandos externos são executados sem shell e com timeout.

Uso:
    ./harden_check.py
    ./harden_check.py --format md --output /tmp/postura.md
    ./harden_check.py --write-baseline assets/baseline.json
    ./harden_check.py --baseline assets/baseline.json --format md

Códigos de saída:
    0  executou, nenhum achado alto/crítico
    1  erro de execução ou baseline inválido
    2  uso incorreto
    3  executou e encontrou achado alto ou crítico
"""

from __future__ import annotations

import argparse
import glob
import grp
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Reutiliza redação, sanitização e validação do log_triage.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import log_triage as triage  # noqa: E402

SCHEMA_VERSION = triage.SCHEMA_VERSION
TOOL = "harden_check"
BASELINE_VERSION = 1
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_CMD_OUTPUT = 2 * 1024 * 1024
EXCERPT_MAX = triage.EXCERPT_MAX
SEVERITY_RANK = triage.SEVERITY_RANK
SEVERITY_LABEL = triage.SEVERITY_LABEL
CONFIDENCE_RANK = triage.CONFIDENCE_RANK
REDACTION_ENABLED = True

# Portas que não deveriam ficar em 0.0.0.0/[::] sem controle de rede.
DB_PORTS = {
    1433, 1521, 3306, 3307, 5432, 5433, 6379, 9042, 9200, 9300,
    11211, 27017, 27018, 5672, 15672, 9092, 2375, 2376, 3389, 5900,
}
PUBLIC_WEB_PORTS = {22, 80, 443}

SSH_CONTROLS = {
    "permitrootlogin": ("ssh.permit_root_login", "Login de root no SSH", 10, "alto"),
    "passwordauthentication": ("ssh.password_authentication", "Autenticação por senha no SSH", 10, "alto"),
    "permitemptypasswords": ("ssh.permit_empty_passwords", "Senha vazia permitida no SSH", 15, "critico"),
    "maxauthtries": ("ssh.max_auth_tries", "Limite de tentativas SSH", 5, "medio"),
    "pubkeyauthentication": ("ssh.pubkey_authentication", "Autenticação por chave pública", 5, "medio"),
    "x11forwarding": ("ssh.x11_forwarding", "X11 forwarding no SSH", 2, "baixo"),
}

SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "maxauthtries": "6",
    "pubkeyauthentication": "yes",
    "x11forwarding": "no",
}


@dataclass
class Control:
    key: str
    title: str
    category: str
    weight: int
    severity: str
    value: str
    status: str
    source: str
    locator: str
    excerpt: str
    impact: str
    confidence: str = "alta"
    action: str = "patch"
    command: str | None = None
    rollback: str | None = None
    false_positive_notes: str = ""
    not_observed: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    source_type: str = "code"

    @property
    def assessed(self) -> bool:
        return self.status in {"pass", "warn", "fail"}


class Host:
    """Acesso somente leitura ao host, com raiz opcional para testes/offline."""

    def __init__(self, root: Path, no_commands: bool, now: datetime) -> None:
        self.root = root.resolve()
        self.host_mode = self.root == Path("/")
        self.no_commands = no_commands or not self.host_mode
        self.now = now
        self.sources: set[str] = set()
        self.notes: list[str] = []
        self.bytes_read = 0
        self.lines_read = 0
        self.truncated = False
        if not self.host_mode:
            self.notes.append("modo --root: donos de arquivo não foram avaliados; comandos do host foram desativados")

    @property
    def can_run(self) -> bool:
        return not self.no_commands

    def path(self, virtual: str) -> Path:
        return self.root / virtual.lstrip("/")

    def read_text(self, virtual: str, max_bytes: int = MAX_READ_BYTES) -> str | None:
        path = self.path(virtual)
        if not path.is_file():
            return None
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.notes.append(f"não foi possível ler {virtual}: {exc.__class__.__name__}")
            return None
        if len(data) > max_bytes:
            self.truncated = True
            data = data[:max_bytes]
            self.notes.append(f"{virtual} truncado em {max_bytes} bytes")
        self.bytes_read += len(data)
        text = data.decode("utf-8", errors="replace")
        self.lines_read += len(text.splitlines())
        self.sources.add(str(path))
        return text

    def stat_path(self, virtual: str) -> os.stat_result | None:
        path = self.path(virtual)
        try:
            result = path.stat()
        except OSError:
            return None
        self.sources.add(str(path))
        return result

    def exists(self, virtual: str) -> bool:
        return self.path(virtual).exists()

    def proc_value(self, relative: str) -> str | None:
        text = self.read_text(f"/proc/sys/{relative}")
        return text.strip() if text is not None and text.strip() else None

    def glob(self, virtual_pattern: str) -> list[Path]:
        return sorted(
            Path(item)
            for item in glob.glob(str(self.path(virtual_pattern)))
            if Path(item).exists()
        )

    def run(self, argv: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str] | None:
        if self.no_commands:
            return None
        label = " ".join(argv)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        except FileNotFoundError:
            return None
        except PermissionError:
            self.notes.append(f"sem permissão para executar {label}")
            return None
        except subprocess.TimeoutExpired:
            self.notes.append(f"{label} excedeu {timeout}s")
            return None
        except OSError as exc:
            self.notes.append(f"falha ao executar {label}: {exc.__class__.__name__}")
            return None
        self.sources.add(label)
        if len(proc.stdout or "") > MAX_CMD_OUTPUT:
            self.truncated = True
            proc = subprocess.CompletedProcess(
                proc.args, proc.returncode, (proc.stdout or "")[:MAX_CMD_OUTPUT],
                (proc.stderr or "")[:MAX_CMD_OUTPUT],
            )
            self.notes.append(f"saída de {label} truncada")
        return proc

    def owner(self, st: os.stat_result) -> str:
        try:
            user = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            user = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)
        return f"{user}:{group}"

    def mode(self, st: os.stat_result) -> int:
        return stat.S_IMODE(st.st_mode)


def parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _value(value: str, limit: int = 120) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _evidence(value: str) -> str:
    text = triage.sanitize(value.replace("\r", " ").replace("\n", " "))
    if REDACTION_ENABLED:
        text = triage.redact(text)
    return text[:EXCERPT_MAX]


def _control(
    *,
    key: str,
    title: str,
    category: str,
    weight: int,
    severity: str,
    status: str,
    value: str,
    source: str,
    locator: str,
    excerpt: str,
    impact: str,
    confidence: str = "alta",
    action: str = "patch",
    command: str | None = None,
    rollback: str | None = None,
    false_positive_notes: str = "",
    not_observed: list[str] | None = None,
    observations: dict[str, Any] | None = None,
    source_type: str = "code",
) -> Control:
    return Control(
        key=key,
        title=title,
        category=category,
        weight=weight,
        severity=severity,
        value=_value(value),
        status=status,
        source=source,
        locator=locator,
        excerpt=_evidence(excerpt),
        impact=impact,
        confidence=confidence,
        action=action,
        command=command,
        rollback=rollback,
        false_positive_notes=false_positive_notes,
        not_observed=list(not_observed or []),
        observations=dict(observations or {}),
        source_type=source_type,
    )


def _unknown(
    key: str, title: str, category: str, weight: int, reason: str, source: str = "host"
) -> Control:
    return _control(
        key=key,
        title=title,
        category=category,
        weight=weight,
        severity="baixo",
        status="unknown",
        value="não avaliado",
        source=source,
        locator="coleta",
        excerpt=reason,
        impact="O controle não pôde ser verificado; não há conclusão sobre ele.",
        confidence="baixa",
        action="investigate",
        not_observed=[reason],
    )


# ---------------------------------------------------------------- SSH

def find_sshd() -> str | None:
    found = shutil.which("sshd")
    if found:
        return found
    for candidate in ("/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def parse_sshd_T(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0]:
            values[parts[0].lower()] = parts[1].strip()
    return values


def parse_sshd_config(host: Host, config: str, depth: int = 0,
                      seen: set[str] | None = None) -> tuple[dict[str, str], list[str]]:
    """Lê configuração global do sshd, com Include e primeiro valor vencendo."""
    values: dict[str, str] = {}
    notes: list[str] = []
    if depth > 6:
        return values, ["limite de Include do sshd atingido"]
    seen = seen or set()
    if config in seen:
        return values, [f"Include circular ignorado: {config}"]
    seen.add(config)
    text = host.read_text(config)
    if text is None:
        return values, [f"não foi possível ler {config}"]

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            notes.append("bloco Match ignorado: valores condicionais não foram avaliados")
            break
        if key == "include":
            pattern = value
            if not pattern.startswith("/"):
                pattern = "/etc/ssh/" + pattern
            files = host.glob(pattern)
            for included in files:
                try:
                    included.relative_to(host.root)
                except ValueError:
                    notes.append(f"Include fora da raiz ignorado: {included}")
                    continue
                child, child_notes = parse_sshd_config(
                    host, "/" + str(included.relative_to(host.root)), depth + 1, seen
                )
                notes.extend(child_notes)
                for child_key, child_value in child.items():
                    values.setdefault(child_key, child_value)
            continue
        if key and key not in values:
            values[key] = value
    return values, notes


def check_ssh(host: Host, ssh_config: str | None) -> list[Control]:
    config = ssh_config or "/etc/ssh/sshd_config"
    if not config.startswith("/"):
        config = "/" + config
    values: dict[str, str] = {}
    source = ""
    source_type = "code"
    confidence = "media"
    notes: list[str] = []

    sshd = find_sshd() if host.can_run else None
    if sshd:
        proc = host.run([sshd, "-T"], timeout=8)
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            values = parse_sshd_T(proc.stdout)
            source = f"{sshd} -T"
            source_type = "command"
            confidence = "alta"
        elif proc is not None:
            notes.append("sshd -T não retornou configuração efetiva; usando o arquivo")
    if not values and host.path(config).is_file():
        values, parse_notes = parse_sshd_config(host, config)
        source = str(host.path(config))
        source_type = "code"
        confidence = "media"
        notes.extend(parse_notes)

    if not values:
        reason = "sshd não instalado ou configuração não legível"
        return [
            _unknown("ssh.config", "Configuração do SSH", "posture/ssh-config", 47, reason)
        ]

    controls: list[Control] = []
    for ssh_key, (key, title, weight, severity) in SSH_CONTROLS.items():
        explicit = ssh_key in values
        raw = values.get(ssh_key, SSH_DEFAULTS[ssh_key])
        normalized = raw.strip().lower()
        control_conf = confidence if explicit else "media"
        note = [] if explicit else [f"{ssh_key} não explícito; assumido o padrão OpenSSH"]
        locator = "sshd -T" if source_type == "command" else "arquivo de configuração"
        excerpt = f"{ssh_key} {raw}" + ("" if explicit else " (padrão presumido)")
        base = dict(
            weight=weight,
            source=source,
            locator=locator,
            excerpt=excerpt,
            confidence=control_conf,
            not_observed=note,
            source_type=source_type,
            observations={"ssh_key": ssh_key, "explicit": explicit},
        )
        common_command = (
            "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.gaara.bak && "
            "sed -i 's/^#\\?{key}.*/{key} {want}/I' /etc/ssh/sshd_config && "
            "sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)"
        )
        common_rollback = (
            "cp -a /etc/ssh/sshd_config.gaara.bak /etc/ssh/sshd_config && "
            "(systemctl reload ssh 2>/dev/null || systemctl reload sshd)"
        )

        if ssh_key == "permitrootlogin":
            if normalized in {"no", "forced-commands-only"}:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="Login direto de root por SSH está restrito.", **base,
                ))
            else:
                is_warn = normalized in {"prohibit-password", "without-password"}
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity="medio" if is_warn else severity,
                    status="warn" if is_warn else "fail",
                    value=raw,
                    impact=(
                        "Root ainda pode entrar por chave; compromise de chave vira root direto."
                        if is_warn else
                        "Permite força bruta direta contra a conta mais privilegiada."
                    ),
                    action="patch",
                    command=common_command.format(key="PermitRootLogin", want="no"),
                    rollback=common_rollback,
                    false_positive_notes="Alguns provedores exigem root por chave; nesse caso use um usuário de salto.",
                    **base,
                ))
        elif ssh_key == "passwordauthentication":
            if normalized == "no":
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="Senhas não são aceitas no SSH.", **base,
                ))
            else:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="fail", value=raw,
                    impact="Credencial fraca ou vazada permite acesso por força bruta ou stuffing.",
                    action="patch",
                    command=common_command.format(key="PasswordAuthentication", want="no"),
                    rollback=common_rollback,
                    false_positive_notes="Desative somente depois de confirmar que todos os usuários têm chave válida.",
                    **base,
                ))
        elif ssh_key == "permitemptypasswords":
            if normalized == "no":
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="Contas sem senha não entram por SSH.", **base,
                ))
            else:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="fail", value=raw,
                    impact="Conta sem senha pode entrar sem credencial.",
                    action="patch",
                    command=common_command.format(key="PermitEmptyPasswords", want="no"),
                    rollback=common_rollback,
                    **base,
                ))
        elif ssh_key == "maxauthtries":
            try:
                tries = int(normalized)
            except ValueError:
                tries = 99
            if tries <= 4:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="Poucas tentativas por conexão reduzem força bruta.", **base,
                ))
            else:
                is_warn = tries <= 6
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity="baixo" if is_warn else severity,
                    status="warn" if is_warn else "fail",
                    value=raw,
                    impact="Muitas tentativas por conexão ampliam a janela de força bruta.",
                    action="patch",
                    command=common_command.format(key="MaxAuthTries", want="3"),
                    rollback=common_rollback,
                    **base,
                ))
        elif ssh_key == "pubkeyauthentication":
            if normalized == "yes":
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="Chaves públicas podem ser usadas.", **base,
                ))
            else:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="fail", value=raw,
                    impact="Sem chave pública, o acesso tende a depender de senha.",
                    action="patch",
                    command=common_command.format(key="PubkeyAuthentication", want="yes"),
                    rollback=common_rollback,
                    **base,
                ))
        elif ssh_key == "x11forwarding":
            if normalized == "no":
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="pass", value=raw,
                    impact="X11 forwarding está desabilitado.", **base,
                ))
            else:
                controls.append(_control(
                    key=key, title=title, category="posture/ssh-config",
                    severity=severity, status="warn", value=raw,
                    impact="X11 forwarding amplia a superfície do cliente SSH.",
                    action="monitor", **base,
                ))
    return controls


# ---------------------------------------------------------------- firewall

def _ufw_enabled(host: Host) -> bool | None:
    text = host.read_text("/etc/ufw/ufw.conf")
    if text is None:
        return None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        match = re.match(r"ENABLED\s*=\s*[\"']?(yes|no)[\"']?\s*$", line, re.I)
        if match:
            return match.group(1).lower() == "yes"
    return None


def _has_iptables_input_rules(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"-P\s+INPUT\s+(DROP|REJECT)\b", stripped):
            return True
        if re.match(r"-A\s+INPUT\b", stripped) and re.search(
            r"-j\s+(DROP|REJECT)\b", stripped
        ):
            return True
    return False


def _nft_has_input_filter(text: str) -> bool:
    for block in re.findall(r"chain\s+\w+\s*\{(.*?)\}", text, re.I | re.S):
        if re.search(r"hook\s+input\b", block, re.I) and re.search(
            r"\b(?:policy\s+)?(?:drop|reject)\b", block, re.I
        ):
            return True
    return False


def check_firewall(host: Host) -> list[Control]:
    ufw_enabled = _ufw_enabled(host)
    ufw_status: str | None = None
    firewall_other = False
    details: list[str] = []
    source = "/etc/ufw/ufw.conf" if ufw_enabled is not None else "host"
    source_type = "code"

    if host.can_run:
        ufw = host.run(["ufw", "status"], timeout=5)
        if ufw is not None and ufw.returncode == 0:
            low = (ufw.stdout or "").lower()
            if "status: active" in low:
                ufw_status = "active"
            elif "status: inactive" in low:
                ufw_status = "inactive"
            if ufw_status:
                source = "ufw status"
                source_type = "command"
                details.append(f"ufw status={ufw_status}")
        elif ufw is not None and "root" in (ufw.stderr or "").lower():
            host.notes.append("ufw status exige root; status efetivo não confirmado sem sudo")

        for service in ("firewalld",):
            proc = host.run(["systemctl", "is-active", service], timeout=3)
            if proc is not None and proc.returncode == 0 and proc.stdout.strip() == "active":
                firewall_other = True
                details.append(f"{service}=active")
                source = f"systemctl is-active {service}"
                source_type = "command"

        nft = host.run(["nft", "list", "ruleset"], timeout=5)
        if nft is not None and nft.returncode == 0:
            if _nft_has_input_filter(nft.stdout or ""):
                firewall_other = True
                details.append("nftables com filtro de entrada")
                source = "nft list ruleset"
                source_type = "command"
        ipt = host.run(["iptables", "-S"], timeout=5)
        if ipt is not None and ipt.returncode == 0 and _has_iptables_input_rules(ipt.stdout or ""):
            firewall_other = True
            details.append("iptables com política/regra de INPUT")
            source = "iptables -S"
            source_type = "command"

    if ufw_status == "active" or firewall_other:
        value = "ativo" + ("; " + "; ".join(details) if details else "")
        return [_control(
            key="firewall.enabled", title="Firewall de entrada ativo",
            category="posture/firewall", weight=12, severity="alto", status="pass",
            value=value, source=source, locator="estado do firewall",
            excerpt=value, impact="O host tem uma camada de filtragem de entrada.",
            confidence="alta" if source_type == "command" else "media",
            source_type=source_type,
        )]

    if ufw_status == "inactive" or ufw_enabled is False:
        value = "ufw desabilitado" if ufw_enabled is False else "ufw inativo"
        return [_control(
            key="firewall.enabled", title="Firewall de entrada desabilitado",
            category="posture/firewall", weight=12, severity="alto", status="fail",
            value=value, source=source, locator="estado do firewall",
            excerpt=value + (f" ({'; '.join(details)})" if details else ""),
            impact="Portas expostas dependem apenas da aplicação e de security groups externos.",
            confidence="alta" if ufw_status == "inactive" else "media",
            action="patch",
            command="cp -a /etc/ufw /etc/ufw.gaara.bak && ufw default deny incoming && ufw allow 22/tcp && ufw enable",
            rollback="ufw disable && cp -a /etc/ufw.gaara.bak /etc/ufw",
            false_positive_notes="Firewall de nuvem/security group pode existir fora do host; confirme antes.",
            source_type=source_type,
        )]

    if ufw_enabled is True:
        host.notes.append(
            "firewall: ENABLED=yes no UFW, mas o status efetivo não foi confirmado sem root"
        )
        return [_control(
            key="firewall.enabled", title="Firewall configurado para iniciar",
            category="posture/firewall", weight=12, severity="alto", status="pass",
            value="ufw habilitado na configuração; status efetivo não confirmado",
            source=source, locator="estado do firewall",
            excerpt="ENABLED=yes; confirme o estado efetivo com ufw status",
            impact="A configuração indica firewall habilitado, mas o estado efetivo não foi lido.",
            confidence="media", action="none",
            not_observed=["saída de ufw status não disponível sem root"],
            source_type=source_type,
        )]

    return [_unknown(
        "firewall.enabled", "Firewall de entrada", "posture/firewall", 12,
        "não foi possível confirmar firewall sem root e sem regras legíveis",
    )]


# ---------------------------------------------------------------- kernel

def check_kernel(host: Host) -> list[Control]:
    controls: list[Control] = []

    aslr = host.proc_value("kernel/randomize_va_space")
    if aslr is None:
        controls.append(_unknown("kernel.aslr", "ASLR do kernel", "posture/firewall", 8,
                                 "/proc/sys/kernel/randomize_va_space não legível"))
    else:
        try:
            aslr_n = int(aslr)
        except ValueError:
            aslr_n = -1
        status = "pass" if aslr_n >= 2 else "warn" if aslr_n == 1 else "fail"
        severity = "alto" if aslr_n == 0 else "medio"
        controls.append(_control(
            key="kernel.aslr", title="ASLR do kernel", category="posture/firewall",
            weight=8, severity=severity, status=status, value=aslr,
            source="/proc/sys/kernel/randomize_va_space", locator="valor atual",
            excerpt=f"randomize_va_space={aslr}; esperado: 2",
            impact="ASLR fraco facilita exploração de corrupção de memória.",
            action="patch",
            command="sysctl -w kernel.randomize_va_space=2 && printf '%s\\n' 'kernel.randomize_va_space=2' >> /etc/sysctl.d/99-gaara.conf",
            rollback=f"sysctl -w kernel.randomize_va_space={aslr} && sed -i '/^kernel\\.randomize_va_space=/d' /etc/sysctl.d/99-gaara.conf",
        ))

    syncookies = host.proc_value("net/ipv4/tcp_syncookies")
    if syncookies is None:
        controls.append(_unknown("net.syncookies", "SYN cookies", "posture/firewall", 4,
                                 "/proc/sys/net/ipv4/tcp_syncookies não legível"))
    else:
        controls.append(_control(
            key="net.syncookies", title="SYN cookies", category="posture/firewall",
            weight=4, severity="medio", status="pass" if syncookies in {"1", "2"} else "fail",
            value=syncookies, source="/proc/sys/net/ipv4/tcp_syncookies", locator="valor atual",
            excerpt=f"tcp_syncookies={syncookies}; esperado: 1",
            impact="Sem SYN cookies, SYN flood pode esgotar a fila de conexões.",
            action="patch",
            command="sysctl -w net.ipv4.tcp_syncookies=1 && printf '%s\\n' 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.d/99-gaara.conf",
            rollback=f"sysctl -w net.ipv4.tcp_syncookies={syncookies} && sed -i '/^net\\.ipv4\\.tcp_syncookies=/d' /etc/sysctl.d/99-gaara.conf",
        ))

    redirects = {
        "all": host.proc_value("net/ipv4/conf/all/accept_redirects"),
        "default": host.proc_value("net/ipv4/conf/default/accept_redirects"),
    }
    if any(value is None for value in redirects.values()):
        controls.append(_unknown("net.accept_redirects", "Redirects ICMP", "posture/firewall", 5,
                                 "accept_redirects não legível em all/default"))
    else:
        bad = [name for name, value in redirects.items() if value != "0"]
        controls.append(_control(
            key="net.accept_redirects", title="Redirects ICMP", category="posture/firewall",
            weight=5, severity="medio", status="fail" if bad else "pass",
            value=", ".join(f"{name}={value}" for name, value in redirects.items()),
            source="/proc/sys/net/ipv4/conf", locator="all/default",
            excerpt=", ".join(f"{name}={value}" for name, value in redirects.items()),
            impact="Redirects ICMP podem desviar tráfego e facilitar MITM.",
            action="patch",
            command="sysctl -w net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 && printf '%s\\n' 'net.ipv4.conf.all.accept_redirects=0' 'net.ipv4.conf.default.accept_redirects=0' >> /etc/sysctl.d/99-gaara.conf",
            rollback=f"sysctl -w net.ipv4.conf.all.accept_redirects={redirects['all']} net.ipv4.conf.default.accept_redirects={redirects['default']} && sed -i '/^net\\.ipv4\\.conf\\.\\(all\\|default\\)\\.accept_redirects=/d' /etc/sysctl.d/99-gaara.conf",
        ))

    rp_filter = {
        "all": host.proc_value("net/ipv4/conf/all/rp_filter"),
        "default": host.proc_value("net/ipv4/conf/default/rp_filter"),
    }
    if any(value is None for value in rp_filter.values()):
        controls.append(_unknown("net.rp_filter", "Reverse path filter", "posture/firewall", 3,
                                 "rp_filter não legível em all/default"))
    else:
        bad = [name for name, value in rp_filter.items() if value == "0"]
        controls.append(_control(
            key="net.rp_filter", title="Reverse path filter", category="posture/firewall",
            weight=3, severity="baixo", status="fail" if bad else "pass",
            value=", ".join(f"{name}={value}" for name, value in rp_filter.items()),
            source="/proc/sys/net/ipv4/conf", locator="all/default",
            excerpt=", ".join(f"{name}={value}" for name, value in rp_filter.items()),
            impact="Sem rp_filter, pacotes com origem falsificada circulam com menos barreira.",
            action="monitor",
            false_positive_notes="Valor 2 (loose) é aceitável em alguns roteadores; o script só falha em 0.",
        ))

    protected = {
        "hardlinks": host.proc_value("fs/protected_hardlinks"),
        "symlinks": host.proc_value("fs/protected_symlinks"),
    }
    if any(value is None for value in protected.values()):
        controls.append(_unknown("fs.protected_links", "Proteção de links", "posture/permissions", 5,
                                 "protected_hardlinks/symlinks não legível"))
    else:
        bad = [name for name, value in protected.items() if value != "1"]
        controls.append(_control(
            key="fs.protected_links", title="Proteção de hardlinks e symlinks",
            category="posture/permissions", weight=5, severity="medio",
            status="fail" if bad else "pass",
            value=", ".join(f"{name}={value}" for name, value in protected.items()),
            source="/proc/sys/fs", locator="protected_hardlinks/symlinks",
            excerpt=", ".join(f"{name}={value}" for name, value in protected.items()),
            impact="Links previsíveis em /tmp podem ser usados para sobrescrever arquivos.",
            action="patch",
            command="sysctl -w fs.protected_hardlinks=1 fs.protected_symlinks=1 && printf '%s\\n' 'fs.protected_hardlinks=1' 'fs.protected_symlinks=1' >> /etc/sysctl.d/99-gaara.conf",
            rollback=f"sysctl -w fs.protected_hardlinks={protected['hardlinks']} fs.protected_symlinks={protected['symlinks']} && sed -i '/^fs\\.protected_\\(hardlinks\\|symlinks\\)=/d' /etc/sysctl.d/99-gaara.conf",
        ))

    kptr = host.proc_value("kernel/kptr_restrict")
    dmesg = host.proc_value("kernel/dmesg_restrict")
    if kptr is None and dmesg is None:
        controls.append(_unknown("kernel.info_leak", "Exposição de informação do kernel",
                                 "posture/permissions", 3, "kptr_restrict/dmesg_restrict não legível"))
    else:
        bad = (kptr is not None and kptr == "0") or (dmesg is not None and dmesg == "0")
        values = f"kptr_restrict={kptr or '?'}, dmesg_restrict={dmesg or '?'}"
        controls.append(_control(
            key="kernel.info_leak", title="Exposição de informação do kernel",
            category="posture/permissions", weight=3, severity="baixo",
            status="warn" if bad else "pass", value=values,
            source="/proc/sys/kernel", locator="kptr_restrict/dmesg_restrict",
            excerpt=values + "; esperado: ambos >= 1",
            impact="Endereços de kernel e dmesg facilitam reconhecimento local.",
            action="monitor",
        ))
    return controls


# ---------------------------------------------------------------- permissões

def _perm_control(
    host: Host, key: str, title: str, virtual: str, weight: int, severity: str,
    mode_bad: bool, owner_bad: bool, expected: str, impact: str,
    command: str, rollback: str, extra_note: str = "",
) -> Control:
    st = host.stat_path(virtual)
    if st is None:
        return _unknown(key, title, "posture/permissions", weight, f"{virtual} não encontrado")
    mode = host.mode(st)
    owner = host.owner(st)
    bad = mode_bad or owner_bad
    value = f"{virtual} modo={mode:04o} dono={owner}"
    note = [extra_note] if extra_note else []
    if not host.host_mode:
        note.append("dono não avaliado no modo --root")
    return _control(
        key=key, title=title, category="posture/permissions", weight=weight,
        severity=severity, status="fail" if bad else "pass", value=value,
        source=str(host.path(virtual)), locator="modo e dono",
        excerpt=f"{value}; esperado: {expected}", impact=impact,
        confidence="alta" if host.host_mode else "media",
        action="patch" if bad else "none",
        command=command if bad else None, rollback=rollback if bad else None,
        not_observed=note,
    )


def check_permissions(host: Host) -> list[Control]:
    controls: list[Control] = []

    shadow = host.stat_path("/etc/shadow")
    if shadow is None:
        controls.append(_unknown("perm.shadow", "Permissão de /etc/shadow",
                                 "posture/permissions", 15, "/etc/shadow não encontrado"))
    else:
        mode = host.mode(shadow)
        unsafe = bool(mode & 0o007) or bool(mode & 0o020) or bool(mode & 0o010)
        owner_bad = host.host_mode and shadow.st_uid != 0
        try:
            shadow_gid = grp.getgrnam("shadow").gr_gid
        except KeyError:
            shadow_gid = 0
        group_bad = host.host_mode and shadow.st_gid not in {0, shadow_gid}
        bad = unsafe or owner_bad or group_bad
        controls.append(_control(
            key="perm.shadow", title="Permissão de /etc/shadow",
            category="posture/permissions", weight=15, severity="critico",
            status="fail" if bad else "pass",
            value=f"modo={mode:04o} dono={host.owner(shadow)}",
            source=str(host.path("/etc/shadow")), locator="modo e dono",
            excerpt=f"modo={mode:04o} dono={host.owner(shadow)}; esperado: 0640 root:shadow",
            impact="Hash de senha legível por outro usuário permite quebra offline.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if bad else "none",
            command="cp -a /etc/shadow /etc/shadow.gaara.bak && chown root:shadow /etc/shadow && chmod 0640 /etc/shadow",
            rollback="cp -a /etc/shadow.gaara.bak /etc/shadow",
        ))

    passwd_st = host.stat_path("/etc/passwd")
    passwd_mode = host.mode(passwd_st) if passwd_st else 0o644
    controls.append(_perm_control(
        host, "perm.passwd", "Permissão de /etc/passwd", "/etc/passwd", 10, "critico",
        bool(passwd_mode & 0o022),
        bool(host.host_mode and passwd_st and passwd_st.st_uid != 0),
        "sem escrita para grupo/outros",
        "Escrita em /etc/passwd permite criar ou alterar contas.",
        "cp -a /etc/passwd /etc/passwd.gaara.bak && chown root:root /etc/passwd && chmod 0644 /etc/passwd",
        "cp -a /etc/passwd.gaara.bak /etc/passwd",
    ))

    group_st = host.stat_path("/etc/group")
    group_mode = host.mode(group_st) if group_st else 0o644
    controls.append(_perm_control(
        host, "perm.group", "Permissão de /etc/group", "/etc/group", 5, "alto",
        bool(group_mode & 0o022),
        bool(host.host_mode and group_st and group_st.st_uid != 0),
        "sem escrita para grupo/outros",
        "Escrita em /etc/group permite ampliar privilégios de grupo.",
        "cp -a /etc/group /etc/group.gaara.bak && chown root:root /etc/group && chmod 0644 /etc/group",
        "cp -a /etc/group.gaara.bak /etc/group",
    ))

    sudoers = host.stat_path("/etc/sudoers")
    if sudoers is None:
        controls.append(_unknown("perm.sudoers", "Permissão de /etc/sudoers",
                                 "posture/permissions", 6, "/etc/sudoers não encontrado"))
    else:
        mode = host.mode(sudoers)
        critical = bool(mode & 0o022) or (host.host_mode and (sudoers.st_uid != 0 or sudoers.st_gid != 0))
        warn = mode not in (0o440, 0o400)
        controls.append(_control(
            key="perm.sudoers", title="Permissão de /etc/sudoers",
            category="posture/permissions", weight=6,
            severity="critico" if critical else "medio",
            status="fail" if critical else "warn" if warn else "pass",
            value=f"modo={mode:04o} dono={host.owner(sudoers)}",
            source=str(host.path("/etc/sudoers")), locator="modo e dono",
            excerpt=f"modo={mode:04o}; esperado: 0440 root:root",
            impact="Sudoers gravável permite escalar para root; leitura amplia reconhecimento.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if critical or warn else "none",
            command="cp -a /etc/sudoers /etc/sudoers.gaara.bak && chown root:root /etc/sudoers && chmod 0440 /etc/sudoers",
            rollback="cp -a /etc/sudoers.gaara.bak /etc/sudoers",
            false_positive_notes="Algumas distribuições usam 0400; ambos são aceitos.",
        ))

    root_st = host.stat_path("/root")
    if root_st is None:
        controls.append(_unknown("perm.root_home", "Permissão de /root",
                                 "posture/permissions", 4, "/root não encontrado"))
    else:
        mode = host.mode(root_st)
        bad = bool(mode & 0o077) or (host.host_mode and root_st.st_uid != 0)
        controls.append(_control(
            key="perm.root_home", title="Permissão de /root",
            category="posture/permissions", weight=4, severity="medio",
            status="fail" if bad else "pass",
            value=f"modo={mode:04o} dono={host.owner(root_st)}",
            source=str(host.path("/root")), locator="modo e dono",
            excerpt=f"modo={mode:04o}; esperado: 0700 root:root",
            impact="Outros usuários podem ler arquivos e chaves do home de root.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if bad else "none",
            command="chmod 0700 /root",
            rollback=f"chmod {mode:04o} /root",
        ))

    ssh_config = host.stat_path("/etc/ssh/sshd_config")
    if ssh_config is None:
        controls.append(_unknown("perm.sshd_config", "Permissão do sshd_config",
                                 "posture/permissions", 6, "sshd_config não encontrado"))
    else:
        mode = host.mode(ssh_config)
        bad = bool(mode & 0o022) or (host.host_mode and ssh_config.st_uid != 0)
        controls.append(_control(
            key="perm.sshd_config", title="Permissão do sshd_config",
            category="posture/permissions", weight=6, severity="critico",
            status="fail" if bad else "pass",
            value=f"modo={mode:04o} dono={host.owner(ssh_config)}",
            source=str(host.path("/etc/ssh/sshd_config")), locator="modo e dono",
            excerpt=f"modo={mode:04o}; esperado: sem escrita para grupo/outros",
            impact="Quem escreve no sshd_config pode habilitar login indevido.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if bad else "none",
            command="chown root:root /etc/ssh/sshd_config && chmod 0644 /etc/ssh/sshd_config",
            rollback=f"chmod {mode:04o} /etc/ssh/sshd_config",
        ))

    key_files = [p for p in host.glob("/etc/ssh/ssh_host_*_key") if p.is_file()]
    if not key_files:
        controls.append(_unknown("perm.ssh_host_keys", "Chaves privadas do host SSH",
                                 "posture/permissions", 10, "nenhuma chave ssh_host_*_key encontrada"))
    else:
        bad_keys: list[str] = []
        for path in key_files:
            st = path.stat()
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o007 or mode & 0o020 or (host.host_mode and (st.st_uid != 0 or st.st_gid != 0)):
                bad_keys.append(f"{path.name} modo={mode:04o}")
        controls.append(_control(
            key="perm.ssh_host_keys", title="Chaves privadas do host SSH",
            category="posture/permissions", weight=10, severity="critico",
            status="fail" if bad_keys else "pass",
            value=", ".join(bad_keys) if bad_keys else f"{len(key_files)} chave(s) restrita(s)",
            source=str(host.path("/etc/ssh")), locator="ssh_host_*_key",
            excerpt=", ".join(bad_keys) if bad_keys else "chaves sem acesso de outros",
            impact="Chave privada do host lida por terceiro permite impersonar o servidor.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if bad_keys else "none",
            command="chown root:root /etc/ssh/ssh_host_*_key && chmod 0600 /etc/ssh/ssh_host_*_key",
            rollback="restaurar modos anteriores do backup; chaves comprometidas devem ser regeneradas",
            not_observed=[] if host.host_mode else ["dono das chaves não avaliado no modo --root"],
        ))

    ssl_private = host.stat_path("/etc/ssl/private")
    if ssl_private is None:
        controls.append(_unknown("perm.ssl_private", "Permissão de /etc/ssl/private",
                                 "posture/permissions", 6, "/etc/ssl/private não encontrado"))
    else:
        mode = host.mode(ssl_private)
        bad = bool(mode & 0o007) or bool(mode & 0o020) or (host.host_mode and ssl_private.st_uid != 0)
        controls.append(_control(
            key="perm.ssl_private", title="Permissão de /etc/ssl/private",
            category="posture/permissions", weight=6, severity="alto",
            status="fail" if bad else "pass",
            value=f"modo={mode:04o} dono={host.owner(ssl_private)}",
            source=str(host.path("/etc/ssl/private")), locator="modo e dono",
            excerpt=f"modo={mode:04o}; esperado: 0710 root:ssl-cert",
            impact="Chave TLS privada exposta permite impersonar o serviço.",
            confidence="alta" if host.host_mode else "media",
            action="patch" if bad else "none",
            command="chown root:ssl-cert /etc/ssl/private && chmod 0710 /etc/ssl/private",
            rollback=f"chmod {mode:04o} /etc/ssl/private",
        ))
    return controls


def check_uid0(host: Host) -> list[Control]:
    text = host.read_text("/etc/passwd")
    if text is None:
        return [_unknown("accounts.uid0", "Contas com UID 0",
                         "posture/permissions", 15, "/etc/passwd não legível")]
    extra: list[tuple[str, int, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(":")
        if len(fields) < 7:
            continue
        try:
            uid = int(fields[2])
        except ValueError:
            continue
        if uid == 0 and fields[0] != "root":
            extra.append((fields[0], number, raw))
    if not extra:
        return [_control(
            key="accounts.uid0", title="Contas com UID 0",
            category="posture/permissions", weight=15, severity="critico", status="pass",
            value="apenas root", source=str(host.path("/etc/passwd")),
            locator="UID 0", excerpt="apenas root possui UID 0",
            impact="Não há conta extra com privilégio total.",
            action="none",
        )]
    names = ", ".join(name for name, _, _ in extra)
    return [_control(
        key="accounts.uid0", title="Conta extra com UID 0",
        category="posture/permissions", weight=15, severity="critico", status="fail",
        value=names, source=str(host.path("/etc/passwd")),
        locator="linhas " + ", ".join(str(number) for _, number, _ in extra),
        excerpt="; ".join(
            f"{name} (linha {number}, UID 0)" for name, number, _ in extra[:3]
        ),
        impact="Qualquer conta com UID 0 tem poder equivalente a root.",
        action="escalate",
        command="getent passwd 0; revisar a conta antes de bloquear ou remover",
        rollback="não aplicável: ação somente de investigação",
        confidence="alta",
        observations={"accounts": names},
    )]


def check_app_root(host: Host, app_root: Path | None) -> list[Control]:
    if app_root is None:
        return []
    names = {".env", ".env.local", ".env.production", "wp-config.php", "config.php", "configuration.php"}
    bad: list[str] = []
    found: list[str] = []
    for name in sorted(names):
        path = app_root / name
        try:
            st = path.stat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        found.append(name)
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o007 or mode & 0o020:
            bad.append(f"{name} modo={mode:04o}")
    if not found:
        return []
    if not bad:
        return [_control(
            key="secrets.app_files", title="Permissão de arquivos de segredo da aplicação",
            category="posture/secrets", weight=8, severity="alto", status="pass",
            value=", ".join(found), source=str(app_root), locator="arquivos de configuração",
            excerpt="segredos sem acesso de outros", impact="Arquivos de segredo não estão expostos.",
            action="none",
        )]
    return [_control(
        key="secrets.app_files", title="Segredo da aplicação legível por outros",
        category="posture/secrets", weight=8, severity="alto", status="fail",
        value=", ".join(bad), source=str(app_root), locator="arquivos de configuração",
        excerpt=", ".join(bad) + "; esperado: 0600 ou 0640 com grupo restrito",
        impact="Usuário local ou processo comprometido pode ler credenciais da aplicação.",
        confidence="media", action="patch",
        command="chmod 0600 <arquivo>  # ajuste o grupo se o servidor web precisar ler",
        rollback="restaurar o modo anterior a partir do backup",
        false_positive_notes="O servidor web pode precisar de leitura via grupo; use 0640 com grupo dedicado.",
    )]


# ---------------------------------------------------------------- TLS

def _tls_configs(host: Host) -> list[tuple[str, int, str]]:
    patterns = [
        "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
        "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*.conf",
        "/etc/apache2/conf-enabled/*.conf",
    ]
    found: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    for pattern in patterns:
        for path in host.glob(pattern):
            if not path.is_file() or str(path) in seen:
                continue
            seen.add(str(path))
            text = host.read_text("/" + str(path.relative_to(host.root)), max_bytes=512 * 1024)
            if text is None:
                continue
            for number, raw in enumerate(text.splitlines(), 1):
                if "ssl_protocols" in raw.lower() or "sslprotocol" in raw.lower():
                    found.append((str(path), number, raw.strip()))
    return found


def check_tls(host: Host) -> list[Control]:
    configs = _tls_configs(host)
    if not configs:
        host.notes.append(
            "TLS: nenhuma configuração local de protocolo em Nginx/Apache; "
            "pode estar em proxy, CDN ou container"
        )
        return [_control(
            key="tls.protocols", title="Protocolos TLS", category="posture/tls",
            weight=8, severity="alto", status="na", value="nenhum TLS local detectado",
            source="host", locator="configuração web",
            excerpt="Nenhum ssl_protocols/SSLProtocol em Nginx/Apache local",
            impact="Não há TLS configurado diretamente neste host.",
            action="none", confidence="baixa",
            not_observed=["TLS pode estar terminado em proxy, CDN ou container"],
        )]

    old: list[str] = []
    all_proto: list[str] = []
    modern: list[str] = []
    old_tokens = {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv2", "sslv3"}
    for source, number, line in configs:
        cleaned = line.split("#", 1)[0]
        enabled: set[str] = set()
        disabled: set[str] = set()
        for sign, token in re.findall(
            r"(?i)(?<![\w-])(-?)(TLSv1(?:\.\d)?|SSLv[23]|all)\b", cleaned
        ):
            (disabled if sign == "-" else enabled).add(token.lower())
        label = f"{Path(source).name}:{number}"
        if "all" in enabled:
            if {"sslv3", "tlsv1", "tlsv1.1"} <= disabled:
                modern.append(label)
            else:
                all_proto.append(label)
        for token in sorted(enabled - {"all"}):
            if token in old_tokens:
                old.append(label)
            else:
                modern.append(label)
    source = configs[0][0]
    locator = f"linha {configs[0][1]}"
    excerpt = configs[0][2]
    if old:
        return [_control(
            key="tls.protocols", title="Protocolo TLS antigo habilitado",
            category="posture/tls", weight=8, severity="alto", status="fail",
            value=", ".join(sorted(set(old))), source=source, locator=locator,
            excerpt=excerpt,
            impact="TLS 1.0/1.1 e SSL são obsoletos e vulneráveis a ataques de downgrade.",
            action="patch",
            command="cp -a <config> <config>.gaara.bak && edite ssl_protocols/SSLProtocol para TLSv1.2 TLSv1.3 && nginx -t/apachectl configtest && recarregar",
            rollback="restaurar o backup e recarregar o serviço",
            false_positive_notes="Clientes muito antigos podem deixar de conectar; confirme antes.",
        )]
    if all_proto:
        return [_control(
            key="tls.protocols", title="TLS aceita protocolos amplos",
            category="posture/tls", weight=8, severity="medio", status="warn",
            value=", ".join(sorted(set(all_proto))), source=source, locator=locator,
            excerpt=excerpt,
            impact="A diretiva ampla pode habilitar protocolos obsoletos conforme a versão.",
            action="investigate",
        )]
    if modern:
        return [_control(
            key="tls.protocols", title="Protocolos TLS modernos",
            category="posture/tls", weight=8, severity="alto", status="pass",
            value=", ".join(sorted(set(modern))), source=source, locator=locator,
            excerpt=excerpt, impact="Somente protocolos TLS modernos foram configurados.",
            action="none",
        )]
    return [_unknown("tls.protocols", "Protocolos TLS", "posture/tls", 8,
                     "configuração TLS presente, mas sem diretiva de protocolo legível")]


# ---------------------------------------------------------------- Docker e portas

def parse_docker_ports(text: str) -> list[tuple[int, int, str]]:
    found: set[tuple[int, int, str]] = set()
    for match in re.finditer(r"(?:0\.0\.0\.0|\[::\]|:::):(\d+)->(\d+)/(tcp|udp)", text):
        found.add((int(match.group(1)), int(match.group(2)), match.group(3)))
    return sorted(found)


def parse_ss_listeners(text: str) -> set[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        host, port = _split_endpoint(local)
        if host in {"0.0.0.0", "::", "*", "[::]"}:
            ports.add(port)
    return ports


def _split_endpoint(local: str) -> tuple[str, int]:
    local = local.split("%", 1)[0]
    if local.startswith("["):
        host, _, rest = local.partition("]")
        host = host + "]"
        port_text = rest.lstrip(":")
    else:
        host, _, port_text = local.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    return host, port


def _proc_listeners(host: Host) -> set[int]:
    ports: set[int] = set()
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        text = host.read_text(name)
        if not text:
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            local = fields[1]
            address_hex, _, port_hex = local.rpartition(":")
            if address_hex not in {
                "00000000",  # IPv4 0.0.0.0
                "00000000000000000000000000000000",  # IPv6 ::
            }:
                continue
            try:
                ports.add(int(port_hex, 16))
            except ValueError:
                continue
    return ports


def check_docker(host: Host) -> list[Control]:
    socket_st = host.stat_path("/var/run/docker.sock")
    controls: list[Control] = []
    if socket_st is not None:
        mode = host.mode(socket_st)
        bad = bool(mode & 0o002)
        warn = bool(mode & 0o004)
        controls.append(_control(
            key="docker.socket", title="Permissão do socket Docker",
            category="posture/docker", weight=8,
            severity="critico" if bad else "alto",
            status="fail" if bad else "warn" if warn else "pass",
            value=f"modo={mode:04o} dono={host.owner(socket_st)}",
            source=str(host.path("/var/run/docker.sock")), locator="modo e dono",
            excerpt=f"modo={mode:04o}; esperado: 0660 root:docker",
            impact="Quem acessa o socket Docker controla containers e, na prática, o host.",
            action="patch" if bad or warn else "none",
            command="chown root:docker /var/run/docker.sock && chmod 0660 /var/run/docker.sock",
            rollback=f"chmod {mode:04o} /var/run/docker.sock",
            false_positive_notes="Pertencer ao grupo docker já equivale a root; revise quem está no grupo.",
        ))

    docker = shutil.which("docker")
    if not docker:
        controls.append(_unknown("docker.available", "Docker", "posture/docker", 24,
                                 "docker não encontrado; inventário de containers não avaliado"))
        return controls

    proc = host.run(["docker", "ps", "--format", "{{json .}}"], timeout=10)
    if proc is None or proc.returncode != 0:
        controls.append(_unknown("docker.available", "Docker", "posture/docker", 24,
                                 "docker ps indisponível ou sem permissão"))
        return controls

    port_rows: list[tuple[int, int, str]] = []
    names: list[str] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        names.append(str(row.get("Names") or row.get("ID") or "container"))
        port_rows.extend(parse_docker_ports(str(row.get("Ports") or "")))

    published = {port for port, _, _ in port_rows}
    high = sorted(port for port in published if port in DB_PORTS)
    other = sorted(port for port in published if port not in DB_PORTS and port not in PUBLIC_WEB_PORTS)
    if high:
        controls.append(_control(
            key="docker.published_high_risk", title="Serviço de banco/admin publicado em todas as interfaces",
            category="posture/docker", weight=12, severity="alto", status="fail",
            value=", ".join(str(port) for port in high),
            source="docker ps", locator="Ports", source_type="command",
            excerpt="portas publicadas: " + ", ".join(str(port) for port in high),
            impact="Serviço sensível pode ser alcançado fora do host, sujeito apenas à autenticação do serviço.",
            action="isolate",
            command="ufw deny " + " && ufw deny ".join(f"{port}/tcp" for port in high),
            rollback="ufw delete " + " && ufw delete ".join(f"deny {port}/tcp" for port in high),
            false_positive_notes="Confirme se a exposição é intencional e se há security group/VPN.",
            observations={"containers": names, "ports": high},
        ))
    else:
        controls.append(_control(
            key="docker.published_high_risk", title="Serviço de banco/admin publicado em todas as interfaces",
            category="posture/docker", weight=12, severity="alto", status="pass",
            value="nenhuma porta sensível em 0.0.0.0",
            source="docker ps", locator="Ports", source_type="command",
            excerpt="nenhuma porta de banco/admin publicada", impact="Serviços sensíveis não estão publicados.",
            action="none",
        ))
    if other:
        controls.append(_control(
            key="docker.published_app", title="Aplicação publicada em todas as interfaces",
            category="posture/docker", weight=4, severity="medio", status="warn",
            value=", ".join(str(port) for port in other),
            source="docker ps", locator="Ports", source_type="command",
            excerpt="portas publicadas: " + ", ".join(str(port) for port in other),
            impact="Aplicação acessível fora do host; pode ser intencional, mas amplia a superfície.",
            action="investigate",
            false_positive_notes="Portas 8080/8081/8501 etc. podem ser o acesso público desejado.",
            observations={"containers": names, "ports": other},
        ))
    else:
        controls.append(_control(
            key="docker.published_app", title="Aplicação publicada em todas as interfaces",
            category="posture/docker", weight=4, severity="medio", status="pass",
            value="nenhuma porta de aplicação em 0.0.0.0",
            source="docker ps", locator="Ports", source_type="command",
            excerpt="nenhuma porta de aplicação publicada", impact="Aplicações não estão publicadas.",
            action="none",
        ))

    ids: list[str] = []
    # Reconsulta enxuta para inspecionar privilégios sem depender do JSON do ps.
    list_proc = host.run(["docker", "ps", "-q"], timeout=10)
    if list_proc is not None and list_proc.returncode == 0:
        ids = [line.strip() for line in list_proc.stdout.splitlines() if line.strip()]
    if ids:
        inspect = host.run(
            ["docker", "inspect", "--format",
             "{{.Name}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}", *ids],
            timeout=15,
        )
        if inspect is not None and inspect.returncode == 0:
            privileged: list[str] = []
            host_network: list[str] = []
            for line in inspect.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue
                name, flag, network = parts[0], parts[1].lower(), parts[2]
                if flag == "true":
                    privileged.append(name.lstrip("/"))
                if network == "host":
                    host_network.append(name.lstrip("/"))
            if privileged:
                controls.append(_control(
                    key="docker.privileged", title="Container privilegiado",
                    category="posture/docker", weight=8, severity="alto", status="fail",
                    value=", ".join(privileged), source="docker inspect",
                    locator="HostConfig.Privileged", source_type="command",
                    excerpt="containers privilegiados: " + ", ".join(privileged),
                    impact="Container privilegiado pode escapar do isolamento e comprometer o host.",
                    action="investigate",
                    false_positive_notes="Recriar o container sem --privileged; confirme a necessidade.",
                ))
            if host_network:
                controls.append(_control(
                    key="docker.host_network", title="Container em rede do host",
                    category="posture/docker", weight=6, severity="alto", status="fail",
                    value=", ".join(host_network), source="docker inspect",
                    locator="HostConfig.NetworkMode", source_type="command",
                    excerpt="containers com NetworkMode=host: " + ", ".join(host_network),
                    impact="Container compartilha a pilha de rede do host e amplia o impacto.",
                    action="investigate",
                ))
    return controls


def check_listening(host: Host, docker_high: set[int]) -> list[Control]:
    ports: set[int] = set()
    source = ""
    source_type = "code"
    ss_ok = False
    if host.can_run:
        proc = host.run(["ss", "-lntH"], timeout=8)
        if proc is not None and proc.returncode == 0:
            ports = parse_ss_listeners(proc.stdout or "")
            source = "ss -lntH"
            source_type = "command"
            ss_ok = True
    if not ss_ok:
        ports = _proc_listeners(host)
        source = "/proc/net/tcp{,6}" if ports else source
        source_type = "code"
    if not source:
        return [_unknown("net.listening", "Portas em todas as interfaces",
                         "posture/firewall", 10, "ss e /proc/net/tcp indisponíveis")]
    exposed = sorted(port for port in ports if port in DB_PORTS and port not in docker_high)
    if exposed:
        return [_control(
            key="net.listening", title="Porta de banco/admin em todas as interfaces",
            category="posture/firewall", weight=10, severity="alto", status="fail",
            value=", ".join(str(port) for port in exposed), source=source,
            locator="LISTEN 0.0.0.0/[::]", source_type=source_type,
            excerpt="portas em todas as interfaces: " + ", ".join(str(port) for port in exposed),
            impact="Serviço sensível alcançável fora do host, sujeito à autenticação do serviço.",
            action="isolate",
            command="ufw deny " + " && ufw deny ".join(f"{port}/tcp" for port in exposed),
            rollback="ufw delete " + " && ufw delete ".join(f"deny {port}/tcp" for port in exposed),
            false_positive_notes="Pode ser protegido por firewall externo/VPN; confirme antes de bloquear.",
        )]
    return [_control(
        key="net.listening", title="Portas em todas as interfaces",
        category="posture/firewall", weight=10, severity="alto", status="pass",
        value="nenhuma porta de banco/admin exposta",
        source=source, locator="LISTEN 0.0.0.0/[::]", source_type=source_type,
        excerpt="nenhuma porta sensível em todas as interfaces",
        impact="Não foi observada exposição direta de banco/admin.",
        action="none",
    )]


# ---------------------------------------------------------------- atualizações

def check_updates(host: Host) -> list[Control]:
    controls: list[Control] = []
    reboot = host.path("/run/reboot-required")
    if reboot.exists():
        controls.append(_control(
            key="updates.reboot", title="Atualizações aguardando reinício",
            category="posture/updates", weight=4, severity="medio", status="warn",
            value="reboot-required presente", source=str(reboot),
            locator="arquivo de estado", excerpt="sistema sinaliza reinício pendente",
            impact="Biblioteca ou kernel atualizado só entra em vigor após reiniciar.",
            action="patch",
            command="agendar janela: apt-get update && apt-get upgrade && reboot",
            rollback="manter snapshot; reboot não tem rollback automático",
            false_positive_notes="Confirme se o serviço crítico pode reiniciar.",
        ))
    else:
        controls.append(_control(
            key="updates.reboot", title="Atualizações aguardando reinício",
            category="posture/updates", weight=4, severity="medio", status="pass",
            value="sem reboot-required", source=str(reboot),
            locator="arquivo de estado", excerpt="nenhum reinício pendente sinalizado",
            impact="Não há indicação local de atualização pendente de reboot.",
            action="none",
        ))

    auto_text = host.read_text("/etc/apt/apt.conf.d/20auto-upgrades")
    enabled = False
    if auto_text:
        enabled = bool(re.search(r'Unattended-Upgrade\s+"?1"?\s*;', auto_text, re.I))
    controls.append(_control(
        key="updates.unattended", title="Atualizações automáticas de segurança",
        category="posture/updates", weight=2, severity="baixo",
        status="pass" if enabled else "warn",
        value="habilitado" if enabled else "não configurado",
        source=str(host.path("/etc/apt/apt.conf.d/20auto-upgrades")),
        locator="APT::Periodic::Unattended-Upgrade",
        excerpt="unattended-upgrades habilitado" if enabled else "configuração ausente ou desabilitada",
        impact="Sem atualização automática, correções de segurança dependem de ação manual.",
        action="monitor",
        false_positive_notes="Em produção, atualização automática pode exigir janela controlada.",
    ))
    return controls


# ---------------------------------------------------------------- baseline

def baseline_values(controls: list[Control]) -> dict[str, dict[str, str]]:
    return {
        control.key: {"value": control.value, "status": control.status}
        for control in sorted(controls, key=lambda item: item.key)
    }


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"não foi possível ler o baseline: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline não é JSON válido: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != BASELINE_VERSION:
        raise ValueError(f"baseline com versão não suportada (esperado {BASELINE_VERSION})")
    controls = raw.get("controls")
    if not isinstance(controls, dict):
        raise ValueError("baseline sem objeto controls")
    normalized: dict[str, str] = {}
    for key, item in controls.items():
        if isinstance(item, dict):
            normalized[str(key)] = str(item.get("value", ""))
        else:
            normalized[str(key)] = str(item)
    return {
        "raw": raw,
        "values": normalized,
        "created_at": str(raw.get("created_at", "")),
        "host": str(raw.get("host", "")),
        "score": raw.get("score"),
    }


def write_baseline(path: Path, host: Host, score: int | None, controls: list[Control],
                   now: datetime) -> None:
    if path.is_symlink():
        raise ValueError("recusando escrever baseline em symlink")
    parent = path.parent
    if not parent.is_dir():
        raise ValueError(f"diretório do baseline não existe: {parent}")
    payload = {
        "version": BASELINE_VERSION,
        "tool": TOOL,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host_name(host),
        "score": score,
        "controls": baseline_values(controls),
    }
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ValueError(f"não foi possível abrir o baseline para escrita: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o600)
    except OSError as exc:
        raise ValueError(f"falha ao escrever o baseline: {exc}") from exc


def drift_report(before: dict[str, Any], controls: list[Control], score: int | None,
                 host: Host) -> dict[str, Any]:
    after = {control.key: control for control in controls}
    items: list[dict[str, Any]] = []
    for key in sorted(set(before["values"]) | set(after)):
        old = before["values"].get(key)
        control = after.get(key)
        new = control.value if control else None
        if old == new:
            continue
        old_status = ""
        raw_controls = before["raw"].get("controls", {})
        old_item = raw_controls.get(key)
        if isinstance(old_item, dict):
            old_status = str(old_item.get("status", ""))
        new_status = control.status if control else "removido"
        if new_status in {"unknown", "na", "removido"}:
            direction = "nao_avaliado"
        elif old_status in {"fail", "warn"} and new_status == "pass":
            direction = "melhoria"
        elif old_status == "pass" and new_status in {"fail", "warn"}:
            direction = "regressao"
        else:
            direction = "alteracao"
        items.append({
            "key": key,
            "title": control.title if control else "controle removido",
            "before": old,
            "after": new,
            "before_status": old_status,
            "after_status": new_status,
            "direction": direction,
        })
    before_score = before["score"] if isinstance(before["score"], (int, float)) else None
    score_delta = None
    if isinstance(before_score, (int, float)) and isinstance(score, (int, float)):
        score_delta = round(score - before_score)
    host_note = ""
    if before["host"] and before["host"] != host_name(host):
        host_note = f"baseline criado em outro host: {before['host']}"
        host.notes.append(host_note)
    return {
        "baseline_created_at": before["created_at"],
        "baseline_host": before["host"],
        "score_before": before_score,
        "score_after": score,
        "score_delta": score_delta,
        "changed": len(items),
        "regressions": sum(1 for item in items if item["direction"] == "regressao"),
        "improvements": sum(1 for item in items if item["direction"] == "melhoria"),
        "items": items,
        "host_note": host_note,
    }


# ---------------------------------------------------------------- resultado

def host_name(host: Host) -> str:
    return os.environ.get("GAARA_HOST") or platform.node() or "desconhecido"


def run_checks(host: Host, app_root: Path | None, ssh_config: str | None) -> list[Control]:
    controls: list[Control] = []
    controls.extend(check_ssh(host, ssh_config))
    controls.extend(check_firewall(host))
    controls.extend(check_kernel(host))
    controls.extend(check_permissions(host))
    controls.extend(check_uid0(host))
    controls.extend(check_app_root(host, app_root))
    controls.extend(check_tls(host))
    controls.extend(check_docker(host))
    docker_high = {
        port
        for control in controls
        if control.key == "docker.published_high_risk" and control.status in {"fail", "warn"}
        for port in re.findall(r"\b(\d{2,5})\b", control.value)
    }
    controls.extend(check_listening(host, {int(port) for port in docker_high}))
    controls.extend(check_updates(host))
    return controls


def score_controls(controls: list[Control]) -> tuple[int | None, str, int, int, float]:
    total = sum(control.weight for control in controls if control.weight > 0)
    assessed = sum(
        control.weight for control in controls
        if control.weight > 0 and control.assessed
    )
    lost = 0.0
    for control in controls:
        if control.status == "fail":
            lost += control.weight
        elif control.status == "warn":
            lost += control.weight / 2
    if assessed == 0 or total == 0 or assessed < total * 0.4:
        return None, "insuficiente", assessed, total, lost
    score = max(0, min(100, round(100 * (assessed - lost) / assessed)))
    return score, "calculado", assessed, total, lost


def finalize(host: Host, controls: list[Control], *, scan_id: str, now: datetime,
             baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    ordered = sorted(
        controls,
        key=lambda item: (SEVERITY_RANK[item.severity], CONFIDENCE_RANK[item.confidence], item.key),
    )
    findings: list[dict[str, Any]] = []
    for index, control in enumerate(ordered, 1):
        if control.status not in {"fail", "warn"}:
            continue
        action = control.action
        if action not in triage.ACTIONS:
            action = "investigate"
        requires = action not in triage.NO_APPROVAL_ACTIONS
        recommendation: dict[str, Any] = {"action": action, "requires_approval": requires}
        if control.command:
            recommendation["command"] = control.command
        if control.rollback:
            recommendation["rollback"] = control.rollback
        if requires and not recommendation.get("rollback"):
            recommendation["rollback"] = "reverter manualmente após backup"
        finding = {
            "id": f"F-{index:03d}",
            "title": control.title,
            "category": control.category,
            "severity": control.severity,
            "confidence": control.confidence,
            "evidence": [{
                "source": control.source,
                "locator": control.locator,
                "excerpt": control.excerpt[:EXCERPT_MAX],
                "redacted": REDACTION_ENABLED,
                "source_type": control.source_type,
            }],
            "impact": control.impact,
            "recommendation": recommendation,
            "false_positive_notes": control.false_positive_notes,
            "not_observed": list(dict.fromkeys(control.not_observed)),
            "observations": {
                "key": control.key,
                "status": control.status,
                "value": control.value,
                "weight": control.weight,
                **control.observations,
            },
        }
        findings.append(finding)

    counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
    for item in findings:
        counts[item["severity"]] += 1
    verdict = "incidente" if counts["critico"] else "atencao" if counts["alto"] or counts["medio"] else "estavel"
    score, score_status, assessed, total, lost = score_controls(controls)
    drift = drift_report(baseline, controls, score, host) if baseline else None

    notes: list[str] = list(host.notes)
    for control in controls:
        if control.status == "unknown":
            notes.append(f"não avaliado: {control.title} — {control.excerpt}")
    notes = list(dict.fromkeys(note for note in notes if note))
    sources = sorted(host.sources)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "id": scan_id,
            "tool": TOOL,
            "host": host_name(host),
            "started_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window": {
                "from": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "to": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "sources": sources,
            "limits": {
                "bytes_read": host.bytes_read,
                "lines_read": host.lines_read,
                "truncated": host.truncated,
                "controls_total": len(controls),
                "controls_assessed": sum(1 for control in controls if control.assessed),
                "assessed_weight": assessed,
                "total_weight": total,
            },
        },
        "findings": findings,
        "summary": {
            "verdict": verdict,
            "counts": counts,
            "correlations": [],
            "not_observed": notes,
            "score": score,
            "score_status": score_status,
            "score_interpretation": _score_interpretation(score),
            "assessed_weight": assessed,
            "total_weight": total,
            "lost_points": round(lost, 1),
            "baseline": {
                "path": str(baseline.get("path", "")) if baseline else None,
                "created_at": baseline["created_at"] if baseline else None,
                "host": baseline["host"] if baseline else None,
            } if baseline else None,
            "drift": drift,
        },
    }
    return result


def _score_interpretation(score: int | None) -> str:
    if score is None:
        return "não calculado: cobertura insuficiente de controles"
    if score >= 90:
        return "boa postura nos controles avaliados"
    if score >= 70:
        return "postura razoável, com correções pendentes"
    if score >= 40:
        return "postura fraca; priorize os achados altos/críticos"
    return "postura crítica; trate os achados críticos primeiro"


# ---------------------------------------------------------------- Markdown

def render_markdown(result: dict[str, Any]) -> str:
    scan = result["scan"]
    summary = result["summary"]
    counts = summary["counts"]
    score = summary["score"]
    score_text = f"{score}/100" if score is not None else "não calculado"
    coverage = "?"
    if summary["total_weight"]:
        coverage = f"{round(100 * summary['assessed_weight'] / summary['total_weight'])}%"
    lines = [
        f"# Postura de segurança — {scan['host']}",
        "",
        f"**Score:** {score_text} — {summary['score_interpretation']}",
        f"**Cobertura:** {coverage} do peso dos controles",
        f"**Veredito:** {summary['verdict']}",
        f"**Quando:** {scan['started_at']}",
        f"**Achados:** " + " · ".join(
            f"{SEVERITY_LABEL[level].lower()} {counts[level]}"
            for level in ("critico", "alto", "medio", "baixo")
        ),
        "",
    ]
    if summary["drift"]:
        drift = summary["drift"]
        delta = drift.get("score_delta")
        delta_text = f"{delta:+d}" if isinstance(delta, int) else "?"
        lines += [
            f"**Drift:** {drift['changed']} mudança(s), score {delta_text} "
            f"({drift['regressions']} regressão(ões), {drift['improvements']} melhoria(s))",
            "",
        ]

    actionable = [item for item in result["findings"] if item["recommendation"]["action"] in {"patch", "isolate"}]
    top = (actionable or result["findings"])[:5]
    if top:
        lines += ["## Top 5 correções", "", "| # | Correção | Sev | Peso | Ação |", "|---|---|---|---|---|"]
        for index, item in enumerate(top, 1):
            lines.append(
                f"| {index} | {item['title']} | {SEVERITY_LABEL[item['severity']]} | "
                f"{item['observations'].get('weight', '?')} | {item['recommendation']['action']} |"
            )
        lines.append("")

    lines += ["## Achados", ""]
    if not result["findings"]:
        lines += ["Nenhum achado acima do limiar nos controles avaliados.", ""]
    for item in result["findings"]:
        lines += [
            f"### [{SEVERITY_LABEL[item['severity']]}] {item['title']} ({item['id']})",
            "",
            f"- **Categoria:** `{item['category']}`",
            f"- **Confiança:** {item['confidence']}",
            "- **Evidência:**",
        ]
        for evidence in item["evidence"]:
            lines.append(f"  - `{evidence['source']}` {evidence['locator']}: `{evidence['excerpt']}`")
        lines += [f"- **Impacto:** {item['impact']}"]
        action = item["recommendation"]["action"]
        suffix = " (requer sua aprovação; nada foi alterado)" if item["recommendation"].get("requires_approval") else ""
        lines.append(f"- **Recomendação:** {action}{suffix}")
        if item["recommendation"].get("command"):
            lines.append(f"  - Comando: `{item['recommendation']['command']}`")
        if item["recommendation"].get("rollback"):
            lines.append(f"  - Rollback: {item['recommendation']['rollback']}")
        if item.get("false_positive_notes"):
            lines.append(f"- **Falso positivo:** {item['false_positive_notes']}")
        for note in item.get("not_observed", []):
            lines.append(f"- **Não observado:** {note}")
        lines.append("")

    if summary["drift"]:
        drift = summary["drift"]
        lines += ["## Drift desde o baseline", ""]
        if drift.get("host_note"):
            lines.append(f"> {drift['host_note']}")
            lines.append("")
        if not drift["items"]:
            lines.append("Nenhuma mudança de valor desde o baseline.")
        else:
            lines += ["| Controle | Antes | Agora | Direção |", "|---|---|---|---|"]
            for item in drift["items"]:
                lines.append(
                    f"| `{item['key']}` | `{item['before']}` | `{item['after']}` | {item['direction']} |"
                )
        lines.append("")

    lines += ["## Não observado", ""]
    if summary["not_observed"]:
        lines += [f"- {note}" for note in summary["not_observed"]]
    else:
        lines.append("- nada relevante")
    lines += [
        "",
        "> Auditoria somente leitura. Nenhuma configuração foi alterada.",
        "> Score é heurístico e cobre apenas os controles avaliados; não é certificação.",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auditoria de postura somente leitura de host Linux.",
        epilog="Exemplo: ./harden_check.py --format md --output /tmp/postura.md",
    )
    parser.add_argument("--root", type=Path, default=Path("/"),
                        help="raiz alternativa para auditoria offline (desativa comandos)")
    parser.add_argument("--app-root", type=Path,
                        help="diretório da aplicação para checar permissão de .env/config")
    parser.add_argument("--ssh-config", help="caminho do sshd_config relativo à raiz")
    parser.add_argument("--baseline", type=Path, help="baseline JSON para comparar drift")
    parser.add_argument("--write-baseline", type=Path, help="grava o inventário atual como baseline")
    parser.add_argument("--no-commands", action="store_true", help="não executa comandos externos")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--output", type=Path, help="arquivo de saída (padrão: stdout)")
    parser.add_argument("--now", help="fixa o instante do scan (ISO 8601), útil para reprodutibilidade")
    parser.add_argument("--host", default="", help="identificador do host")
    parser.add_argument("--scan-id", help="ID do scan (padrão: gaara-YYYYMMDD-0001)")
    parser.add_argument("--redact", choices=("on", "off"), default="on")
    parser.add_argument("--redact-off-reason", help="justificativa obrigatória para --redact off")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    global REDACTION_ENABLED
    if args.redact == "off" and not args.redact_off_reason:
        print("erro: --redact off exige --redact-off-reason", file=sys.stderr)
        return 2
    if args.redact == "off":
        REDACTION_ENABLED = False
        triage.REDACTION_ENABLED = False
        triage.redact = lambda text: triage.sanitize(text.replace("\r", " ").replace("\n", " "))  # noqa: E731
        print("aviso: redação desativada; não compartilhe a saída", file=sys.stderr)

    try:
        now = parse_now(args.now)
    except ValueError:
        print(f"erro: --now inválido: {args.now}", file=sys.stderr)
        return 2
    if args.host:
        os.environ["GAARA_HOST"] = args.host
    root = args.root.expanduser().resolve()
    if not root.is_dir():
        print(f"erro: --root não é diretório: {root}", file=sys.stderr)
        return 1
    if args.app_root is not None:
        app_root = args.app_root.expanduser().resolve()
        if not app_root.is_dir():
            print(f"erro: --app-root não é diretório: {app_root}", file=sys.stderr)
            return 2
    else:
        app_root = None

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
            baseline["path"] = str(args.baseline)
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 1

    host = Host(root, args.no_commands, now)
    controls = run_checks(host, app_root, args.ssh_config)
    scan_id = args.scan_id or f"gaara-{now.strftime('%Y%m%d')}-0001"
    result = finalize(host, controls, scan_id=scan_id, now=now, baseline=baseline)

    errors = triage.validate(result)
    if errors:
        for error in errors:
            print(f"schema: {error}", file=sys.stderr)
        return 1

    if args.write_baseline:
        try:
            write_baseline(args.write_baseline, host, result["summary"]["score"], controls, now)
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 1

    output = render_markdown(result) if args.format == "md" else json.dumps(
        result, ensure_ascii=False, indent=2, sort_keys=False
    )
    if args.output:
        try:
            args.output.write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"erro ao escrever {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        print(output)

    high = result["summary"]["counts"]["critico"] + result["summary"]["counts"]["alto"]
    return 3 if high else 0


if __name__ == "__main__":
    sys.exit(main())
