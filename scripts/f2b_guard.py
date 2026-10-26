#!/usr/bin/env python3
"""f2b_guard.py — camada de ação para Fail2ban, com allowlist e auditoria.

Este é o **único** script da skill que altera o sistema. Ele implementa o
protocolo de references/safe-operations.md:

- allowlist obrigatória e fail-closed (config inválida = nenhuma ação);
- apenas IP único, jail validado e presente em `allowed_jails`;
- TTL obrigatório, com teto por severidade e teto global de 72 h;
- dry-run por padrão; `--execute` exige `--approved-by`;
- auditoria append-only em JSONL, modo 0600, com intenção e resultado;
- unban e sweep só tocam bans criados por esta ferramenta;
- nunca usa shell e nunca usa `sudo`.

Uso:
    ./f2b_guard.py check --jail sshd
    ./f2b_guard.py check --jail sshd --ip 203.0.113.45
    ./f2b_guard.py ban --ip 203.0.113.45 --jail sshd --severity alto \
        --confidence alta --reason "312 falhas SSH" --evidence "auth.log:1234"
    ./f2b_guard.py ban ... --execute --approved-by seu-nome
    ./f2b_guard.py unban --ip 203.0.113.45 --jail sshd --reason "falso positivo" \
        --execute --approved-by seu-nome
    ./f2b_guard.py sweep
    ./f2b_guard.py sweep --execute --approved-by seu-nome

Códigos de saída:
    0  sucesso (ou dry-run válido)
    1  erro de execução, cliente, verificação ou auditoria
    2  recusa de política ou uso incorreto
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

TOOL = "f2b_guard"
TOOL_VERSION = "1.0"
CONFIG_VERSION = 1
HARD_MAX_TTL = 72 * 3600
MAX_REASON = 500
MAX_EVIDENCE = 1000
MAX_DETAIL = 1000
MAX_APPROVER = 64
MAX_SWEEP_HARD = 100
JAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

REQUIRED_ALLOWLIST = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fe80::/10",
    "224.0.0.0/4",
    "ff00::/8",
    "fc00::/7",
)
DEFAULT_TTL = {"medio": 3600, "alto": 86400, "max": HARD_MAX_TTL}
SEVERITY_MAX = {"medio": 4 * 3600, "alto": HARD_MAX_TTL, "critico": HARD_MAX_TTL}
KNOWN_CONFIG_KEYS = {
    "version", "client", "socket", "timeout", "allowed_jails", "allowlist",
    "protected_ips", "operator_ips", "ttl", "max_sweep", "audit_path",
}
KNOWN_TTL_KEYS = {"medio", "alto", "max"}
STATUS_LABEL = {
    "planned": "planejado (nada foi alterado)",
    "ok": "executado e verificado",
    "error": "erro",
    "refused": "recusado pela política",
    "already_banned": "já estava banido — nada a fazer",
    "not_banned": "não estava banido — estado já conforme",
    "blocked": "bloqueado pela política",
}


# --------------------------------------------------------------- exceções

class ConfigError(Exception):
    """Configuração ausente, ilegível ou inválida."""


class PolicyError(Exception):
    """A ação viola allowlist, TTL, escopo ou protocolo de aprovação."""


class AuditError(Exception):
    """A trilha de auditoria não pôde ser lida ou escrita com segurança."""


class ClientError(Exception):
    """O cliente Fail2ban falhou, não existe ou devolveu saída inesperada."""


# ------------------------------------------------------------------- tempo

def parse_iso(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(f"{field_name} inválido: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_duration(value: str) -> int:
    text = value.strip().lower()
    match = re.fullmatch(r"(\d+)([smhd])", text)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        seconds = amount * factor
    elif text.isdigit():
        seconds = int(text)
    else:
        raise PolicyError(f"TTL inválido: {value!r} (use 900, 30m, 4h ou 1d)")
    if seconds <= 0:
        raise PolicyError("TTL precisa ser maior que zero; ban permanente é proibido")
    return seconds


def format_duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


# ---------------------------------------------------------- dados e redação

_SECRET_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "[CHAVE-PRIVADA]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret)"
                r"\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"), r"\1=[REDACTADO]"),
    (re.compile(r"(?i)(--?(?:password|passwd|token|secret|api[_-]?key|access[_-]?key))\s+(\S+)"),
     r"\1 [REDACTADO]"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+"),
     r"\1: [REDACTADO]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTADO]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "[JWT]"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://[REDACTADO]@"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
]


def sanitize(text: str) -> str:
    """Neutraliza caracteres de controle vindos de config, argv ou cliente."""
    out: list[str] = []
    for char in text.replace("\r", " ").replace("\n", " "):
        code = ord(char)
        if char == "\t":
            out.append(" ")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    return "".join(out)


def redact(text: str, limit: int = MAX_DETAIL) -> str:
    value = str(text)
    for pattern, replacement in _SECRET_RULES:
        value = pattern.sub(replacement, value)
    value = sanitize(value)
    if len(value) > limit:
        value = value[:limit].rstrip() + "... [TRUNCADO]"
    return value


def safe_detail(*parts: str) -> str:
    joined = " ".join(part.strip() for part in parts if part and part.strip())
    return redact(joined, MAX_DETAIL)


# --------------------------------------------------------------- política

@dataclass
class Config:
    path: Path
    client: str
    socket: str | None
    timeout: int
    allowed_jails: tuple[str, ...]
    allowlist: tuple[ipaddress._BaseNetwork, ...]
    protected_ips: tuple[ipaddress._BaseNetwork, ...]
    operator_ips: tuple[ipaddress._BaseNetwork, ...]
    ttl_medio: int
    ttl_alto: int
    max_ttl: int
    max_sweep: int
    audit_path: Path

    def client_argv(self, args: Sequence[str]) -> list[str]:
        argv = [self.client]
        if self.socket:
            argv += ["-s", self.socket]
        return argv + list(args)


def _parse_networks(values: Any, field_name: str) -> tuple[ipaddress._BaseNetwork, ...]:
    if not isinstance(values, list):
        raise ConfigError(f"{field_name} precisa ser uma lista")
    networks: list[ipaddress._BaseNetwork] = []
    for index, raw in enumerate(values, 1):
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError(f"{field_name}[{index}] precisa ser IP ou CIDR em texto")
        text = raw.strip()
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            raise ConfigError(f"{field_name}[{index}] inválido: {text!r}") from exc
        if network.prefixlen == 0:
            raise ConfigError(f"{field_name}[{index}] não pode ser 0.0.0.0/0 nem ::/0")
        networks.append(network)
    return tuple(networks)


def load_config(path: Path) -> Config:
    if not path.exists():
        raise ConfigError(
            f"config não encontrada: {path}. Copie assets/config.example.json para "
            "assets/config.json e revise allowlist/audit_path."
        )
    if path.is_symlink():
        raise ConfigError(f"config não pode ser symlink: {path}")
    try:
        if path.stat().st_size > 64 * 1024:
            raise ConfigError(f"config grande demais (limite 64 KiB): {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"não foi possível ler {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"JSON inválido em {path}: linha {exc.lineno}, coluna {exc.colno}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("a raiz da config precisa ser um objeto JSON")

    unknown = sorted(set(raw) - KNOWN_CONFIG_KEYS)
    if unknown:
        raise ConfigError(f"chaves desconhecidas na config: {', '.join(unknown)}")
    missing = sorted({"version", "client", "allowed_jails", "allowlist", "audit_path"} - set(raw))
    if missing:
        raise ConfigError(f"chaves obrigatórias ausentes: {', '.join(missing)}")
    if raw["version"] != CONFIG_VERSION or isinstance(raw["version"], bool):
        raise ConfigError(f"version precisa ser {CONFIG_VERSION}")

    client = raw["client"]
    if not isinstance(client, str) or not client.strip():
        raise ConfigError("client precisa ser um caminho ou nome de executável")
    if any(ch in client for ch in ("\x00", "\n", "\r")):
        raise ConfigError("client contém caractere inválido")
    if Path(client.strip()).name in {"sudo", "su", "doas", "pkexec"}:
        raise ConfigError("client não pode ser um elevador de privilégio; use o binário ou socket")

    socket = raw.get("socket")
    if socket is not None:
        if not isinstance(socket, str) or not socket.strip():
            raise ConfigError("socket precisa ser null ou um caminho")
        if not os.path.isabs(socket):
            raise ConfigError("socket precisa ser caminho absoluto")
        if any(ch in socket for ch in ("\x00", "\n", "\r")):
            raise ConfigError("socket contém caractere inválido")

    timeout = raw.get("timeout", 10)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        raise ConfigError("timeout precisa ser inteiro entre 1 e 60 segundos")

    allowed_jails = raw["allowed_jails"]
    if not isinstance(allowed_jails, list) or not allowed_jails:
        raise ConfigError("allowed_jails precisa ser uma lista não vazia")
    jails: list[str] = []
    for index, jail in enumerate(allowed_jails, 1):
        if not isinstance(jail, str) or not JAIL_RE.fullmatch(jail):
            raise ConfigError(f"allowed_jails[{index}] inválido: {jail!r}")
        if jail in jails:
            raise ConfigError(f"jail duplicado em allowed_jails: {jail}")
        jails.append(jail)

    allowlist = _parse_networks(raw["allowlist"], "allowlist")
    allowlist_text = {str(network) for network in allowlist}
    missing_ranges = [item for item in REQUIRED_ALLOWLIST if item not in allowlist_text]
    if missing_ranges:
        raise ConfigError(
            "allowlist não contém as faixas obrigatórias: " + ", ".join(missing_ranges)
        )

    protected = _parse_networks(raw.get("protected_ips", []), "protected_ips")
    operator = _parse_networks(raw.get("operator_ips", []), "operator_ips")

    ttl = raw.get("ttl", DEFAULT_TTL)
    if not isinstance(ttl, dict):
        raise ConfigError("ttl precisa ser um objeto")
    unknown_ttl = sorted(set(ttl) - KNOWN_TTL_KEYS)
    if unknown_ttl:
        raise ConfigError(f"chaves desconhecidas em ttl: {', '.join(unknown_ttl)}")
    merged_ttl = {**DEFAULT_TTL, **ttl}
    for key in KNOWN_TTL_KEYS:
        value = merged_ttl[key]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ConfigError(f"ttl.{key} precisa ser inteiro positivo")
    max_ttl = merged_ttl["max"]
    if max_ttl > HARD_MAX_TTL:
        raise ConfigError(f"ttl.max não pode exceder {HARD_MAX_TTL}s (72h)")
    if merged_ttl["medio"] > max_ttl or merged_ttl["alto"] > max_ttl:
        raise ConfigError("ttl.medio e ttl.alto não podem exceder ttl.max")

    max_sweep = raw.get("max_sweep", 10)
    if not isinstance(max_sweep, int) or isinstance(max_sweep, bool) or not 1 <= max_sweep <= MAX_SWEEP_HARD:
        raise ConfigError(f"max_sweep precisa ser inteiro entre 1 e {MAX_SWEEP_HARD}")

    audit_path = raw["audit_path"]
    if not isinstance(audit_path, str) or not audit_path.strip():
        raise ConfigError("audit_path precisa ser um caminho")
    if not os.path.isabs(audit_path):
        raise ConfigError("audit_path precisa ser absoluto")
    if any(ch in audit_path for ch in ("\x00", "\n", "\r")):
        raise ConfigError("audit_path contém caractere inválido")

    return Config(
        path=path,
        client=client.strip(),
        socket=socket,
        timeout=timeout,
        allowed_jails=tuple(jails),
        allowlist=allowlist,
        protected_ips=protected,
        operator_ips=operator,
        ttl_medio=merged_ttl["medio"],
        ttl_alto=merged_ttl["alto"],
        max_ttl=max_ttl,
        max_sweep=max_sweep,
        audit_path=Path(audit_path),
    )


def validate_ip(value: str) -> ipaddress._BaseAddress:
    text = value.strip()
    if "/" in text:
        raise PolicyError(f"apenas IP único é permitido, não rede/CIDR: {value}")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise PolicyError(f"IP inválido: {value!r}") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise PolicyError("IPv6 mapeado não é permitido; use o IPv4 canônico")
    return address


def validate_correlation(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text or len(text) > 100:
        raise PolicyError("--correlation-id precisa ter de 1 a 100 caracteres")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise PolicyError("--correlation-id contém caractere de controle")
    return text


def validate_jail_name(jail: str) -> str:
    if not JAIL_RE.fullmatch(jail):
        raise PolicyError(f"nome de jail inválido: {jail!r}")
    return jail


def validate_jail(config: Config, jail: str) -> str:
    validate_jail_name(jail)
    if jail not in config.allowed_jails:
        raise PolicyError(
            f"jail {jail!r} não está em allowed_jails "
            f"({', '.join(config.allowed_jails)})"
        )
    return jail


def ssh_client_ips() -> set[ipaddress._BaseAddress]:
    found: set[ipaddress._BaseAddress] = set()
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        value = os.environ.get(var, "").strip()
        if not value:
            continue
        candidate = value.split()[0]
        try:
            found.add(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return found


def _matching_network(
    ip: ipaddress._BaseAddress,
    networks: Iterable[ipaddress._BaseNetwork],
) -> ipaddress._BaseNetwork | None:
    for network in networks:
        if network.version == ip.version and ip in network:
            return network
    return None


def target_policy(config: Config, ip: ipaddress._BaseAddress) -> dict[str, str]:
    """Retorna {'allowed': 'true'|'false', 'reason': ...}. Fail-closed."""
    allow_net = _matching_network(ip, config.allowlist)
    if allow_net is not None:
        return {"allowed": "false", "reason": f"IP na allowlist ({allow_net})",
                "ssh_session": "unknown"}

    protected_net = _matching_network(ip, config.protected_ips)
    if protected_net is not None:
        return {"allowed": "false", "reason": f"IP protegido ({protected_net})",
                "ssh_session": "unknown"}

    operator_net = _matching_network(ip, config.operator_ips)
    if operator_net is not None:
        return {"allowed": "false", "reason": f"IP do operador ({operator_net})",
                "ssh_session": "unknown"}

    if ip in ssh_client_ips():
        return {"allowed": "false", "reason": "é o IP da sessão SSH atual",
                "ssh_session": "true"}

    return {"allowed": "true", "reason": "fora da allowlist, de protected_ips e da sessão SSH",
            "ssh_session": "false"}


def resolve_ttl(config: Config, severity: str, raw_ttl: str | None) -> int:
    if severity == "baixo":
        raise PolicyError("severidade baixa não autoriza ban; use monitoramento")
    if severity == "critico" and raw_ttl is None:
        raise PolicyError("severidade crítica exige --ttl explícito (decisão humana)")
    if raw_ttl is None:
        ttl = config.ttl_medio if severity == "medio" else config.ttl_alto
    else:
        ttl = parse_duration(raw_ttl)
    cap = min(config.max_ttl, SEVERITY_MAX[severity])
    if ttl > cap:
        raise PolicyError(
            f"TTL {format_duration(ttl)} excede o máximo para {severity} "
            f"({format_duration(cap)})"
        )
    return ttl


def validate_prose(value: str, field_name: str, limit: int) -> str:
    text = value.strip()
    if not text:
        raise PolicyError(f"{field_name} não pode ser vazio")
    if len(text) > limit:
        raise PolicyError(f"{field_name} excede {limit} caracteres")
    return text


def require_approval(execute: bool, approved_by: str | None) -> str | None:
    if not execute:
        return None
    if approved_by is None or not approved_by.strip():
        raise PolicyError("--execute exige --approved-by com o nome de quem aprovou")
    approver = approved_by.strip()
    if len(approver) > MAX_APPROVER:
        raise PolicyError(f"--approved-by excede {MAX_APPROVER} caracteres")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in approver):
        raise PolicyError("--approved-by contém caractere de controle")
    return approver


# ---------------------------------------------------------------- cliente

def client_available(config: Config) -> bool:
    if os.sep in config.client:
        return Path(config.client).is_file() and os.access(config.client, os.X_OK)
    return shutil.which(config.client) is not None


def run_client(config: Config, args: Sequence[str]) -> tuple[list[str], int, str, str]:
    argv = config.client_argv(args)
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ClientError(f"cliente não encontrado: {config.client}") from exc
    except PermissionError as exc:
        raise ClientError(f"sem permissão para executar: {config.client}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ClientError(f"cliente excedeu {config.timeout}s") from exc
    except OSError as exc:
        raise ClientError(f"falha ao executar {config.client}: {exc}") from exc
    return argv, proc.returncode, proc.stdout or "", proc.stderr or ""


@dataclass
class JailStatus:
    jail: str
    banned: tuple[ipaddress._BaseAddress, ...]
    currently_banned: int
    raw: str


def parse_status(jail: str, output: str) -> JailStatus:
    count: int | None = None
    banned: list[ipaddress._BaseAddress] | None = None
    for line in output.splitlines():
        stripped = line.strip()
        match = re.search(r"Currently banned:\s*(\d+)\s*$", stripped)
        if match:
            count = int(match.group(1))
            continue
        marker = "Banned IP list:"
        position = stripped.find(marker)
        if position >= 0:
            tail = stripped[position + len(marker):].strip()
            parsed: list[ipaddress._BaseAddress] = []
            invalid: list[str] = []
            for token in tail.replace(",", " ").split():
                try:
                    parsed.append(ipaddress.ip_address(token))
                except ValueError:
                    invalid.append(token)
            if invalid:
                raise ClientError(
                    f"lista de banidos com token inválido no jail {jail}: "
                    + ", ".join(safe_detail(token) for token in invalid[:5])
                )
            banned = parsed
    if banned is None:
        if count == 0:
            banned = []
        else:
            raise ClientError(f"saída sem 'Banned IP list:' para o jail {jail}")
    if count is None:
        count = len(banned)
    if count != len(banned):
        raise ClientError(
            f"saída inconsistente para o jail {jail}: "
            f"Currently banned={count}, lista com {len(banned)} IP(s)"
        )
    return JailStatus(jail=jail, banned=tuple(banned), currently_banned=count, raw=output)


def get_status(config: Config, jail: str) -> JailStatus:
    _, code, stdout, stderr = run_client(config, ["status", jail])
    if code != 0:
        raise ClientError(
            f"fail2ban-client status {jail} falhou (exit {code}): {safe_detail(stderr, stdout)}"
        )
    return parse_status(jail, stdout)


# --------------------------------------------------------------- auditoria

def _refuse_unsafe_audit_path(path: Path) -> None:
    if path.is_symlink():
        raise AuditError(f"audit_path não pode ser symlink: {path}")
    if path.exists() and not path.is_file():
        raise AuditError(f"audit_path não é arquivo regular: {path}")


def _refuse_unsafe_audit_dir(path: Path) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise AuditError(f"diretório de auditoria não pode ser symlink: {parent}")
    try:
        stat_result = parent.stat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AuditError(f"não foi possível inspecionar {parent}: {exc}") from exc
    if stat_result.st_mode & 0o002 and not stat_result.st_mode & 0o1000:
        raise AuditError(f"diretório de auditoria é gravável por qualquer usuário: {parent}")


def prepare_audit(path: Path) -> None:
    parent = path.parent
    try:
        _refuse_unsafe_audit_dir(path)
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700)
        _refuse_unsafe_audit_path(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
    except OSError as exc:
        raise AuditError(f"não foi possível preparar {path}: {exc}") from exc


def append_audit(path: Path, record: dict[str, Any]) -> None:
    _refuse_unsafe_audit_path(path)
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    except OSError as exc:
        raise AuditError(f"falha ao gravar auditoria em {path}: {exc}") from exc


def record_result(
    config: Config,
    record: dict[str, Any],
    rollback: Sequence[str],
    report: dict[str, Any],
    fmt: str,
) -> bool:
    """Grava o resultado. Se a auditoria falhar, avisa e mostra o rollback."""
    try:
        append_audit(config.audit_path, record)
        return True
    except AuditError as exc:
        message = f"a ação pode ter sido executada, mas a auditoria falhou: {exc}"
        print(f"erro: {message}", file=sys.stderr)
        if rollback:
            print(f"rollback: {shlex.join([str(item) for item in rollback])}", file=sys.stderr)
        report.update({"status": "error", "detail": safe_detail(message)})
        emit(report, fmt)
        return False


def read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    _refuse_unsafe_audit_dir(path)
    _refuse_unsafe_audit_path(path)
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditError(f"auditoria inválida em {path}:{number}: {exc}") from exc
                if not isinstance(item, dict):
                    raise AuditError(f"auditoria inválida em {path}:{number}: registro não é objeto")
                if item.get("tool") != TOOL:
                    continue
                records.append(item)
    except OSError as exc:
        raise AuditError(f"não foi possível ler a auditoria {path}: {exc}") from exc
    return records


def active_bans(records: Sequence[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Último ban verificado por (IP, jail), fechado por unban confirmado."""
    active: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if record.get("phase") != "result":
            continue
        action = record.get("action")
        result = record.get("result")
        ip = record.get("ip")
        jail = record.get("jail")
        if not isinstance(ip, str) or not isinstance(jail, str):
            continue
        key = (ip, jail)
        if action == "ban" and result == "ok":
            expires_at = record.get("expires_at")
            if not isinstance(expires_at, str):
                raise AuditError(f"ban sem expires_at na auditoria: {ip} / {jail}")
            try:
                parse_iso(expires_at, "expires_at da auditoria")
            except PolicyError as exc:
                raise AuditError(str(exc)) from exc
            active[key] = record
        elif action == "unban" and result in ("ok", "not_banned"):
            active.pop(key, None)
    return active


def find_active_ban(
    records: Sequence[dict[str, Any]], ip: str, jail: str
) -> dict[str, Any] | None:
    return active_bans(records).get((ip, jail))


# ---------------------------------------------------------------- relatório

def _escape_md(value: Any) -> str:
    text = str(value).replace("\\", "\\\\")
    text = text.replace("`", "\\`").replace("|", "\\|")
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _cell(value: Any) -> str:
    # Células frequentemente contêm código inline; só o pipe quebra a tabela.
    return str(value).replace("|", "\\|")


def _table(rows: Sequence[tuple[str, str]]) -> str:
    lines = ["| Campo | Valor |", "|---|---|"]
    for field_name, value in rows:
        lines.append(f"| {_cell(field_name)} | {_cell(value)} |")
    return "\n".join(lines)


def _command_block(argv: Sequence[str]) -> str:
    return "```bash\n" + shlex.join([str(item) for item in argv]) + "\n```"


def render_markdown(report: dict[str, Any]) -> str:
    action = report.get("action")
    mode = report.get("mode", "")
    title = {
        "check": "Check de jail",
        "ban": "Ban de IP",
        "unban": "Unban de IP",
        "sweep": "Sweep de TTL vencido",
    }.get(action, action or "Relatório")
    lines = [f"# {title}", ""]
    if action != "check":
        mode_label = "EXECUÇÃO" if mode == "execute" else "SIMULAÇÃO — nada foi alterado no sistema"
        lines += [f"**Modo:** {mode_label}", f"**Status:** {STATUS_LABEL.get(str(report.get('status')), report.get('status'))}", ""]
    else:
        lines += [f"**Status:** {STATUS_LABEL.get(str(report.get('status')), report.get('status'))}", ""]

    if action == "check":
        rows = [
            ("Jail", f"`{report.get('jail')}`"),
            ("Banidos agora", str(report.get("currently_banned"))),
            ("Cliente", f"`{report.get('client')}`"),
            ("Config", f"`{report.get('config_path')}`"),
        ]
        if report.get("ip"):
            rows.append(("IP alvo", f"`{report['ip']}`"))
            rows.append(("IP está banido?", "sim" if report.get("ip_banned") else "não"))
            policy = report.get("policy") or {}
            rows.append(("Política de ban", "permitido" if policy.get("allowed") == "true" else f"bloqueado — {policy.get('reason', '')}"))
        lines += [_table(rows), ""]
        banned = report.get("banned") or []
        lines += ["**Lista de banidos**", ""]
        lines += [", ".join(f"`{ip}`" for ip in banned) if banned else "_(vazia)_", ""]
        return "\n".join(lines).rstrip() + "\n"

    if action in ("ban", "unban"):
        rows = [
            ("IP", f"`{report.get('ip')}`"),
            ("Jail", f"`{report.get('jail')}`"),
        ]
        if action == "ban":
            rows += [
                ("Severidade", str(report.get("severity"))),
                ("Confiança", str(report.get("confidence"))),
                ("TTL", f"{format_duration(report.get('ttl', 0))} ({report.get('ttl')}s)"),
                ("Expira em", f"`{report.get('expires_at')}`"),
            ]
        if report.get("ban_correlation_id"):
            rows.append(("Ban de origem", f"`{report['ban_correlation_id']}`"))
        if action == "ban":
            rows.append(("Allowlist", report.get("policy", {}).get("reason", "")))
        rows += [
            ("Cliente", f"`{report.get('client')}`"),
            ("Auditoria", f"`{report.get('audit_path')}`"),
            ("Aprovação", str(report.get("approved_by") or "pendente")),
        ]
        if report.get("client_exit") is not None:
            rows.append(("Exit do cliente", str(report.get("client_exit"))))
        if report.get("verified") is not None:
            rows.append(("Estado verificado", "sim" if report.get("verified") else "não"))
        lines += [_table(rows), ""]
        if report.get("reason"):
            lines += [f"**Motivo:** {_escape_md(report['reason'])}", ""]
        if report.get("evidence"):
            lines += [f"**Evidência:** {_escape_md(report['evidence'])}", ""]
        if report.get("detail"):
            lines += [f"**Detalhe:** {_escape_md(report['detail'])}", ""]
        lines += ["**Comando exato**", "", _command_block(report.get("command") or []), ""]
        lines += ["**Rollback**", ""]
        if report.get("rollback"):
            lines += [_command_block(report["rollback"]), ""]
        else:
            lines += ["_(nenhum — nada foi alterado)_", ""]
        if mode != "execute":
            lines += ["> Para executar, repita com `--execute --approved-by <nome>`.", ""]
        return "\n".join(lines).rstrip() + "\n"

    # sweep
    rows = [
        ("Limite desta execução", str(report.get("limit"))),
        ("Bans vencidos encontrados", str(report.get("due_total"))),
        ("Fora do limite", str(report.get("skipped"))),
        ("Auditoria", f"`{report.get('audit_path')}`"),
        ("Aprovação", str(report.get("approved_by") or "pendente")),
    ]
    lines += [_table(rows), ""]
    due = report.get("due") or []
    lines += ["**Bans vencidos**", ""]
    if due:
        lines += ["| IP | Jail | Expirou em | correlation_id |", "|---|---|---|---|"]
        for item in due:
            lines.append(f"| `{_cell(item.get('ip'))}` | `{_cell(item.get('jail'))}` | `{_cell(item.get('expires_at'))}` | `{_cell(item.get('correlation_id'))}` |")
    else:
        lines.append("_(nenhum)_")
    lines.append("")
    results = report.get("results") or []
    if results:
        lines += ["**Resultados**", "", "| IP | Jail | Resultado | Detalhe |", "|---|---|---|---|"]
        for item in results:
            lines.append(
                f"| `{_cell(item.get('ip'))}` | `{_cell(item.get('jail'))}` | {_cell(STATUS_LABEL.get(str(item.get('status')), item.get('status')))} | {_cell(item.get('detail', ''))} |"
            )
        lines.append("")
    if mode != "execute":
        lines += ["> Para executar, repita com `--execute --approved-by <nome>`.", ""]
    return "\n".join(lines).rstrip() + "\n"


def emit(report: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report), end="")


# --------------------------------------------------------------- comandos

def new_correlation_id(now: datetime) -> str:
    return f"gaara-{now.strftime('%Y%m%d')}-{os.urandom(3).hex()}"


def _base_report(action: str, config: Config, mode: str) -> dict[str, Any]:
    return {
        "tool": TOOL,
        "version": TOOL_VERSION,
        "action": action,
        "mode": mode,
        "client": config.client,
        "config_path": str(config.path),
        "audit_path": str(config.audit_path),
    }


def cmd_check(args: argparse.Namespace, config: Config, now: datetime) -> int:
    jail = validate_jail(config, args.jail)
    ip = validate_ip(args.ip) if args.ip else None
    report = _base_report("check", config, "read-only")
    report.update({"jail": jail, "status": "ok"})
    try:
        status = get_status(config, jail)
    except ClientError as exc:
        report.update({"status": "error", "detail": safe_detail(str(exc))})
        emit(report, args.format)
        return 1
    report.update({
        "banned": [str(item) for item in status.banned],
        "currently_banned": status.currently_banned,
    })
    code = 0
    if ip is not None:
        policy = target_policy(config, ip)
        report.update({
            "ip": str(ip),
            "ip_banned": ip in status.banned,
            "policy": policy,
        })
        if policy["allowed"] != "true":
            report["status"] = "blocked"
            code = 2
    emit(report, args.format)
    return code


def cmd_ban(args: argparse.Namespace, config: Config, now: datetime) -> int:
    ip = validate_ip(args.ip)
    jail = validate_jail(config, args.jail)
    severity = args.severity
    if severity not in ("medio", "alto", "critico"):
        raise PolicyError(f"severidade inválida para ban: {severity}")
    confidence = args.confidence
    if confidence not in ("media", "alta"):
        raise PolicyError("confiança baixa não autoriza ban; investigue mais")
    reason = validate_prose(args.reason, "--reason", MAX_REASON)
    evidence = validate_prose(args.evidence, "--evidence", MAX_EVIDENCE)
    ttl = resolve_ttl(config, severity, args.ttl)
    policy = target_policy(config, ip)
    if policy["allowed"] != "true":
        raise PolicyError(f"ban recusado: {policy['reason']}")

    approver = require_approval(args.execute, args.approved_by)
    expires_at = now + timedelta(seconds=ttl)
    correlation = validate_correlation(args.correlation_id) or new_correlation_id(now)
    command = config.client_argv(["set", jail, "banip", str(ip)])
    rollback = config.client_argv(["set", jail, "unbanip", str(ip)])

    report = _base_report("ban", config, "execute" if args.execute else "dry-run")
    report.update({
        "status": "planned",
        "ip": str(ip),
        "jail": jail,
        "severity": severity,
        "confidence": confidence,
        "ttl": ttl,
        "expires_at": iso_z(expires_at),
        "reason": redact(reason, MAX_REASON),
        "evidence": redact(evidence, MAX_EVIDENCE),
        "policy": policy,
        "approved_by": approver,
        "correlation_id": correlation,
        "command": command,
        "rollback": rollback,
        "client_available": client_available(config),
    })

    if not args.execute:
        emit(report, args.format)
        return 0

    status = get_status(config, jail)
    report["banned_before"] = [str(item) for item in status.banned]
    if ip in status.banned:
        report["status"] = "already_banned"
        report["detail"] = "o IP já estava banido antes desta ação; nada foi alterado"
        report["rollback"] = []
        emit(report, args.format)
        return 2

    prepare_audit(config.audit_path)
    intent = {
        "ts": iso_z(now),
        "tool": TOOL,
        "version": TOOL_VERSION,
        "phase": "intent",
        "correlation_id": correlation,
        "action": "ban",
        "ip": str(ip),
        "jail": jail,
        "severity": severity,
        "confidence": confidence,
        "ttl": ttl,
        "expires_at": iso_z(expires_at),
        "reason": redact(reason, MAX_REASON),
        "evidence": redact(evidence, MAX_EVIDENCE),
        "approved_by": approver,
        "command": command,
        "rollback": rollback,
    }
    append_audit(config.audit_path, intent)

    try:
        _, code, stdout, stderr = run_client(config, ["set", jail, "banip", str(ip)])
    except ClientError as exc:
        detail = safe_detail(str(exc))
        record = {
            **intent,
            "ts": iso_z(datetime.now(timezone.utc)),
            "phase": "result",
            "result": "error",
            "detail": detail,
        }
        if not record_result(config, record, rollback, report, args.format):
            return 1
        report.update({"status": "error", "detail": detail})
        emit(report, args.format)
        return 1

    report["client_exit"] = code
    verified = False
    verify_detail = ""
    try:
        after = get_status(config, jail)
        verified = ip in after.banned
        verify_detail = "IP confirmado na lista de banidos" if verified else "IP não aparece na lista de banidos"
    except ClientError as exc:
        verify_detail = f"estado não verificável: {safe_detail(str(exc))}"

    client_detail = safe_detail((stderr or "").strip(), (stdout or "").strip())
    if code != 0 and verified:
        verify_detail += f"; cliente retornou exit {code}, mas o estado confirma o ban"
    result = "ok" if verified else "error"
    detail = safe_detail(verify_detail, client_detail)
    record = {
        **intent,
        "ts": iso_z(datetime.now(timezone.utc)),
        "phase": "result",
        "result": result,
        "client_exit": code,
        "verified_banned": verified,
        "detail": detail,
    }
    if not record_result(config, record, rollback, report, args.format):
        return 1
    report.update({"status": result, "verified": verified, "detail": detail})
    emit(report, args.format)
    if code != 0 and verified:
        print(f"aviso: cliente retornou exit {code}, mas o ban foi confirmado", file=sys.stderr)
    return 0 if verified else 1


def cmd_unban(args: argparse.Namespace, config: Config, now: datetime) -> int:
    ip = validate_ip(args.ip)
    jail = validate_jail_name(args.jail)
    reason = validate_prose(args.reason, "--reason", MAX_REASON)
    approver = require_approval(args.execute, args.approved_by)

    records = read_audit(config.audit_path)
    origin = find_active_ban(records, str(ip), jail)
    if origin is None:
        raise PolicyError(
            "não há ban ativo criado por esta ferramenta para este IP/jail; "
            "unban manual de ban externo não é permitido"
        )

    correlation = validate_correlation(args.correlation_id) or new_correlation_id(now)
    ban_correlation = str(origin.get("correlation_id", ""))
    command = config.client_argv(["set", jail, "unbanip", str(ip)])
    rollback = config.client_argv(["set", jail, "banip", str(ip)])

    report = _base_report("unban", config, "execute" if args.execute else "dry-run")
    report.update({
        "status": "planned",
        "ip": str(ip),
        "jail": jail,
        "reason": redact(reason, MAX_REASON),
        "ban_correlation_id": ban_correlation,
        "approved_by": approver,
        "correlation_id": correlation,
        "command": command,
        "rollback": rollback,
        "client_available": client_available(config),
    })

    if not args.execute:
        emit(report, args.format)
        return 0

    prepare_audit(config.audit_path)
    status = get_status(config, jail)
    report["banned_before"] = [str(item) for item in status.banned]
    intent = {
        "ts": iso_z(now),
        "tool": TOOL,
        "version": TOOL_VERSION,
        "phase": "intent",
        "correlation_id": correlation,
        "action": "unban",
        "ip": str(ip),
        "jail": jail,
        "ban_correlation_id": ban_correlation,
        "reason": redact(reason, MAX_REASON),
        "evidence": f"auditoria:{ban_correlation}",
        "approved_by": approver,
        "command": command,
        "rollback": rollback,
    }

    if ip not in status.banned:
        detail = "IP não estava banido; estado já conforme"
        append_audit(config.audit_path, intent)
        record = {
            **intent,
            "ts": iso_z(datetime.now(timezone.utc)),
            "phase": "result",
            "result": "not_banned",
            "verified_banned": False,
            "detail": detail,
        }
        if not record_result(config, record, [], report, args.format):
            return 1
        report.update({"status": "not_banned", "verified": False, "detail": detail})
        report["rollback"] = []
        emit(report, args.format)
        return 0

    append_audit(config.audit_path, intent)
    try:
        _, code, stdout, stderr = run_client(config, ["set", jail, "unbanip", str(ip)])
    except ClientError as exc:
        detail = safe_detail(str(exc))
        record = {
            **intent,
            "ts": iso_z(datetime.now(timezone.utc)),
            "phase": "result",
            "result": "error",
            "detail": detail,
        }
        if not record_result(config, record, rollback, report, args.format):
            return 1
        report.update({"status": "error", "detail": detail})
        emit(report, args.format)
        return 1

    report["client_exit"] = code
    verified = False
    verify_detail = ""
    try:
        after = get_status(config, jail)
        verified = ip not in after.banned
        verify_detail = "IP ausente da lista de banidos" if verified else "IP continua na lista de banidos"
    except ClientError as exc:
        verify_detail = f"estado não verificável: {safe_detail(str(exc))}"

    client_detail = safe_detail((stderr or "").strip(), (stdout or "").strip())
    if code != 0 and verified:
        verify_detail += f"; cliente retornou exit {code}, mas o estado confirma a remoção"
    result = "ok" if verified else "error"
    detail = safe_detail(verify_detail, client_detail)
    record = {
        **intent,
        "ts": iso_z(datetime.now(timezone.utc)),
        "phase": "result",
        "result": result,
        "client_exit": code,
        "verified_banned": False if verified else True,
        "detail": detail,
    }
    if not record_result(config, record, rollback, report, args.format):
        return 1
    report.update({"status": result, "verified": verified, "detail": detail})
    emit(report, args.format)
    if code != 0 and verified:
        print(f"aviso: cliente retornou exit {code}, mas a remoção foi confirmada", file=sys.stderr)
    return 0 if verified else 1


def cmd_sweep(args: argparse.Namespace, config: Config, now: datetime) -> int:
    approver = require_approval(args.execute, args.approved_by)
    limit = args.limit if args.limit is not None else config.max_sweep
    if not 1 <= limit <= MAX_SWEEP_HARD:
        raise PolicyError(f"--limit precisa estar entre 1 e {MAX_SWEEP_HARD}")

    records = read_audit(config.audit_path)
    active = active_bans(records)
    due: list[dict[str, Any]] = []
    for (ip, jail), record in active.items():
        try:
            expires = parse_iso(str(record["expires_at"]), "expires_at da auditoria")
        except PolicyError as exc:
            raise AuditError(str(exc)) from exc
        if expires <= now:
            due.append({
                "ip": ip,
                "jail": jail,
                "expires_at": iso_z(expires),
                "correlation_id": str(record.get("correlation_id", "")),
            })
    due.sort(key=lambda item: (item["expires_at"], item["ip"], item["jail"]))
    due_total = len(due)
    selected = due[:limit]

    report = _base_report("sweep", config, "execute" if args.execute else "dry-run")
    report.update({
        "status": "planned",
        "approved_by": approver,
        "limit": limit,
        "due_total": due_total,
        "skipped": max(0, due_total - len(selected)),
        "due": selected,
        "results": [],
    })
    if not args.execute:
        emit(report, args.format)
        return 0

    if not selected:
        report["status"] = "ok"
        emit(report, args.format)
        return 0

    prepare_audit(config.audit_path)
    failures = 0
    for item in selected:
        try:
            ip = validate_ip(item["ip"])
            jail = validate_jail_name(item["jail"])
        except PolicyError as exc:
            raise AuditError(f"auditoria inválida no sweep: {exc}") from exc
        correlation = new_correlation_id(now)
        command = config.client_argv(["set", jail, "unbanip", str(ip)])
        rollback = config.client_argv(["set", jail, "banip", str(ip)])
        intent = {
            "ts": iso_z(now),
            "tool": TOOL,
            "version": TOOL_VERSION,
            "phase": "intent",
            "correlation_id": correlation,
            "action": "unban",
            "ip": str(ip),
            "jail": jail,
            "ban_correlation_id": item["correlation_id"],
            "reason": "TTL expirado (sweep)",
            "evidence": f"auditoria:{item['correlation_id']}",
            "approved_by": approver,
            "command": command,
            "rollback": rollback,
        }
        try:
            status = get_status(config, jail)
        except ClientError as exc:
            detail = safe_detail(str(exc))
            append_audit(config.audit_path, intent)
            record = {
                **intent,
                "ts": iso_z(datetime.now(timezone.utc)),
                "phase": "result",
                "result": "error",
                "detail": detail,
            }
            if not record_result(config, record, [], report, args.format):
                return 1
            report["results"].append({"ip": str(ip), "jail": jail, "status": "error", "detail": detail})
            failures += 1
            continue

        if ip not in status.banned:
            detail = "IP não estava banido; estado já conforme"
            append_audit(config.audit_path, intent)
            record = {
                **intent,
                "ts": iso_z(datetime.now(timezone.utc)),
                "phase": "result",
                "result": "not_banned",
                "verified_banned": False,
                "detail": detail,
            }
            if not record_result(config, record, [], report, args.format):
                return 1
            report["results"].append({"ip": str(ip), "jail": jail, "status": "not_banned", "detail": detail})
            continue

        append_audit(config.audit_path, intent)
        try:
            _, code, stdout, stderr = run_client(config, ["set", jail, "unbanip", str(ip)])
        except ClientError as exc:
            detail = safe_detail(str(exc))
            record = {
                **intent,
                "ts": iso_z(datetime.now(timezone.utc)),
                "phase": "result",
                "result": "error",
                "detail": detail,
            }
            if not record_result(config, record, rollback, report, args.format):
                return 1
            report["results"].append({"ip": str(ip), "jail": jail, "status": "error", "detail": detail})
            failures += 1
            continue

        verified = False
        try:
            after = get_status(config, jail)
            verified = ip not in after.banned
            verify_detail = "IP removido e verificado" if verified else "IP continua banido"
        except ClientError as exc:
            verify_detail = f"estado não verificável: {safe_detail(str(exc))}"
        client_detail = safe_detail((stderr or "").strip(), (stdout or "").strip())
        if code != 0 and verified:
            verify_detail += f"; cliente retornou exit {code}, mas a remoção foi confirmada"
        result = "ok" if verified else "error"
        detail = safe_detail(verify_detail, client_detail)
        record = {
            **intent,
            "ts": iso_z(datetime.now(timezone.utc)),
            "phase": "result",
            "result": result,
            "client_exit": code,
            "verified_banned": False if verified else True,
            "detail": detail,
        }
        if not record_result(config, record, rollback, report, args.format):
            return 1
        report["results"].append({
            "ip": str(ip), "jail": jail,
            "status": result if verified else "error",
            "detail": detail,
        })
        if not verified:
            failures += 1

    report["status"] = "error" if failures else "ok"
    emit(report, args.format)
    return 1 if failures else 0


# -------------------------------------------------------------------- CLI

def default_config_path() -> Path:
    env = os.environ.get("GAARA_F2B_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path(__file__).resolve().parent.parent / "assets" / "config.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="f2b_guard.py",
        description="Ban/unban/check de Fail2ban com allowlist, TTL e auditoria.",
        epilog=(
            "Dry-run é o padrão. Para alterar o sistema: --execute --approved-by <nome>. "
            "Exit: 0 sucesso, 1 erro, 2 recusa de política."
        ),
    )
    parser.add_argument("--config", type=Path, default=default_config_path(),
                        help="config JSON (padrão: assets/config.json ou $GAARA_F2B_CONFIG)")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--now", help="fixa o instante UTC (ISO 8601), para testes")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="estado do jail e política do IP")
    check.add_argument("--jail", required=True)
    check.add_argument("--ip")

    ban = subparsers.add_parser("ban", help="propõe/executa ban de um IP")
    ban.add_argument("--ip", required=True)
    ban.add_argument("--jail", required=True)
    ban.add_argument("--severity", required=True, choices=("baixo", "medio", "alto", "critico"))
    ban.add_argument("--confidence", required=True, choices=("alta", "media", "baixa"))
    ban.add_argument("--reason", required=True)
    ban.add_argument("--evidence", required=True)
    ban.add_argument("--ttl", help="TTL: 900, 30m, 4h, 1d; padrão por severidade")
    ban.add_argument("--execute", action="store_true")
    ban.add_argument("--approved-by")
    ban.add_argument("--correlation-id")

    unban = subparsers.add_parser("unban", help="remove um ban criado por esta ferramenta")
    unban.add_argument("--ip", required=True)
    unban.add_argument("--jail", required=True)
    unban.add_argument("--reason", required=True)
    unban.add_argument("--execute", action="store_true")
    unban.add_argument("--approved-by")
    unban.add_argument("--correlation-id")

    sweep = subparsers.add_parser("sweep", help="remove bans vencidos criados por esta ferramenta")
    sweep.add_argument("--limit", type=int)
    sweep.add_argument("--execute", action="store_true")
    sweep.add_argument("--approved-by")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config.expanduser())
    except ConfigError as exc:
        print(f"erro de configuração: {exc}", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    if args.now:
        try:
            now = parse_iso(args.now, "--now")
        except PolicyError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2

    try:
        if args.command == "check":
            return cmd_check(args, config, now)
        if args.command == "ban":
            return cmd_ban(args, config, now)
        if args.command == "unban":
            return cmd_unban(args, config, now)
        if args.command == "sweep":
            return cmd_sweep(args, config, now)
        parser.error(f"comando desconhecido: {args.command}")
    except PolicyError as exc:
        print(f"recusado: {exc}", file=sys.stderr)
        return 2
    except (AuditError, ClientError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
