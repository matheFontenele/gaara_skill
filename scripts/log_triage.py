#!/usr/bin/env python3
"""log_triage.py — triagem de auth.log, access log e PHP-FPM.

Lê logs, aplica os limiares de references/detection-playbook.md e emite
JSON no contrato de references/finding-schema.md.

Somente leitura. Nunca altera o sistema, nunca executa conteúdo de log.

Uso:
    ./log_triage.py /var/log/auth.log
    ./log_triage.py auth.log access.log --format md
    ./log_triage.py *.log --since 24h --output /tmp/triagem.json

Códigos de saída:
    0  executou, nenhum achado alto/crítico
    1  erro de execução
    2  uso incorreto
    3  executou e encontrou achado alto ou crítico
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import platform
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, unquote_plus

SCHEMA_VERSION = "1.0"
TOOL = "log_triage"
MAX_BYTES = 64 * 1024 * 1024
MAX_LINE = 64 * 1024
EXCERPT_MAX = 500
REDACTION_ENABLED = True

SEVERITY_RANK = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
SEVERITY_LABEL = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MÉDIO", "baixo": "BAIXO"}
CONFIDENCE_RANK = {"alta": 0, "media": 1, "baixa": 2}
CATEGORIES = {
    "detection/ssh-brute-force",
    "detection/credential-stuffing",
    "detection/scan-enumeration",
    "detection/path-traversal",
    "detection/rce-runtime",
    "detection/sql-injection",
    "detection/upload-webshell",
    "detection/cryptomining",
    "detection/exfiltration-c2",
    "detection/api-abuse",
    "detection/prompt-injection",
    "posture/ssh-config",
    "posture/firewall",
    "posture/permissions",
    "posture/tls",
    "posture/secrets",
    "posture/docker",
    "posture/updates",
    "cve/cve-2026-109618",
    "cve/exposure",
    "cve/patch-state",
    "legacy/eol-runtime",
    "legacy/unsupported-dependency",
    "legacy/migration-blocker",
    "code/rce",
    "code/injection",
    "code/upload",
    "ir/persistence",
    "ir/lateral-movement",
    "ir/evidence-integrity",
    "meta/prompt-injection-attempt",
    "meta/baseline-poisoning",
}
ACTIONS = {
    "none", "monitor", "investigate", "escalate",
    "ban", "unban", "isolate", "patch", "migrate", "rotate-credential",
}
NO_APPROVAL_ACTIONS = {"none", "monitor", "investigate", "escalate"}

# ---------------------------------------------------------------- redação

_SECRET_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "[CHAVE-PRIVADA]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret)"
                r"\s*[=:]\s*(\"[^\"]*\"|'[^']*'|\S+)"), r"\1=[REDACTADO]"),
    (re.compile(r"(?i)(--?(?:password|passwd|token|secret|api[_-]?key|access[_-]?key))\s+(\S+)"),
     r"\1 [REDACTADO]"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*:\s*[^\r\n]+"),
     r"\1: [REDACTADO]"),
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\r\n]+"), r"\1: [REDACTADO]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTADO]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "[JWT]"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://[REDACTADO]@"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    (re.compile(r"ssh2:\s*[A-Z0-9-]+\s+SHA256:[A-Za-z0-9+/=]+"), "ssh2: [CHAVE]"),
    (re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b"), "[BLOB]"),
]


def sanitize(text: str) -> str:
    """Escapa caracteres de controle para que log hostil não afete o terminal."""
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def redact(text: str) -> str:
    """Remove segredos e conteúdo ativo. Sempre aplicado antes da citação."""
    clean = text.replace("\r", " ").replace("\n", " ")
    for pattern, repl in _SECRET_RULES:
        clean = pattern.sub(repl, clean)
    return sanitize(clean)


def excerpt(text: str, limit: int = EXCERPT_MAX) -> str:
    safe = redact(text)
    if len(safe) <= limit:
        return safe
    return safe[: limit - 1] + "…"


# ---------------------------------------------------------------- parsing

TS_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
                       r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
TS_WEB = re.compile(r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
                    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
                    r"(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?")
TS_FPM = re.compile(r"^\[(?P<ts>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\]\s+"
                    r"(?P<level>[A-Z]+):\s+\[pool\s+(?P<pool>[^\]]+)\]\s+"
                    r"child\s+(?P<child>\d+)\s+(?P<rest>.*)$")

RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
RE_ACCEPTED = re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
RE_CLOSED = re.compile(r"Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+)")
RE_MAXATT = re.compile(r"maximum authentication attempts exceeded for (?P<user>\S+) from (?P<ip>\S+)")
RE_SESSION = re.compile(r"session opened for user (?P<user>\S+)")


def parse_syslog_ts(value: str, now: datetime) -> datetime | None:
    try:
        dt = datetime.strptime(f"{now.year} {value}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if dt > now + timedelta(days=2):
        dt = dt.replace(year=dt.year - 1)
    return dt


def parse_web_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


def parse_fpm_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%d-%b-%Y %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass
class Event:
    source: str
    line_no: int
    raw: str
    ts: datetime | None
    log_type: str
    data: dict[str, Any] = field(default_factory=dict)


def parse_line(source: str, line_no: int, line: str, now: datetime) -> Event | None:
    match = TS_FPM.match(line)
    if match:
        rest = match.group("rest")
        kind = "segv" if ("signal 11" in rest or "SIGSEGV" in rest) else "oom" if "Allowed memory size" in rest else "other"
        return Event(source, line_no, line, parse_fpm_ts(match.group("ts")), "fpm",
                     {"pool": match.group("pool"), "child": match.group("child"), "kind": kind, "rest": rest})

    match = TS_WEB.match(line)
    if match:
        return Event(source, line_no, line, parse_web_ts(match.group("ts")), "web", {
            "ip": match.group("ip"),
            "method": match.group("method"),
            "path": match.group("path"),
            "status": int(match.group("status")),
            "size": match.group("size"),
            "referer": match.group("ref") or "",
            "ua": match.group("ua") or "",
        })

    match = TS_SYSLOG.match(line)
    if match and ("sshd" in match.group("proc") or "pam_unix" in match.group("proc")):
        msg = match.group("msg")
        data: dict[str, Any] = {"msg": msg, "user": None, "ip": None, "outcome": None}
        if (m := RE_FAILED.search(msg)):
            data.update(user=m.group("user"), ip=m.group("ip"), outcome="failed")
        elif (m := RE_ACCEPTED.search(msg)):
            data.update(user=m.group("user"), ip=m.group("ip"),
                        outcome="accepted", method=m.group("method"))
        elif (m := RE_INVALID.search(msg)):
            data.update(user=m.group("user"), ip=m.group("ip"), outcome="invalid")
        elif (m := RE_CLOSED.search(msg)):
            data.update(user=m.group("user"), ip=m.group("ip"), outcome="closed")
        elif (m := RE_MAXATT.search(msg)):
            data.update(user=m.group("user"), ip=m.group("ip"), outcome="max-attempts")
        elif (m := RE_SESSION.search(msg)):
            data.update(user=m.group("user"), outcome="session-opened")
        else:
            return None
        return Event(source, line_no, line, parse_syslog_ts(match.group("ts"), now), "auth", data)

    if re.match(r"^(?:User-Agent|URI|Referer|Body|Header|Filename)\s*:", line, re.I):
        return Event(source, line_no, line, None, "injection", {"text": line})

    return None


# ---------------------------------------------------------------- detecção

SENSITIVE_PATHS = (
    "/.env", "/.git", "/wp-admin", "/wp-login", "/phpmyadmin", "/server-status",
    "/actuator", "/vendor/", "/.aws", "/docker-compose", "/config.php.bak",
    "/backup", "/db.sql", "/admin.php", "/.ssh", "/.svn", "/phpinfo",
)
TRAVERSAL = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|\.\.%5c|%252e%252e|"
    r"php://(?:filter|input)|data://|expect://|phar://|zip://|"
    r"/etc/passwd|/etc/shadow|win\.ini|web\.xml)", re.I)
SQLI = re.compile(
    r"(?:union\s+(?:all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|"
    r"information_schema|into\s+outfile|xp_cmdshell|'\s*--)", re.I)
RCE = re.compile(
    r"(?:[;|]\s*(?:id|whoami|uname|curl|wget|nc|bash|sh|python|perl)\b|"
    r"%3b\s*(?:id|whoami)|%7c\s*(?:id|whoami)|\$\(|`[^`]+`|"
    r"\b(?:wget|curl)\s+https?://|\bnc\s+-e\b|\bbash\s+-i\b|"
    r"\bunserialize\s*\(|\bO:\d+:\"|\$\{jndi:)", re.I)
INJECTION_PATTERNS = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:the\s+)?previous\s+instructions|"
    r"disregard\s+(?:your|all|any)\s+(?:rules|instructions)|"
    r"forget\s+your\s+(?:rules|instructions)|system\s+override|"
    r"you\s+are\s+now\b|<\|\s*im_start\s*\|>|"
    r"\bunban\b|\bdisable\s+the\s+firewall\b|"
    r"\bexecute\s*:|\brun\s*:|rm\s+-rf\s+/|"
    r"print\s+the\s+contents|summarize\s+and\s+then\s+run|"
    r"\"role\"\s*:\s*\"system\")", re.I)
BASE64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


def is_sensitive(path: str) -> bool:
    low = path.lower()
    return any(marker in low for marker in SENSITIVE_PATHS)


def decoded(path: str) -> str:
    """Decodifica uma ou duas camadas, para casar payload URL-encoded."""
    return unquote(unquote(path))


def max_in_window(times: list[datetime], window: timedelta) -> int:
    if not times:
        return 0
    ordered = sorted(times)
    best = 0
    start = 0
    for end, current in enumerate(ordered):
        while current - ordered[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def distinct_in_window(events: Iterable[Event], window: timedelta, key: str) -> int:
    items = [(e.ts, e.data.get(key)) for e in events if e.ts]
    if not items:
        return 0
    items.sort()
    best = 0
    start = 0
    seen: dict[Any, int] = {}
    for end, (current, value) in enumerate(items):
        seen[value] = seen.get(value, 0) + 1
        while current - items[start][0] > window:
            old = items[start][1]
            seen[old] -= 1
            if seen[old] == 0:
                del seen[old]
            start += 1
        best = max(best, len(seen))
    return best


def evidence(source: str, line_no: int, raw: str, locator: str | None = None) -> dict[str, Any]:
    return {
        "source": Path(source).name,
        "locator": locator or f"linha {line_no}",
        "excerpt": excerpt(raw),
        "redacted": REDACTION_ENABLED,
        "source_type": "log",
    }


def finding(*, title: str, category: str, severity: str, confidence: str,
            evidence_items: list[dict[str, Any]], impact: str, action: str,
            command: str | None = None, rollback: str | None = None,
            ttl: int | None = None, target: str | None = None,
            observations: dict[str, Any] | None = None,
            false_positive_notes: str | None = None,
            not_observed: list[str] | None = None,
            mitre: list[str] | None = None) -> dict[str, Any]:
    recommendation: dict[str, Any] = {"action": action, "requires_approval": action not in NO_APPROVAL_ACTIONS}
    if command:
        recommendation["command"] = command
    if rollback:
        recommendation["rollback"] = rollback
    if ttl is not None:
        recommendation["ttl_seconds"] = ttl
    if target:
        recommendation["target"] = target
    item: dict[str, Any] = {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence_items[:3],
        "impact": impact,
        "recommendation": recommendation,
        "not_observed": not_observed or [],
    }
    if mitre:
        item["mitre"] = mitre
    if observations:
        item["observations"] = observations
    if false_positive_notes:
        item["false_positive_notes"] = false_positive_notes
    return item


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


def detect_auth(events: list[Event]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_ip: dict[str, list[Event]] = {}
    accepted: dict[str, list[Event]] = {}
    for event in events:
        ip = event.data.get("ip")
        if not ip:
            continue
        if event.data.get("outcome") == "failed":
            by_ip.setdefault(ip, []).append(event)
        elif event.data.get("outcome") == "accepted":
            accepted.setdefault(ip, []).append(event)

    for ip in sorted(by_ip):
        failures = by_ip[ip]
        times = [e.ts for e in failures if e.ts]
        users = {e.data.get("user") for e in failures}
        first, last = failures[0], failures[-1]
        success = [e for e in accepted.get(ip, []) if e.ts and times and e.ts >= min(times)]
        burst_5 = max_in_window(times, timedelta(minutes=5))
        burst_60 = max_in_window(times, timedelta(hours=1))
        spray = distinct_in_window(failures, timedelta(minutes=10), "user")
        evidence_items = [evidence(first.source, first.line_no, first.raw)]

        if success:
            hit = success[0]
            evidence_items.append(evidence(hit.source, hit.line_no, hit.raw))
            findings.append(finding(
                title="Login bem-sucedido após sequência de falhas",
                category="detection/ssh-brute-force",
                severity="critico",
                confidence="alta",
                evidence_items=evidence_items,
                impact="Acesso autenticado com credencial válida após tentativas falhas. "
                       "Senha comprometida, reutilizada ou conta sob controle do atacante.",
                action="escalate",
                target=ip,
                observations={"count": len(failures), "distinct_users": len(users),
                              "window_start": iso(times[0]) if times else None,
                              "window_end": iso(times[-1]) if times else None,
                              "actors": [ip]},
                not_observed=["nenhum indício de troca de senha ou criação de usuário nos logs fornecidos"],
                mitre=["T1110.001", "T1078"],
            ))
            continue

        if burst_60 >= 50 or spray >= 5:
            severity, action = "alto", "ban"
            title = "Brute force SSH" + (" com spraying" if spray >= 5 else "")
            impact = ("Tentativa de acesso não autorizado por SSH, com múltiplos usuários. "
                      "Nenhum sucesso observado.")
            notes = "NAT corporativo pode concentrar vários usuários no mesmo IP."
        elif burst_5 >= 10 or burst_60 >= 10:
            severity, action = "medio", "monitor"
            title = "Tentativa de força bruta SSH abaixo do limiar alto"
            impact = "Tentativa de acesso não autorizado por SSH, em volume moderado."
            notes = "Pode ser senha errada repetida ou monitoração mal configurada."
        elif len(failures) >= 3:
            severity, action = "baixo", "monitor"
            title = "Falhas de autenticação abaixo do limiar"
            impact = "Poucas tentativas falhas; compatível com erro de digitação ou ruído de internet."
            notes = "Não há evidência de ataque coordenado."
        else:
            continue

        findings.append(finding(
            title=title,
            category="detection/ssh-brute-force",
            severity=severity,
            confidence="alta" if severity in ("alto", "critico") else "media",
            evidence_items=evidence_items,
            impact=impact,
            action=action,
            command=f"fail2ban-client set sshd banip {ip}" if action == "ban" else None,
            rollback=f"fail2ban-client set sshd unbanip {ip}" if action == "ban" else None,
            ttl=86400 if action == "ban" else None,
            target=ip,
            observations={"count": len(failures), "distinct_users": len(users),
                          "max_5min": burst_5, "max_1h": burst_60, "spray_users_10min": spray,
                          "window_start": iso(times[0]) if times else None,
                          "window_end": iso(times[-1]) if times else None,
                          "actors": [ip]},
            false_positive_notes=notes,
            not_observed=[f"nenhum Accepted para {ip} na janela"],
            mitre=["T1110.001", "T1110.003"] if spray >= 5 else ["T1110.001"],
        ))

    return findings


def detect_web(events: list[Event]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_ip: dict[str, list[Event]] = {}
    for event in events:
        by_ip.setdefault(event.data["ip"], []).append(event)

    for ip in sorted(by_ip):
        items = sorted(by_ip[ip], key=lambda e: (e.ts or datetime.min.replace(tzinfo=timezone.utc), e.line_no))

        # scan de paths sensíveis
        hits = [e for e in items if is_sensitive(decoded(e.data["path"]))]
        ok_hits = [e for e in hits if e.data["status"] == 200]
        distinct_paths = {decoded(e.data["path"]).split("?")[0] for e in hits}
        total = len(items)
        not_found = sum(1 for e in items if e.data["status"] == 404)
        peak = max_in_window([e.ts for e in items if e.ts], timedelta(minutes=1))

        if ok_hits:
            critical = any(".env" in e.data["path"] or ".git" in e.data["path"] for e in ok_hits)
            findings.append(finding(
                title="Path sensível acessível" if not critical else "Arquivo de configuração exposto",
                category="detection/scan-enumeration",
                severity="critico" if critical else "alto",
                confidence="alta",
                evidence_items=[evidence(e.source, e.line_no, e.raw) for e in ok_hits[:3]],
                impact="Conteúdo sensível retornado com sucesso. Credenciais ou código-fonte podem ter sido lidos.",
                action="escalate",
                target=ip,
                observations={"count": len(ok_hits), "actors": [ip],
                              "paths": sorted({e.data["path"] for e in ok_hits})[:10]},
                not_observed=[],
                mitre=["T1595.002"],
            ))
        elif len(distinct_paths) >= 10 or (peak >= 50 and total and not_found / total > 0.8):
            sample = hits[0] if hits else items[0]
            findings.append(finding(
                title="Scan de paths sensíveis",
                category="detection/scan-enumeration",
                severity="medio",
                confidence="alta",
                evidence_items=[evidence(sample.source, sample.line_no, sample.raw)],
                impact="Reconhecimento automatizado. Nenhum path sensível retornou conteúdo.",
                action="monitor",
                target=ip,
                observations={"count": total, "distinct_sensitive_paths": len(distinct_paths),
                              "not_found": not_found, "max_requests_1min": peak, "actors": [ip]},
                false_positive_notes="Crawler legítimo ou scanner autorizado produzem o mesmo padrão. "
                                     "Confirme com o time antes de banir.",
                not_observed=["nenhum path sensível retornou 200"],
                mitre=["T1595", "T1595.002"],
            ))

        # path traversal / LFI
        traversal = [e for e in items if TRAVERSAL.search(decoded(e.data["path"]))]
        if traversal:
            ok = [e for e in traversal if e.data["status"] == 200]
            severe = [e for e in ok if re.search(r"/etc/passwd|/etc/shadow|php://filter", decoded(e.data["path"]), re.I)]
            if severe:
                severity, action = "critico", "escalate"
            elif ok:
                severity, action = "alto", "investigate"
            else:
                severity, action = "medio", "monitor"
            findings.append(finding(
                title="Tentativa de path traversal / LFI",
                category="detection/path-traversal",
                severity=severity,
                confidence="alta" if severity == "critico" else "media",
                evidence_items=[evidence(e.source, e.line_no, e.raw) for e in (severe or ok or traversal)[:3]],
                impact="Leitura arbitrária de arquivo" + (" confirmada por resposta 200." if ok else " tentada, sem sucesso observado."),
                action=action,
                target=ip,
                observations={"count": len(traversal), "status_200": len(ok), "actors": [ip]},
                not_observed=[] if ok else ["nenhuma resposta 200 para payload de traversal"],
                mitre=["T1190", "T1005"],
            ))

        # SQL injection
        sqli = [e for e in items if SQLI.search(decoded(e.data["path"]))]
        if sqli:
            ok = [e for e in sqli if e.data["status"] == 200]
            findings.append(finding(
                title="Tentativas de SQL injection",
                category="detection/sql-injection",
                severity="alto",
                confidence="alta" if not ok else "media",
                evidence_items=[evidence(e.source, e.line_no, e.raw) for e in sqli[:3]],
                impact="Injeção de SQL tentada. " + (
                    "Resposta 200 não confirma extração; exige verificação no corpo e no banco."
                    if ok else "Erro 5xx sugere falha na consulta, sem confirmação de extração."),
                action="investigate",
                target=ip,
                observations={"count": len(sqli), "status_200": len(ok), "actors": [ip],
                              "payloads": sorted({e.data["path"] for e in sqli})[:5]},
                false_positive_notes="Busca legítima com apóstrofo pode gerar erro de sintaxe em app mal feita.",
                not_observed=["sem acesso ao corpo da resposta, não é possível confirmar reflexo de dados"],
                mitre=["T1190"],
            ))

        # upload seguido de acesso a arquivo executável
        posts = [e for e in items if e.data["method"] == "POST" and 200 <= e.data["status"] < 300]
        for post in posts:
            window_end = (post.ts or datetime.min.replace(tzinfo=timezone.utc)) + timedelta(minutes=2)
            after = [
                e for e in items
                if e.data["method"] == "GET" and 200 <= e.data["status"] < 300
                and e.ts and post.ts and post.ts <= e.ts <= window_end
                and re.search(r"\.(php|phtml|phar|jsp|aspx)(\.|$)", e.data["path"], re.I)
            ]
            if after:
                findings.append(finding(
                    title="Upload de arquivo executável aceito",
                    category="detection/upload-webshell",
                    severity="alto",
                    confidence="alta",
                    evidence_items=[evidence(post.source, post.line_no, post.raw),
                                    evidence(after[0].source, after[0].line_no, after[0].raw)],
                    impact="Arquivo com extensão executável foi aceito e acessado. Possível webshell.",
                    action="investigate",
                    target=ip,
                    observations={"count": 1, "actors": [ip], "path": after[0].data["path"]},
                    false_positive_notes="Upload legítimo de aplicação PHP pode ter o mesmo padrão; "
                                         "confirme o conteúdo em disco antes de concluir.",
                    not_observed=["conteúdo do arquivo não é visível no access log"],
                    mitre=["T1505.003", "T1105"],
                ))
                break

        # payload de RCE
        rce = [e for e in items if RCE.search(decoded(e.data["path"]) + " " + e.data["ua"] + " " + e.data["referer"])]
        if rce:
            ok = [e for e in rce if e.data["status"] == 200]
            findings.append(finding(
                title="Payload de execução de comando",
                category="detection/rce-runtime",
                severity="critico" if ok else "alto",
                confidence="alta",
                evidence_items=[evidence(e.source, e.line_no, e.raw) for e in rce[:3]],
                impact="Tentativa de execução remota de comando" + (" com resposta 200." if ok else ", sem sucesso observado."),
                action="escalate" if ok else "investigate",
                target=ip,
                observations={"count": len(rce), "status_200": len(ok), "actors": [ip]},
                not_observed=[] if ok else ["nenhuma resposta 200 para payload de execução"],
                mitre=["T1190", "T1059.004"],
            ))

    return findings


def detect_fpm(events: list[Event]) -> list[dict[str, Any]]:
    segv = [e for e in events if e.data.get("kind") == "segv"]
    oom = [e for e in events if e.data.get("kind") == "oom"]
    if not segv:
        return []
    if len(segv) >= 3:
        severity = "alto"
    elif segv:
        severity = "medio" if not oom else "alto"
    else:
        return []
    times = [e.ts for e in segv if e.ts]
    return [finding(
        title="Crash repetido de worker PHP",
        category="detection/rce-runtime",
        severity=severity,
        confidence="media",
        evidence_items=[evidence(segv[0].source, segv[0].line_no, segv[0].raw)],
        impact="Compatível com tentativa de exploração de corrupção de memória no interpretador. "
               "Também pode ser extensão instável ou falha de alocação.",
        action="investigate",
        observations={"count": len(segv), "oom": len(oom),
                      "window_start": iso(min(times)) if times else None,
                      "window_end": iso(max(times)) if times else None},
        false_positive_notes="Extensão PHP instável ou deploy que reinicia workers produzem o mesmo sinal.",
        not_observed=["processos filhos e conexões de saída não são visíveis neste log; verificar no host"],
        mitre=["T1190"],
    )]


def _decode_base64(text: str) -> str | None:
    for token in BASE64_TOKEN.findall(text):
        if len(token) < 20:
            continue
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            decoded = raw.decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if sum(ch.isprintable() or ch.isspace() for ch in decoded) / max(len(decoded), 1) > 0.85:
            return decoded
    return None


def detect_injection(events: list[Event], web_events: list[Event]) -> list[dict[str, Any]]:
    hits: list[tuple[str, Event, str]] = []
    traversal_hits: list[Event] = []

    for event in events:
        if event.log_type == "injection":
            text = event.data["text"]
            probe = unquote_plus(unquote(text))
            if INJECTION_PATTERNS.search(probe) or INJECTION_PATTERNS.search(_decode_base64(probe) or ""):
                hits.append(("texto", event, text))
            elif TRAVERSAL.search(probe):
                traversal_hits.append(event)

    for event in web_events:
        for field_name in ("ua", "referer", "path"):
            value = event.data.get(field_name, "")
            probe = unquote_plus(unquote(value))
            if INJECTION_PATTERNS.search(probe) or INJECTION_PATTERNS.search(_decode_base64(probe) or ""):
                hits.append((field_name, event, value))
                break

    findings: list[dict[str, Any]] = []
    if hits:
        by_ip: dict[str, list[tuple[str, Event, str]]] = {}
        for field_name, event, value in hits:
            ip = event.data.get("ip", "desconhecido")
            by_ip.setdefault(ip, []).append((field_name, event, value))

        for ip in sorted(by_ip):
            items = by_ip[ip]
            findings.append(finding(
                title="Prompt injection dirigida ao agente",
                category="meta/prompt-injection-attempt",
                severity="medio",
                confidence="alta",
                evidence_items=[evidence(event.source, event.line_no, event.raw) for _, event, _ in items[:3]],
                impact="Tentativa de manipular a automação que lê logs. Não é ataque ao servidor.",
                action="none",
                target=ip if ip != "desconhecido" else None,
                observations={"count": len(items), "fields": sorted({f for f, _, _ in items})},
                not_observed=["nenhuma ação foi executada a partir do conteúdo"],
                mitre=["AML.T0051"],
            ))

    if traversal_hits:
        findings.append(finding(
            title="Payload de traversal em campo controlado pelo atacante",
            category="detection/path-traversal",
            severity="baixo",
            confidence="alta",
            evidence_items=[evidence(e.source, e.line_no, e.raw) for e in traversal_hits[:3]],
            impact="Tentativa de leitura de arquivo registrada em texto lido pela automação. "
                   "Sem resposta HTTP associada, não há como confirmar sucesso.",
            action="none",
            observations={"count": len(traversal_hits)},
            not_observed=["nenhuma resposta HTTP para confirmar leitura"],
            mitre=["T1005"],
        ))

    return findings


# ---------------------------------------------------------------- orquestração

def build_result(paths: list[Path], events: list[Event], limits: dict[str, Any],
                 now: datetime, host: str, scan_id: str) -> dict[str, Any]:
    auth = [e for e in events if e.log_type == "auth"]
    web = [e for e in events if e.log_type == "web"]
    fpm = [e for e in events if e.log_type == "fpm"]

    findings = []
    findings += detect_auth(auth)
    findings += detect_web(web)
    findings += detect_fpm(fpm)
    findings += detect_injection([e for e in events if e.log_type == "injection"], web)

    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], CONFIDENCE_RANK[f["confidence"]], f["title"]))
    for index, item in enumerate(findings, 1):
        item["id"] = f"F-{index:03d}"

    counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
    for item in findings:
        counts[item["severity"]] += 1
    verdict = "incidente" if counts["critico"] else "atencao" if counts["alto"] or counts["medio"] else "estavel"

    actors: dict[str, list[str]] = {}
    for item in findings:
        for actor in item.get("observations", {}).get("actors", []):
            actors.setdefault(actor, []).append(item["id"])
    correlations = [
        {"key": actor, "findings": ids, "note": f"{len(ids)} famílias distintas para o mesmo ator"}
        for actor, ids in sorted(actors.items()) if len(ids) >= 2
    ]

    not_observed: list[str] = []
    if auth:
        failed_ips = {e.data.get("ip") for e in auth if e.data.get("outcome") == "failed"}
        accepted_ips = {e.data.get("ip") for e in auth if e.data.get("outcome") == "accepted"}
        for ip in sorted(failed_ips - accepted_ips):
            not_observed.append(f"nenhum login bem-sucedido para {ip}")
    if web and not any(is_sensitive(decoded(e.data["path"])) and e.data["status"] == 200 for e in web):
        not_observed.append("nenhum path sensível retornou 200")
    if fpm:
        not_observed.append("processos filhos e conexões de saída não constam nos logs analisados")
    if not web:
        not_observed.append("sem access log: requisições web não foram avaliadas")

    times = [e.ts for e in events if e.ts]
    return {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "id": scan_id,
            "tool": TOOL,
            "host": host,
            "started_at": iso(now),
            "finished_at": iso(now),
            "window": {"from": iso(min(times)) if times else iso(now),
                       "to": iso(max(times)) if times else iso(now)},
            "sources": [str(p) for p in paths],
            "limits": limits,
        },
        "findings": findings,
        "summary": {
            "verdict": verdict,
            "counts": counts,
            "correlations": correlations,
            "not_observed": not_observed,
        },
    }


def validate(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version inválida")
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        return ["findings não é lista"]
    for item in findings:
        if item.get("category") not in CATEGORIES:
            errors.append(f"{item.get('id')}: categoria fora da lista ({item.get('category')})")
        if item.get("severity") not in SEVERITY_RANK:
            errors.append(f"{item.get('id')}: severidade inválida")
        if item.get("confidence") not in CONFIDENCE_RANK:
            errors.append(f"{item.get('id')}: confiança inválida")
        if not item.get("evidence"):
            errors.append(f"{item.get('id')}: sem evidência")
        for ev in item.get("evidence", []):
            if not ev.get("locator"):
                errors.append(f"{item.get('id')}: evidência sem locator")
            if len(ev.get("excerpt", "")) > EXCERPT_MAX:
                errors.append(f"{item.get('id')}: excerpt acima de {EXCERPT_MAX}")
        rec = item.get("recommendation", {})
        if rec.get("action") not in ACTIONS:
            errors.append(f"{item.get('id')}: ação inválida")
        if rec.get("action") not in NO_APPROVAL_ACTIONS and rec.get("requires_approval") is not True:
            errors.append(f"{item.get('id')}: ação sem requires_approval")
        if rec.get("action") not in NO_APPROVAL_ACTIONS and not rec.get("rollback"):
            errors.append(f"{item.get('id')}: ação sem rollback")
    counts = result.get("summary", {}).get("counts", {})
    if sum(counts.values()) != len(findings):
        errors.append("counts não bate com findings")
    ids = {item.get("id") for item in findings}
    for corr in result.get("summary", {}).get("correlations", []):
        for ref in corr.get("findings", []):
            if ref not in ids:
                errors.append(f"correlação referencia achado inexistente: {ref}")
    return errors


def render_markdown(result: dict[str, Any]) -> str:
    scan = result["scan"]
    summary = result["summary"]
    lines = [
        f"# Triagem — {scan['host']}",
        "",
        f"**Veredito:** {summary['verdict']}",
        f"**Janela:** {scan['window']['from']} → {scan['window']['to']}",
        f"**Fontes:** {', '.join(scan['sources'])}",
        f"**Achados:** " + " · ".join(f"{SEVERITY_LABEL[k].lower()} {v}" for k, v in summary["counts"].items()),
        "",
        "## Achados",
        "",
    ]
    if not result["findings"]:
        lines += ["Nenhum achado acima do limiar.", ""]
    for item in result["findings"]:
        lines += [
            f"### [{SEVERITY_LABEL[item['severity']]}] {item['title']} ({item['id']})",
            "",
            f"- **Categoria:** `{item['category']}`",
            f"- **Confiança:** {item['confidence']}",
            f"- **Evidência:**",
        ]
        for ev in item["evidence"]:
            lines.append(f"  - `{ev['source']}` {ev['locator']}: `{ev['excerpt']}`")
        lines += [
            f"- **Impacto:** {item['impact']}",
            f"- **Recomendação:** {item['recommendation']['action']}"
            + (f" — `{item['recommendation']['command']}`" if item["recommendation"].get("command") else ""),
        ]
        if item.get("false_positive_notes"):
            lines.append(f"- **Falso positivo:** {item['false_positive_notes']}")
        for note in item.get("not_observed", []):
            lines.append(f"- **Não observado:** {note}")
        lines.append("")
    if summary["correlations"]:
        lines += ["## Correlação", ""]
        for corr in summary["correlations"]:
            lines.append(f"- `{corr['key']}`: {', '.join(corr['findings'])} — {corr['note']}")
        lines.append("")
    if summary["not_observed"]:
        lines += ["## Não observado", ""] + [f"- {n}" for n in summary["not_observed"]] + [""]
    lines += ["> Horários interpretados como UTC. Logs syslog não trazem fuso.", ""]
    return "\n".join(lines)


def parse_since(value: str, now: datetime) -> datetime:
    match = re.fullmatch(r"(\d+)([smhd])", value.strip())
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        delta = {"s": timedelta(seconds=amount), "m": timedelta(minutes=amount),
                 "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]
        return now - delta
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"--since inválido: {value}") from exc
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Triagem somente leitura de auth.log, access log e PHP-FPM.",
        epilog="Exemplo: ./log_triage.py /var/log/auth.log /var/log/nginx/access.log --since 24h",
    )
    parser.add_argument("files", nargs="+", type=Path, help="arquivos de log")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--output", type=Path, help="arquivo de saída (padrão: stdout)")
    parser.add_argument("--since", help="janela: 24h, 7d, 90m ou ISO 8601")
    parser.add_argument("--now", help="fixa o instante de referência (ISO 8601), útil para reprodutibilidade")
    parser.add_argument("--host", default="", help="identificador do host")
    parser.add_argument("--scan-id", help="ID do scan (padrão: gaara-YYYYMMDD-0001)")
    parser.add_argument("--redact", choices=("on", "off"), default="on")
    parser.add_argument("--redact-off-reason", help="justificativa obrigatória para --redact off")
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES, help="limite total de leitura")
    args = parser.parse_args(argv)

    if args.redact == "off" and not args.redact_off_reason:
        print("erro: --redact off exige --redact-off-reason", file=sys.stderr)
        return 2
    if args.redact == "off":
        print("aviso: redação desativada; não compartilhe a saída", file=sys.stderr)

    now = datetime.now(timezone.utc)
    if args.now:
        try:
            parsed = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
            now = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"erro: --now inválido: {args.now}", file=sys.stderr)
            return 2
    since = None
    if args.since:
        try:
            since = parse_since(args.since, now)
        except argparse.ArgumentTypeError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2

    events: list[Event] = []
    limits = {"bytes_read": 0, "lines_read": 0, "truncated": False}
    for path in args.files:
        if not path.is_file():
            print(f"erro: arquivo não encontrado: {path}", file=sys.stderr)
            return 1
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    if limits["bytes_read"] + len(line) > args.max_bytes:
                        limits["truncated"] = True
                        break
                    limits["bytes_read"] += len(line.encode("utf-8", "replace"))
                    limits["lines_read"] += 1
                    if len(line) > MAX_LINE:
                        limits["truncated"] = True
                        continue
                    event = parse_line(str(path), number, line.rstrip("\n"), now)
                    if event is None:
                        continue
                    if since and event.ts and event.ts < since:
                        continue
                    events.append(event)
        except OSError as exc:
            print(f"erro ao ler {path}: {exc}", file=sys.stderr)
            return 1

    if args.redact == "off":
        global redact, REDACTION_ENABLED
        REDACTION_ENABLED = False
        redact = lambda text: sanitize(text.replace("\r", " ").replace("\n", " "))  # noqa: E731

    host = args.host or platform.node() or "desconhecido"
    scan_id = args.scan_id or f"gaara-{now.strftime('%Y%m%d')}-0001"
    result = build_result(args.files, events, limits, now, host, scan_id)

    errors = validate(result)
    if errors:
        for error in errors:
            print(f"schema: {error}", file=sys.stderr)
        return 1

    output = render_markdown(result) if args.format == "md" else json.dumps(result, ensure_ascii=False, indent=2, sort_keys=False)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    high = result["summary"]["counts"]["critico"] + result["summary"]["counts"]["alto"]
    return 3 if high else 0


if __name__ == "__main__":
    sys.exit(main())
