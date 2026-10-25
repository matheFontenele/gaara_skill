#!/usr/bin/env python3
"""php_audit.py — auditoria estática somente leitura de código PHP.

Procura padrões perigosos (execução, inclusão, SQL, upload, segredos) e
incompatibilidades de PHP 5/7 para PHP 8. Emite JSON no contrato de
references/finding-schema.md ou Markdown para leitura humana.

Somente leitura. Não executa o código analisado, não instala nada e não
altera permissões. A análise é lexical: não segue fluxo entre arquivos.

Uso:
    ./php_audit.py /var/www/app
    ./php_audit.py app/ --format md --output /tmp/php-audit.md
    ./php_audit.py app/ --include-vendor

Códigos de saída:
    0  executou, nenhum achado alto/crítico
    1  erro de execução
    2  uso incorreto
    3  executou e encontrou achado alto ou crítico
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Reutiliza redação e validação do log_triage: um único contrato de saída.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import log_triage as triage  # noqa: E402

SCHEMA_VERSION = triage.SCHEMA_VERSION
TOOL = "php_audit"
EXCERPT_MAX = triage.EXCERPT_MAX
SEVERITY_RANK = triage.SEVERITY_RANK
SEVERITY_LABEL = triage.SEVERITY_LABEL
CONFIDENCE_RANK = triage.CONFIDENCE_RANK
REDACTION_ENABLED = True

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 5000
PHP_SUFFIXES = {".php", ".phtml", ".phps", ".inc", ".php3", ".php4", ".php5", ".php7", ".php8"}
KEY_SUFFIXES = {".pem", ".key"}
SPECIAL_NAMES = {"composer.json", "Dockerfile", ".php-version", ".tool-versions"}
SKIP_DIRS_ALWAYS = {".git", ".hg", ".svn", "__pycache__"}
SKIP_DIRS_DEFAULT = {"vendor", "node_modules", "bower_components"}

SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[_-])(pass|password|passwd|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|db[_-]?pass|app[_-]?key)(?:$|[_-])"
)
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:|changeme|change[-_ ]?me|your[-_ ].*|example.*|sample.*|todo|fixme|"
    r"x{3,}|\*{3,}|<.*>|null|none|test|dummy|placeholder|secret|password|pass|"
    r"\.{3,}|-+)$"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
REQUEST_RE = r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER)"

# (regex com grupo "fn", versão em que foi removida)
REMOVED_FUNCTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?P<fn>mysql_[a-z_]+)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>ereg(?:i)?(?:_replace)?)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>spliti?|sql_regcase)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>call_user_method(?:_array)?)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>set_socket_blocking)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>set_magic_quotes_runtime)\s*\(", re.I), "7.0"),
    (re.compile(r"\b(?P<fn>mcrypt_[a-z_]+)\s*\(", re.I), "7.2"),
    (re.compile(r"\b(?P<fn>each)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>create_function)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>get_magic_quotes_gpc|get_magic_quotes_runtime)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>money_format)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>hebrevc|convert_cyr_string|ezmlm_hash)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>fgetss)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>image2wbmp|png2wbmp|jpeg2wbmp)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>ldap_sort|read_exif_data)\s*\(", re.I), "8.0"),
    (re.compile(r"\b(?P<fn>gmp_random)\s*\(", re.I), "8.0"),
    (re.compile(r"\bfunction\s+(?P<fn>__autoload)\s*\(", re.I), "8.0"),
    (re.compile(r"(?P<fn>\$HTTP_RAW_POST_DATA)\b"), "7.0"),
]

CURLY_OFFSET_RE = re.compile(r"(?P<fn>\$[A-Za-z_]\w*)\s*\{[^}\n]*\}")
RCE_RE = re.compile(
    rf"\b(?P<fn>eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
    rf"\s*\([^;]{{0,300}}{REQUEST_RE}", re.I | re.S
)
CREATE_FUNCTION_RE = re.compile(
    rf"\b(?P<fn>create_function)\s*\([^;]{{0,300}}{REQUEST_RE}", re.I | re.S
)
INCLUDE_RE = re.compile(
    rf"\b(?P<fn>include|include_once|require|require_once)\s*\(?\s*[^;]{{0,150}}{REQUEST_RE}",
    re.I | re.S,
)
UNSERIALIZE_RE = re.compile(
    rf"\b(?P<fn>unserialize)\s*\(\s*[^;]{{0,150}}{REQUEST_RE}", re.I | re.S
)
EXTRACT_RE = re.compile(rf"\b(?P<fn>extract)\s*\(\s*{REQUEST_RE}", re.I | re.S)
SQL_RE = re.compile(
    rf"\b(?P<fn>mysql_query|mysqli_query|pg_query|sqlite_query|->query)"
    rf"\s*\([^;]{{0,500}}{REQUEST_RE}", re.I | re.S
)
UPLOAD_RE = re.compile(
    r"\b(?P<fn>move_uploaded_file|copy)\s*\([^;]{0,500}\$_FILES", re.I | re.S
)
WEAK_HASH_RE = re.compile(r"\b(?P<fn>md5|sha1)\s*\(\s*\$(?P<var>[A-Za-z_]\w*)", re.I)


@dataclass
class Draft:
    key: tuple[Any, ...]
    path: str
    title: str
    category: str
    severity: str
    confidence: str
    impact: str
    action: str
    command: str | None = None
    rollback: str | None = None
    false_positive_notes: str = ""
    not_observed: list[str] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    lines: list[int] = field(default_factory=list)
    excerpts: dict[int, str] = field(default_factory=dict)
    locator_override: str | None = None


# ---------------------------------------------------------------- léxico PHP

def lex_php(text: str) -> tuple[str, list[tuple[str, int]]]:
    """Mascara comentários e strings, preservando tamanho e quebras de linha.

    Retorna (código_mascarado, strings). O código mascarado permite procurar
    chamadas reais sem casar texto dentro de comentário ou string. As strings
    são usadas para segredos e para o modificador /e de preg_replace.
    """
    n = len(text)
    out = list(text)
    strings: list[tuple[str, int]] = []
    i = 0
    line = 1

    def blank(start: int, end: int) -> None:
        nonlocal line
        for pos in range(start, min(end, n)):
            if text[pos] == "\n":
                line += 1
            else:
                out[pos] = " "

    while i < n:
        ch = text[i]

        if ch == "\n":
            line += 1
            i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            if end < 0:
                end = n
            blank(i, end)
            i = end
            continue

        if ch == "#" and not (i + 1 < n and text[i + 1] == "["):
            end = text.find("\n", i)
            if end < 0:
                end = n
            blank(i, end)
            i = end
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            start_line = line
            j = i + 1
            buf: list[str] = []
            while j < n:
                current = text[j]
                if current == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    if text[j + 1] == "\n":
                        line += 1
                    j += 2
                    continue
                if current == quote:
                    j += 1
                    break
                if current == "\n":
                    line += 1
                buf.append(current)
                j += 1
            blank(i, j)
            strings.append(("".join(buf), start_line))
            i = j
            continue

        if text.startswith("<<<", i):
            match = re.match(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n", text[i:])
            if match:
                label = match.group(2)
                start = i + match.end()
                start_line = line + 1
                closing = re.compile(r"^[ \t]*" + re.escape(label) + r";?[ \t]*$", re.M)
                found = closing.search(text, start)
                end = found.end() if found else n
                content = text[start:found.start()] if found else text[start:]
                strings.append((content, start_line))
                blank(i, end)
                i = end
                continue

        i += 1

    return "".join(out), strings


def line_of(masked: str, pos: int) -> int:
    return masked.count("\n", 0, pos) + 1


def line_text(lines: list[str], number: int) -> str:
    if 1 <= number <= len(lines):
        return lines[number - 1]
    return ""


# ---------------------------------------------------------------- heurísticas

def safe_excerpt(text: str, limit: int = 300) -> str:
    return triage.excerpt(text, limit=min(limit, EXCERPT_MAX))


def is_secret_name(name: str) -> bool:
    clean = name.strip().lstrip("$")
    # dbPassword/dbPass também são nomes comuns; separa camelCase antes do teste.
    clean = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", clean)
    return bool(SECRET_NAME_RE.search(clean))


def is_placeholder(value: str) -> bool:
    clean = value.strip().strip("'\"")
    if not clean:
        return True
    if clean.startswith(("${", "{{", "<%", "%(")):
        return True
    return bool(PLACEHOLDER_RE.fullmatch(clean))


def secret_excerpt(raw: str, value: str) -> str:
    if REDACTION_ENABLED and value:
        return safe_excerpt(raw.replace(value, "[REDACTADO]"))
    return safe_excerpt(raw)


def iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_constraint(constraint: str) -> tuple[str, str] | None:
    """Classifica constraint do composer. Heurística conservadora.

    Só aponta EOL quando a constraint exclui PHP 8 (limite superior < 8)
    ou fixa uma série 5.x/7.x. `>=7.4` sozinho não é apontado, pois permite 8.
    """
    value = constraint.strip().lower()
    if not value:
        return None

    exact = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", value)
    if exact:
        major = int(exact.group(1))
        if major == 5:
            return ("critico", exact.group(0).lstrip("v"))
        if major == 7:
            return ("alto", exact.group(0).lstrip("v"))
        return None

    # Se a constraint oferece explicitamente PHP 8, não trate como runtime
    # exclusivamente 5/7. Ex.: "^7.4 || ^8.0" permite 8 e não é EOL por si.
    if re.search(r"(?:\|\||\^|~|>=)\s*8(?:\.\d+)?", value):
        return None

    upper_below_8 = bool(
        re.search(r"(?:<|<=)\s*8(?:\.0)?(?:\D|$)", value)
        or re.search(r"(?:<|<=)\s*[5-7](?:\.|$|\D)", value)
        or re.search(r"(?:\^|~)\s*[5-7](?:\.|$)", value)
        or re.search(r"\b[5-7]\.\d+\.\*", value)
    )
    if not upper_below_8:
        return None

    five = re.search(r"(?<![\d.])5(?:\.\d+)?", value)
    seven = re.search(r"(?<![\d.])7(?:\.\d+)?", value)
    if five:
        return ("critico", five.group(0))
    if seven:
        return ("alto", seven.group(0))
    return None


def version_severity(major: int, minor: int | None = None) -> str | None:
    if major == 5:
        return "critico"
    if major == 7:
        return "alto"
    return None


class Auditor:
    def __init__(self, *, include_vendor: bool = False, max_file_bytes: int = MAX_FILE_BYTES,
                 max_files: int = MAX_FILES) -> None:
        self.include_vendor = include_vendor
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.drafts: dict[tuple[Any, ...], Draft] = {}
        self.artifacts: dict[str, dict[str, Any]] = {}
        self.security_covered: set[tuple[str, str, int]] = set()
        self.secret_values: set[str] = set()
        self.limits: dict[str, Any] = {
            "bytes_read": 0,
            "lines_read": 0,
            "files_scanned": 0,
            "files_skipped": 0,
            "truncated": False,
            "max_file_bytes": max_file_bytes,
        }
        self.php_files = 0
        self.config_files = 0
        self.skipped_large = 0
        self.skipped_vendor = False
        self.read_errors: list[str] = []
        self.files_seen = 0

    # ------------------------------------------------------------- registro

    def record(self, *, key: tuple[Any, ...], path: str, line: int, excerpt: str,
               title: str, category: str, severity: str, confidence: str,
               impact: str, action: str, command: str | None = None,
               rollback: str | None = None, false_positive_notes: str = "",
               not_observed: Iterable[str] = (),
               observations: dict[str, Any] | None = None,
               locator_override: str | None = None) -> None:
        current = self.drafts.get(key)
        if current is None:
            current = Draft(
                key=key,
                path=path,
                title=title,
                category=category,
                severity=severity,
                confidence=confidence,
                impact=impact,
                action=action,
                command=command,
                rollback=rollback,
                false_positive_notes=false_positive_notes,
                not_observed=list(dict.fromkeys(not_observed)),
                observations=dict(observations or {}),
                locator_override=locator_override,
            )
            self.drafts[key] = current
        else:
            if SEVERITY_RANK[severity] < SEVERITY_RANK[current.severity]:
                current.severity = severity
            if CONFIDENCE_RANK[confidence] < CONFIDENCE_RANK[current.confidence]:
                current.confidence = confidence
            for note in not_observed:
                if note not in current.not_observed:
                    current.not_observed.append(note)
            if observations:
                for obs_key, obs_value in observations.items():
                    if isinstance(obs_value, list):
                        existing = current.observations.setdefault(obs_key, [])
                        for entry in obs_value:
                            if entry not in existing:
                                existing.append(entry)
                    else:
                        current.observations.setdefault(obs_key, obs_value)

        if line not in current.lines:
            current.lines.append(line)
            current.excerpts[line] = excerpt

    def add_eol(self, path: str, line: int, raw: str, version: str,
                reason: str, severity: str) -> None:
        self.record(
            key=(path, "eol"),
            path=path,
            line=line,
            excerpt=safe_excerpt(raw),
            title=f"Runtime PHP {version} fora de suporte",
            category="legacy/eol-runtime",
            severity=severity,
            confidence="alta",
            impact=("Runtime sem correção de segurança. Falhas novas não recebem patch; "
                    "a exposição fica dependente de contenção e migração."),
            action="migrate",
            rollback=("Manter o runtime atual até a migração validada; reverter o deploy "
                      "se houver regressão."),
            false_positive_notes=("A constraint pode ser mais ampla que o runtime real; "
                                  "confirme a versão efetiva com phpquery/php-fpm -i."),
            not_observed=["a versão efetiva do runtime no servidor não foi consultada"],
            observations={"versions": [version], "signals": [{"version": version, "reason": reason, "line": line}]},
        )

    # ------------------------------------------------------------- varredura

    def scan(self, roots: list[Path]) -> None:
        for root in roots:
            if root.is_file():
                self._scan_file(root.resolve())
            elif root.is_dir():
                self._walk(root.resolve())
            else:
                self.read_errors.append(f"caminho não encontrado: {root}")

    def _walk(self, root: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            kept: list[str] = []
            for name in sorted(dirnames):
                if name in SKIP_DIRS_ALWAYS:
                    continue
                if not self.include_vendor and name in SKIP_DIRS_DEFAULT:
                    self.skipped_vendor = True
                    continue
                kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                if self.files_seen >= self.max_files:
                    self.limits["truncated"] = True
                    return
                path = Path(dirpath) / name
                if path.is_symlink() or not path.is_file():
                    continue
                if self._kind(path) is None:
                    continue
                self.files_seen += 1
                self._scan_file(path)

    def _kind(self, path: Path) -> str | None:
        name = path.name
        if name == "composer.json":
            return "composer"
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            return "dockerfile"
        if name == ".php-version":
            return "php-version"
        if name == ".tool-versions":
            return "tool-versions"
        if name == ".env" or name.startswith(".env."):
            return "env"
        if path.suffix.lower() in PHP_SUFFIXES:
            return "php"
        if path.suffix.lower() in KEY_SUFFIXES:
            return "key"
        return None

    def _scan_file(self, path: Path) -> None:
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            self.read_errors.append(f"{path}: {exc}")
            self.limits["files_skipped"] += 1
            return
        if len(raw_bytes) > self.max_file_bytes:
            self.skipped_large += 1
            self.limits["files_skipped"] += 1
            return
        if b"\x00" in raw_bytes[:8192]:
            self.limits["files_skipped"] += 1
            return

        kind = self._kind(path)
        if kind is None:
            return
        text = raw_bytes.decode("utf-8", errors="replace")
        path_str = str(path)
        self.limits["bytes_read"] += len(raw_bytes)
        self.limits["lines_read"] += text.count("\n") + (0 if text.endswith("\n") else 1)
        self.limits["files_scanned"] += 1
        if kind == "php":
            self.php_files += 1
        else:
            self.config_files += 1

        stat_result = path.stat()
        self.artifacts[path_str] = {
            "path": path_str,
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "bytes": str(len(raw_bytes)),
            "mtime": iso_from_timestamp(stat_result.st_mtime),
        }

        lines = text.splitlines()
        if kind == "php":
            self._scan_php(path_str, text, lines)
        elif kind == "composer":
            self._scan_composer(path_str, text, lines)
        elif kind == "dockerfile":
            self._scan_dockerfile(path_str, text, lines)
        elif kind == "php-version":
            self._scan_php_version(path_str, text, lines)
        elif kind == "tool-versions":
            self._scan_tool_versions(path_str, text, lines)
        elif kind == "env":
            self._scan_env(path_str, text, lines, path)
        self._scan_private_key(path_str, text, lines)

    # ------------------------------------------------------------- PHP

    def _scan_php(self, path: str, text: str, lines: list[str]) -> None:
        masked, strings = lex_php(text)
        masked_lines = masked.splitlines()

        # Execução e inclusão controladas por request.
        for pattern, sink_kind in ((RCE_RE, "rce"), (CREATE_FUNCTION_RE, "rce")):
            for match in pattern.finditer(masked):
                fn = match.group("fn").lower()
                number = line_of(masked, match.start())
                self.security_covered.add((path, fn, number))
                self.record(
                    key=(path, "rce", fn),
                    path=path,
                    line=number,
                    excerpt=safe_excerpt(line_text(lines, number)),
                    title=f"Execução controlada por request: {fn}",
                    category="code/rce",
                    severity="critico",
                    confidence="alta",
                    impact=("Entrada de request chega a um sink de execução; um atacante "
                            "pode executar código ou comando no servidor."),
                    action="escalate",
                    false_positive_notes=("Frameworks e templates podem chamar eval de forma "
                                          "controlada; confirme se o fluxo realmente vem do request."),
                    not_observed=["o fluxo entre a entrada e o sink não foi seguido"],
                    observations={"sink": fn, "occurrences": 1},
                )

        for match in INCLUDE_RE.finditer(masked):
            fn = match.group("fn").lower()
            number = line_of(masked, match.start())
            self.record(
                key=(path, "injection", "file-include"),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title="Inclusão de arquivo controlada por request",
                category="code/injection",
                severity="alto",
                confidence="alta",
                impact=("Caminho de arquivo controlado pelo request; pode permitir inclusão "
                        "de arquivo local/remoto e execução de código."),
                action="investigate",
                false_positive_notes="Confirme se o caminho passa por allowlist antes do include.",
                not_observed=["a allowlist de caminhos não foi avaliada"],
                observations={"sink": fn, "occurrences": 1},
            )

        for match in UNSERIALIZE_RE.finditer(masked):
            number = line_of(masked, match.start())
            self.record(
                key=(path, "rce", "unserialize"),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title="Desserialização de dado controlado por request",
                category="code/rce",
                severity="alto",
                confidence="alta",
                impact=("Dado controlado pelo usuário é desserializado; pode permitir object "
                        "injection e execução de código, dependendo das classes carregadas."),
                action="investigate",
                false_positive_notes=("Se o valor for validado/assinado antes de unserialize, "
                                      "o risco é menor."),
                not_observed=["as classes carregadas e seus magic methods não foram analisados"],
                observations={"sink": "unserialize", "occurrences": 1},
            )

        for match in EXTRACT_RE.finditer(masked):
            number = line_of(masked, match.start())
            self.record(
                key=(path, "injection", "extract"),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title="Variáveis do request extraídas para o escopo",
                category="code/injection",
                severity="alto",
                confidence="alta",
                impact=("Chaves do request viram variáveis; podem sobrescrever configuração e "
                        "facilitar inclusão ou execução."),
                action="investigate",
                false_positive_notes="Se houver allowlist explícita de chaves, o risco é menor.",
                not_observed=["o escopo e as variáveis sobrescritas não foram rastreados"],
                observations={"sink": "extract", "occurrences": 1},
            )

        for match in SQL_RE.finditer(masked):
            fn = match.group("fn").lower()
            number = line_of(masked, match.start())
            self.security_covered.add((path, fn, number))
            self.record(
                key=(path, "injection", "sql", fn),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title=f"Consulta SQL concatenada com entrada de request: {fn}",
                category="code/injection",
                severity="alto",
                confidence="media",
                impact=("Entrada de request é concatenada em consulta SQL; pode permitir "
                        "leitura ou alteração do banco."
                        + (" `mysql_*` também foi removido no PHP 7 e bloqueia a migração."
                           if fn.startswith("mysql_") else "")),
                action="investigate",
                false_positive_notes=("Se a variável já passou por prepared statement ou escape "
                                      "confiável, o achado pode ser falso positivo."),
                not_observed=["o fluxo completo e o escape em outras camadas não foram seguidos"],
                observations={"sink": fn, "occurrences": 1,
                              **({"removed_in": "7.0"} if fn.startswith("mysql_") else {})},
            )

        for match in UPLOAD_RE.finditer(masked):
            fn = match.group("fn").lower()
            number = line_of(masked, match.start())
            severity = "alto" if fn == "move_uploaded_file" else "medio"
            self.record(
                key=(path, "upload", fn),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title="Upload de arquivo sem validação visível",
                category="code/upload",
                severity=severity,
                confidence="media",
                impact=("Nome/conteúdo do upload chega ao destino; se o diretório permitir "
                        "execução, pode virar webshell."),
                action="investigate",
                false_positive_notes=("A extensão/MIME pode ser validada em outro arquivo ou no "
                                      "servidor; confirme antes de tratar como explorável."),
                not_observed=["a validação de extensão/MIME e as permissões do diretório não foram avaliadas"],
                observations={"sink": fn, "occurrences": 1},
            )

        # preg_replace com /e: o modificador fica na string, não no código mascarado.
        for value, string_line in strings:
            if not self._preg_replace_e(value):
                continue
            window = range(max(1, string_line - 4), string_line + 1)
            if not any("preg_replace" in masked_lines[n - 1] for n in window if 1 <= n <= len(masked_lines)):
                continue
            self.record(
                key=(path, "rce", "preg_replace_e"),
                path=path,
                line=string_line,
                excerpt=safe_excerpt(line_text(lines, string_line)),
                title="preg_replace com modificador /e",
                category="code/rce",
                severity="alto",
                confidence="alta",
                impact=("O modificador /e executa o resultado como código em PHP antigo; "
                        "entrada controlada pode virar execução remota. Foi removido no PHP 7."),
                action="investigate",
                false_positive_notes="Confirme se o padrão ou a substituição vêm de entrada externa.",
                not_observed=["a origem do padrão e da substituição não foi rastreada"],
                observations={"sink": "preg_replace /e", "occurrences": 1},
            )

        # Funções removidas: migração. Não duplica linha já tratada como RCE/SQLi.
        for pattern, removed_in in REMOVED_FUNCTIONS:
            for match in pattern.finditer(masked):
                fn = match.group("fn")
                number = line_of(masked, match.start())
                if (path, fn.lower(), number) in self.security_covered:
                    continue
                line = line_text(lines, number)
                # Não confunda chamada com declaração de função homônima ou
                # método de mesmo nome. `__autoload` é declaração por natureza.
                if fn != "__autoload":
                    if re.search(rf"\bfunction\s+{re.escape(fn)}\s*\(", line, re.I):
                        continue
                    if re.search(rf"(?:->|::)\s*{re.escape(fn)}\s*\(", line, re.I):
                        continue
                self.record(
                    key=(path, "migration", fn.lower()),
                    path=path,
                    line=number,
                    excerpt=safe_excerpt(line),
                    title=f"Função removida no PHP {removed_in}: {fn}",
                    category="legacy/migration-blocker",
                    severity="alto",
                    confidence="alta",
                    impact=(f"`{fn}` foi removido no PHP {removed_in}; o arquivo falha ao "
                            "executar nessa versão e bloqueia a migração."),
                    action="investigate",
                    false_positive_notes=("A ocorrência pode estar em código morto; ainda bloqueia "
                                          "a migração se o arquivo for carregado."),
                    not_observed=["o caminho de execução até essa função não foi seguido"],
                    observations={"symbol": fn, "removed_in": removed_in, "occurrences": 1},
                )

        for match in CURLY_OFFSET_RE.finditer(masked):
            fn = match.group("fn")
            number = line_of(masked, match.start())
            self.record(
                key=(path, "migration", "curly-offset"),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title="Acesso a índice com chaves removido no PHP 8",
                category="legacy/migration-blocker",
                severity="alto",
                confidence="alta",
                impact=("A sintaxe `$var{0}` foi removida no PHP 8; use `$var[0]` antes de migrar."),
                action="investigate",
                false_positive_notes="Confirme se a linha é código carregado e não trecho comentado.",
                not_observed=["a sintaxe foi detectada por padrão lexical, sem parser completo"],
                observations={"symbol": "curly-offset", "removed_in": "8.0", "occurrences": 1},
            )

        # Hash rápido em senha.
        for match in WEAK_HASH_RE.finditer(masked):
            var = match.group("var")
            if not is_secret_name(var):
                continue
            number = line_of(masked, match.start())
            fn = match.group("fn").lower()
            self.record(
                key=(path, "secrets", "weak-hash", fn),
                path=path,
                line=number,
                excerpt=safe_excerpt(line_text(lines, number)),
                title=f"Hash rápido usado em senha: {fn}",
                category="posture/secrets",
                severity="medio",
                confidence="alta",
                impact=("Hash rápido e sem salt adequado; senhas vazadas podem ser quebradas "
                        "rapidamente. Prefira password_hash/password_verify."),
                action="investigate",
                false_positive_notes="Confirme se a variável é realmente uma senha e não um checksum.",
                not_observed=["o armazenamento e a política de senha não foram avaliados"],
                observations={"algorithm": fn, "variable": var, "occurrences": 1},
            )

        # Segredos literais em PHP.
        self._scan_php_secrets(path, lines, masked_lines)

        self._scan_private_key(path, text, lines)

    @staticmethod
    def _preg_replace_e(value: str) -> bool:
        match = re.match(r"^([^A-Za-z0-9\s]).*\1([a-zA-Z]*)$", value, re.S)
        return bool(match and "e" in match.group(2).lower())

    def _scan_php_secrets(self, path: str, lines: list[str], masked_lines: list[str]) -> None:
        assignment_single = re.compile(
            r"\$(?P<name>[A-Za-z_]\w*)\s*=\s*'(?P<value>(?:\\.|[^'\\])*)'"
        )
        assignment_double = re.compile(
            r'\$(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<value>(?:\\.|[^"\\])*)"'
        )
        define_single = re.compile(
            r"\bdefine\s*\(\s*'(?P<name>[A-Za-z_]\w*)'\s*,\s*'(?P<value>(?:\\.|[^'\\])*)'"
        )
        define_double = re.compile(
            r'\bdefine\s*\(\s*"(?P<name>[A-Za-z_]\w*)"\s*,\s*"(?P<value>(?:\\.|[^"\\])*)"'
        )
        const_single = re.compile(
            r"\bconst\s+(?P<name>[A-Za-z_]\w*)\s*=\s*'(?P<value>(?:\\.|[^'\\])*)'"
        )
        const_double = re.compile(
            r'\bconst\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<value>(?:\\.|[^"\\])*)"'
        )
        connect_single = re.compile(
            r"\b(?:mysql|mysqli)_connect\s*\([^;\n]*?,\s*[^,;\n]+,\s*"
            r"'(?P<value>(?:\\.|[^'\\])*)'"
        )
        connect_double = re.compile(
            r'\b(?:mysql|mysqli)_connect\s*\([^;\n]*?,\s*[^,;\n]+,\s*'
            r'"(?P<value>(?:\\.|[^"\\])*)"'
        )

        for index, raw in enumerate(lines):
            masked = masked_lines[index] if index < len(masked_lines) else ""
            candidates: list[tuple[str, str, str]] = []

            for pattern, require in (
                (assignment_single, "$"),
                (assignment_double, "$"),
                (define_single, "define"),
                (define_double, "define"),
                (const_single, "const"),
                (const_double, "const"),
            ):
                for match in pattern.finditer(raw):
                    name = match.group("name")
                    if require == "$":
                        if f"${name}" not in masked:
                            continue
                    elif require not in masked:
                        continue
                    candidates.append((name, match.group("value"), raw))

            for pattern in (connect_single, connect_double):
                for match in pattern.finditer(raw):
                    if "mysql" not in masked:
                        continue
                    candidates.append(("db_password", match.group("value"), raw))

            for name, value, raw_line in candidates:
                if not is_secret_name(name):
                    continue
                if is_placeholder(value) or (raw_line.count("$") and value.startswith("$")):
                    continue
                if '"' in raw_line and "$" in value:
                    continue
                self.secret_values.add(value)
                self.record(
                    key=(path, "secrets", name.lower()),
                    path=path,
                    line=index + 1,
                    excerpt=secret_excerpt(raw_line, value),
                    title=f"Credencial literal no código: {name}",
                    category="posture/secrets",
                    severity="alto",
                    confidence="alta",
                    impact=("Credencial legível no código/repositório; quem acessa o código "
                            "pode usá-la para autenticar no serviço."),
                    action="rotate-credential",
                    rollback=("Manter a credencial antiga ativa até a nova ser validada; "
                              "revogar a nova se a integração falhar."),
                    false_positive_notes=("O valor pode ser placeholder não reconhecido ou "
                                          "credencial já revogada."),
                    not_observed=["o valor não foi testado contra o serviço"],
                    observations={"name": name, "occurrences": 1},
                )

    def _scan_private_key(self, path: str, text: str, lines: list[str]) -> None:
        match = PRIVATE_KEY_RE.search(text)
        if not match:
            return
        number = line_of(text, match.start())
        self.record(
            key=(path, "secrets", "private-key"),
            path=path,
            line=number,
            excerpt="-----BEGIN ... PRIVATE KEY----- [conteúdo omitido]",
            title="Chave privada no repositório",
            category="posture/secrets",
            severity="critico",
            confidence="alta",
            impact=("Chave privada acessível junto com o código; permite impersonar o serviço "
                    "ou descriptografar tráfego, conforme o uso da chave."),
            action="rotate-credential",
            rollback=("Manter a chave antiga em uso até a nova ser validada; revogar a nova "
                      "se a integração falhar."),
            false_positive_notes="Confirme se é chave de produção e não material de teste.",
            not_observed=["o escopo e os sistemas que confiam nessa chave não foram verificados"],
            observations={"name": "private-key", "occurrences": 1},
        )

    # ------------------------------------------------------------- configuração

    def _scan_composer(self, path: str, text: str, lines: list[str]) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self.read_errors.append(f"{path}: JSON inválido na linha {exc.lineno}")
            return
        if not isinstance(data, dict):
            return

        require = data.get("require")
        if isinstance(require, dict):
            constraint = require.get("php")
            if isinstance(constraint, str):
                classified = classify_constraint(constraint)
                if classified:
                    severity, version = classified
                    number = self._find_line(lines, '"php"', 1)
                    self.add_eol(path, number, line_text(lines, number), version,
                                 "constraint require.php do composer", severity)

        platform = data.get("config", {}).get("platform", {}) if isinstance(data.get("config"), dict) else {}
        if isinstance(platform, dict):
            exact = platform.get("php")
            if isinstance(exact, str):
                match = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", exact.strip())
                if match:
                    severity = version_severity(int(match.group(1)))
                    if severity:
                        number = self._find_line_after(lines, '"platform"', '"php"', 1)
                        self.add_eol(path, number, line_text(lines, number),
                                     match.group(0).lstrip("v"),
                                     "config.platform.php do composer", severity)

    def _scan_dockerfile(self, path: str, text: str, lines: list[str]) -> None:
        for index, raw in enumerate(lines, 1):
            from_match = re.search(r"\bphp:(\d+)(?:\.(\d+))?", raw, re.I)
            if from_match and raw.lstrip().upper().startswith("FROM"):
                major = int(from_match.group(1))
                severity = version_severity(major)
                if severity:
                    version = from_match.group(0).split(":", 1)[1]
                    self.add_eol(path, index, raw, version, "imagem base do Dockerfile", severity)

            arg_match = re.match(r"\s*ARG\s+PHP_VERSION=(\d+)(?:\.(\d+))?", raw, re.I)
            if arg_match:
                severity = version_severity(int(arg_match.group(1)))
                if severity:
                    self.add_eol(path, index, raw, arg_match.group(1),
                                 "ARG PHP_VERSION do Dockerfile", severity)

            env_match = re.match(r"\s*(?:ENV|ARG)\s+([A-Za-z_]\w*)\s*=\s*(.+?)\s*$", raw)
            if env_match:
                name, value = env_match.group(1), env_match.group(2).strip().strip("'\"")
                if is_secret_name(name) and not is_placeholder(value) and not value.startswith("$"):
                    self.secret_values.add(value)
                    self.record(
                        key=(path, "secrets", name.lower()),
                        path=path,
                        line=index,
                        excerpt=secret_excerpt(raw, value),
                        title=f"Credencial literal no Dockerfile: {name}",
                        category="posture/secrets",
                        severity="alto",
                        confidence="alta",
                        impact=("Credencial legível na imagem/repositório; qualquer acesso à "
                                "imagem ou ao Dockerfile permite usá-la."),
                        action="rotate-credential",
                        rollback=("Manter a credencial antiga ativa até a nova ser validada; "
                                  "revogar a nova se a integração falhar."),
                        false_positive_notes="O valor pode ser placeholder não reconhecido.",
                        not_observed=["o valor não foi testado contra o serviço"],
                        observations={"name": name, "occurrences": 1},
                    )

    def _scan_php_version(self, path: str, text: str, lines: list[str]) -> None:
        for index, raw in enumerate(lines, 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            match = re.match(r"v?(\d+)(?:\.(\d+))?", value)
            if not match:
                continue
            severity = version_severity(int(match.group(1)))
            if severity:
                self.add_eol(path, index, raw, match.group(0).lstrip("v"),
                             "arquivo .php-version", severity)
            return

    def _scan_tool_versions(self, path: str, text: str, lines: list[str]) -> None:
        for index, raw in enumerate(lines, 1):
            match = re.match(r"\s*php\s+v?(\d+)(?:\.(\d+))?", raw, re.I)
            if not match:
                continue
            severity = version_severity(int(match.group(1)))
            if severity:
                self.add_eol(path, index, raw, match.group(1),
                             "arquivo .tool-versions", severity)

    def _scan_env(self, path: str, text: str, lines: list[str], file_path: Path) -> None:
        for index, raw in enumerate(lines, 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", raw)
            if not match:
                continue
            name, value = match.group(1), match.group(2).strip().strip("'\"")
            if is_secret_name(name) and not is_placeholder(value) and not value.startswith("$"):
                self.secret_values.add(value)
                self.record(
                    key=(path, "secrets", name.lower()),
                    path=path,
                    line=index,
                    excerpt=secret_excerpt(raw, value),
                    title=f"Credencial literal no arquivo de ambiente: {name}",
                    category="posture/secrets",
                    severity="alto",
                    confidence="alta",
                    impact=("Credencial legível no arquivo de ambiente; qualquer acesso ao "
                            "arquivo ou ao repositório permite usá-la."),
                    action="rotate-credential",
                    rollback=("Manter a credencial antiga ativa até a nova ser validada; "
                              "revogar a nova se a integração falhar."),
                    false_positive_notes="O valor pode ser placeholder não reconhecido.",
                    not_observed=["o valor não foi testado contra o serviço"],
                    observations={"name": name, "occurrences": 1},
                )

        if file_path.name == ".env":
            try:
                mode = stat.S_IMODE(file_path.stat().st_mode)
            except OSError:
                return
            if mode & 0o077:
                self.record(
                    key=(path, "permissions", "env"),
                    path=path,
                    line=1,
                    excerpt=f"modo {oct(mode)}; recomendado 0600",
                    title="Arquivo .env legível por grupo ou outros",
                    category="posture/permissions",
                    severity="medio",
                    confidence="alta",
                    impact=("Usuários locais sem privilégio podem ler as credenciais do "
                            "arquivo de ambiente."),
                    action="investigate",
                    false_positive_notes="Confirme dono, grupo e ACLs antes de alterar o modo.",
                    not_observed=["ACLs e dono do arquivo não foram avaliados"],
                    observations={"mode": oct(mode)},
                    locator_override="permissões do arquivo",
                )

    @staticmethod
    def _find_line(lines: list[str], needle: str, default: int) -> int:
        for index, raw in enumerate(lines, 1):
            if needle in raw:
                return index
        return default

    @staticmethod
    def _find_line_after(lines: list[str], first: str, second: str, default: int) -> int:
        start = 0
        for index, raw in enumerate(lines, 1):
            if first in raw:
                start = index
                break
        if start:
            for index in range(start, len(lines) + 1):
                if second in lines[index - 1]:
                    return index
        return default

    # ------------------------------------------------------------- resultado

    def finalize(self, *, roots: list[str], now: datetime, host: str,
                 scan_id: str) -> dict[str, Any]:
        ordered = sorted(
            self.drafts.values(),
            key=lambda d: (SEVERITY_RANK[d.severity], CONFIDENCE_RANK[d.confidence],
                           d.path, d.title),
        )
        if REDACTION_ENABLED:
            # Um valor secreto pode aparecer em outra linha (ex.: argumento de
            # mysql_connect também citado no achado de migração). Depois de
            # coletar todos os valores, remove-os de qualquer excerto.
            for draft in ordered:
                for number, text in draft.excerpts.items():
                    for value in sorted(self.secret_values, key=lambda item: (len(item), item), reverse=True):
                        text = text.replace(f"'{value}'", "'[REDACTADO]'")
                        text = text.replace(f'"{value}"', '"[REDACTADO]"')
                        if len(value) >= 4 and value in text:
                            text = text.replace(value, "[REDACTADO]")
                    draft.excerpts[number] = text
        findings: list[dict[str, Any]] = []
        for index, draft in enumerate(ordered, 1):
            # Material de chave privada nunca é impresso, nem com --redact off.
            redacted = True if (
                draft.category == "posture/secrets"
                and draft.observations.get("name") == "private-key"
            ) else REDACTION_ENABLED
            if draft.locator_override:
                evidence = [{
                    "source": draft.path,
                    "locator": draft.locator_override,
                    "excerpt": draft.excerpts.get(1, ""),
                    "redacted": redacted,
                    "source_type": "code",
                }]
            else:
                lines = sorted(draft.lines)
                evidence = [{
                    "source": draft.path,
                    "locator": f"linha {number}",
                    "excerpt": draft.excerpts.get(number, ""),
                    "redacted": redacted,
                    "source_type": "code",
                } for number in lines[:3]]
                if not evidence:
                    evidence = [{
                        "source": draft.path,
                        "locator": "arquivo",
                        "excerpt": "",
                        "redacted": redacted,
                        "source_type": "code",
                    }]

            observations = dict(draft.observations)
            if len(draft.lines) > 1:
                observations["lines"] = sorted(draft.lines)
                if "occurrences" in observations:
                    observations["occurrences"] = len(draft.lines)
            recommendation: dict[str, Any] = {
                "action": draft.action,
                "requires_approval": draft.action not in triage.NO_APPROVAL_ACTIONS,
            }
            if draft.command:
                recommendation["command"] = draft.command
            if draft.rollback:
                recommendation["rollback"] = draft.rollback

            item: dict[str, Any] = {
                "id": f"F-{index:03d}",
                "title": draft.title,
                "category": draft.category,
                "severity": draft.severity,
                "confidence": draft.confidence,
                "evidence": evidence,
                "impact": draft.impact,
                "recommendation": recommendation,
                "false_positive_notes": draft.false_positive_notes,
                "not_observed": list(dict.fromkeys(draft.not_observed)),
                "observations": observations,
            }
            findings.append(item)

        counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
        for item in findings:
            counts[item["severity"]] += 1
        verdict = "incidente" if counts["critico"] else "atencao" if counts["alto"] or counts["medio"] else "estavel"

        grouped: dict[str, list[str]] = {}
        for item in findings:
            grouped.setdefault(item["evidence"][0]["source"], []).append(item["id"])
        correlations = [
            {"key": source, "findings": ids,
             "note": f"{len(ids)} achados no mesmo arquivo"}
            for source, ids in sorted(grouped.items()) if len(ids) >= 2
        ]

        notes: list[str] = [
            "análise lexical e por padrões: não executa o código nem segue fluxo entre arquivos",
            "não avalia lógica de negócio, controle de acesso, configuração do servidor ou dependências transitivas",
        ]
        if self.skipped_vendor:
            notes.append("vendor/ e node_modules foram ignorados; use --include-vendor para auditar dependências instaladas")
        if self.skipped_large:
            notes.append(f"{self.skipped_large} arquivo(s) acima de {self.max_file_bytes} bytes foram ignorados")
        if self.limits["truncated"]:
            notes.append(f"limite de {self.max_files} arquivos atingido; a varredura foi truncada")
        if not self.php_files:
            notes.append("nenhum arquivo PHP foi encontrado nos caminhos informados")
        if not any(item["category"] == "legacy/eol-runtime" for item in findings):
            notes.append("versão efetiva do runtime não confirmada; execute phpquery/php-fpm -i no servidor")
        notes.extend(self.read_errors)
        notes = list(dict.fromkeys(notes))

        artifact_map = {
            source: self.artifacts[source]
            for item in findings for source in {ev["source"] for ev in item["evidence"]}
            if source in self.artifacts
        }

        result: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "scan": {
                "id": scan_id,
                "tool": TOOL,
                "host": host,
                "started_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finished_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "window": {
                    "from": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "to": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                "sources": roots,
                "limits": {
                    **self.limits,
                    "php_files": self.php_files,
                    "config_files": self.config_files,
                },
                "artifacts": sorted(artifact_map.values(), key=lambda item: item["path"]),
            },
            "findings": findings,
            "summary": {
                "verdict": verdict,
                "counts": counts,
                "correlations": correlations,
                "not_observed": notes,
            },
        }
        return result


# ---------------------------------------------------------------- Markdown

def render_markdown(result: dict[str, Any]) -> str:
    scan = result["scan"]
    summary = result["summary"]
    counts = summary["counts"]
    total = sum(counts.values())
    lines = [
        f"# Auditoria de código PHP — {scan['host']}",
        "",
        f"**Veredito:** {summary['verdict']}",
        f"**Quando:** {scan['started_at']}",
        f"**Fontes:** {', '.join(scan['sources'])}",
        f"**Arquivos:** {scan['limits']['php_files']} PHP, "
        f"{scan['limits']['config_files']} de configuração; "
        f"{scan['limits']['lines_read']} linhas lidas",
        f"**Achados:** " + " · ".join(
            f"{SEVERITY_LABEL[level].lower()} {counts[level]}"
            for level in ("critico", "alto", "medio", "baixo")
        ),
        "",
    ]
    if total == 0:
        lines += ["Nenhum sinal encontrado nos padrões conhecidos. Isso não é atestado de segurança.", ""]
    else:
        critical = [item["title"] for item in result["findings"] if item["severity"] == "critico"]
        headline = critical[0] if critical else result["findings"][0]["title"]
        lines += [f"**Em uma frase:** {total} sinal(is); o mais grave é “{headline}”.", ""]

    lines += ["## Achados", ""]
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
        if item.get("false_positive_notes"):
            lines.append(f"- **Falso positivo:** {item['false_positive_notes']}")
        for note in item.get("not_observed", []):
            lines.append(f"- **Não observado:** {note}")
        lines.append("")

    if summary["correlations"]:
        lines += ["## Correlação", ""]
        for correlation in summary["correlations"]:
            lines.append(f"- `{correlation['key']}`: {', '.join(correlation['findings'])} — {correlation['note']}")
        lines.append("")

    lines += ["## Não observado", ""] + [f"- {note}" for note in summary["not_observed"]] + [""]
    lines += ["> Auditoria somente leitura. Nenhum arquivo foi alterado.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Auditoria estática somente leitura de código PHP.",
        epilog="Exemplo: ./php_audit.py /var/www/app --format md --output /tmp/php-audit.md",
    )
    parser.add_argument("paths", nargs="*", type=Path, default=[Path(".")],
                        help="diretórios ou arquivos PHP/config (padrão: .)")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--output", type=Path, help="arquivo de saída (padrão: stdout)")
    parser.add_argument("--include-vendor", action="store_true",
                        help="inclui vendor/, node_modules/ e bower_components/")
    parser.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES)
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--now", help="fixa o instante do scan (ISO 8601), útil para reprodutibilidade")
    parser.add_argument("--host", default="", help="identificador do host")
    parser.add_argument("--scan-id", help="ID do scan (padrão: gaara-YYYYMMDD-0001)")
    parser.add_argument("--redact", choices=("on", "off"), default="on")
    parser.add_argument("--redact-off-reason", help="justificativa obrigatória para --redact off")
    args = parser.parse_args(argv)

    if args.max_file_bytes <= 0 or args.max_files <= 0:
        print("erro: limites devem ser positivos", file=sys.stderr)
        return 2
    if args.redact == "off" and not args.redact_off_reason:
        print("erro: --redact off exige --redact-off-reason", file=sys.stderr)
        return 2
    if args.redact == "off":
        global REDACTION_ENABLED
        REDACTION_ENABLED = False
        triage.REDACTION_ENABLED = False
        triage.redact = lambda text: triage.sanitize(text.replace("\r", " ").replace("\n", " "))  # noqa: E731
        print("aviso: redação desativada; não compartilhe a saída", file=sys.stderr)

    try:
        now = parse_now(args.now)
    except ValueError:
        print(f"erro: --now inválido: {args.now}", file=sys.stderr)
        return 2

    missing = [path for path in args.paths if not path.exists()]
    if missing:
        for path in missing:
            print(f"erro: caminho não encontrado: {path}", file=sys.stderr)
        return 1

    auditor = Auditor(
        include_vendor=args.include_vendor,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
    )
    auditor.scan(args.paths)
    host = args.host or platform.node() or "desconhecido"
    scan_id = args.scan_id or f"gaara-{now.strftime('%Y%m%d')}-0001"
    result = auditor.finalize(
        roots=[str(path.resolve()) for path in args.paths],
        now=now,
        host=host,
        scan_id=scan_id,
    )

    errors = triage.validate(result)
    if errors:
        for error in errors:
            print(f"schema: {error}", file=sys.stderr)
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
