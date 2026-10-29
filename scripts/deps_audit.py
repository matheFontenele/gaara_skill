#!/usr/bin/env python3
"""deps_audit.py — inventário de dependências e correlação com vulnerabilidades conhecidas.

Duas fases independentes:

  A. Inventário (offline, determinístico)
     Lê lockfiles/manifests, monta a lista de dependências e reporta o que não
     conseguiu ler. Nunca baixa nada, nunca altera o projeto.

  B. Correlação (rede, só com --online)
     Consulta OSV.dev (afetação por pacote), CISA KEV (exploração ativa),
     EPSS (probabilidade) e NVD (CVSS oficial, enriquecimento opcional).

Somente leitura. Nenhum comando de atualização é executado: o script emite a
recomendação com comando e rollback, e a execução depende de aprovação.

Uso:
    ./deps_audit.py .
    ./deps_audit.py . --format md
    ./deps_audit.py . --online
    ./deps_audit.py . --online --nvd off --cache-dir ~/.cache/gaara
    ./deps_audit.py . --online --offline            # usa apenas o cache
    ./deps_audit.py --list-parsers

Códigos de saída:
    0  executou, nenhum achado alto/crítico
    1  erro de execução
    2  uso incorreto
    3  executou e encontrou achado alto ou crítico

Contrato de saída: references/finding-schema.md (schema_version 1.1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - ambiente antigo
    tomllib = None  # type: ignore[assignment]

SCHEMA_VERSION = "1.1"
TOOL = "deps_audit"
USER_AGENT = "gaara-deps-audit/1.1 (+https://github.com/matheFontenele/gaara_skill)"
EXCERPT_MAX = 500
MAX_FILES = 20000
HTTP_TIMEOUT = 20
MAX_FINDINGS_DEFAULT = 200
MAX_NVD_DEFAULT = 20
EPSS_THRESHOLD_DEFAULT = 0.1

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"

TTL_OSV = timedelta(hours=24)
TTL_NVD = timedelta(hours=24)
TTL_KEV = timedelta(days=7)
TTL_EPSS = timedelta(hours=12)

SEVERITY_RANK = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
SEVERITY_LABEL = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MÉDIO", "baixo": "BAIXO"}
SEVERITY_ORDER = ["baixo", "medio", "alto", "critico"]
CONFIDENCE_RANK = {"alta": 0, "media": 1, "baixa": 2}
ACTIONS = {
    "none", "monitor", "investigate", "escalate",
    "ban", "unban", "isolate", "patch", "migrate", "rotate-credential",
}
NO_APPROVAL_ACTIONS = {"none", "monitor", "investigate", "escalate"}

# Prefixos aceitos pela lista fechada do schema 1.1.
SUPPLY_CHAIN_CATEGORIES = {
    "supply-chain/known-vulnerability",
    "supply-chain/inventory-gap",
    "supply-chain/unpinned-dependency",
    "supply-chain/docker-base-image",
    "supply-chain/os-package",
}
CVE_CATEGORY_RE = re.compile(r"^cve/cve-\d{4}-\d{4,}$", re.IGNORECASE)

PRUNE_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules", "bower_components", "vendor", "dist", "build", "target",
    "coverage", "__pycache__", "site-packages", ".venv", "venv", "env",
    ".next", ".nuxt", ".svelte-kit", ".terraform", "Pods",
}

# ecossistema interno -> ecossistema OSV
OSV_ECOSYSTEM = {
    "packagist": "Packagist",
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates": "crates.io",
    "rubygems": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
}

LABEL_SEVERITY = {
    "CRITICAL": "critico",
    "HIGH": "alto",
    "MODERATE": "medio",
    "MEDIUM": "medio",
    "LOW": "baixo",
}


# ---------------------------------------------------------------- utilidades


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_TAG_RE = re.compile(r"<[^>]{1,200}>")
_WS_RE = re.compile(r"\s+")


def clean_text(value: str, limit: int = EXCERPT_MAX) -> str:
    """Neutraliza conteúdo de advisory hostil antes de citar.

    Advisory é dado não confiável: pode conter escape de terminal, HTML ou
    instrução direcionada ao modelo. Aqui só removemos o que é ativo; o texto
    restante é citado, nunca interpretado como comando.
    """
    text = _ANSI_RE.sub("", value or "")
    text = _CONTROL_RE.sub(" ", text)
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def locate_line(text: str, needle: str, start: int = 0) -> int:
    index = text.find(needle, start)
    if index < 0:
        return 0
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------- modelo


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    source: str
    line: int = 0
    scope: str = "runtime"
    pinned: bool = True
    confidence: str = "alta"

    @property
    def key(self) -> tuple[str, str]:
        return (self.ecosystem, self.name.lower())


@dataclass
class Manifest:
    path: str
    fmt: str
    parsed: bool
    packages: int = 0
    reason: str = ""


@dataclass
class Inventory:
    packages: list[Package] = field(default_factory=list)
    manifests: list[Manifest] = field(default_factory=list)
    unpinned: list[Package] = field(default_factory=list)
    docker_images: list[Package] = field(default_factory=list)

    def add(self, package: Package) -> None:
        if package.pinned and package.version:
            self.packages.append(package)
        else:
            self.unpinned.append(package)


@dataclass
class SourceMeta:
    name: str
    url: str
    retrieved_at: str | None = None
    stale: bool = False
    cached: bool = False
    error: str | None = None


@dataclass
class Hit:
    package: Package
    osv_id: str
    cve_id: str | None
    summary: str
    fixed: str | None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_source: str | None = None
    severity_label: str | None = None
    kev: bool = False
    epss: float | None = None
    published: str | None = None
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)


class SourceError(RuntimeError):
    """Falha ao consultar uma fonte externa."""


# ---------------------------------------------------------------- cache/http


def cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:40]


def cache_path(cache_dir: Path, url: str) -> Path:
    return cache_dir / f"{cache_key(url)}.json"


def cache_store(cache_dir: Path, url: str, body: Any, fetched_at: datetime | None = None) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_path(cache_dir, url)
    payload = {
        "url": url,
        "fetched_at": iso(fetched_at or utcnow()),
        "body": body,
    }
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(target)
    return target


def cache_load(cache_dir: Path, url: str, ttl: timedelta, now: datetime) -> tuple[Any, datetime, bool] | None:
    target = cache_path(cache_dir, url)
    if not target.is_file():
        return None
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        fetched_at = datetime.fromisoformat(payload["fetched_at"].replace("Z", "+00:00"))
        stale = (now - fetched_at) > ttl
        return payload["body"], fetched_at, stale
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def http_json(url: str, *, cache_dir: Path, ttl: timedelta, offline: bool,
              refresh: bool, headers: dict[str, str] | None = None,
              timeout: int = HTTP_TIMEOUT) -> tuple[Any, SourceMeta]:
    now = utcnow()
    if not refresh:
        cached = cache_load(cache_dir, url, ttl, now)
        if cached is not None:
            body, fetched_at, stale = cached
            if offline or not stale:
                return body, SourceMeta(
                    name=url, url=url, retrieved_at=iso(fetched_at),
                    stale=stale, cached=True,
                )

    if offline:
        cached = cache_load(cache_dir, url, ttl, now)
        if cached is None:
            raise SourceError(f"offline: sem cache para {url}")
        body, fetched_at, stale = cached
        return body, SourceMeta(name=url, url=url, retrieved_at=iso(fetched_at),
                                stale=True, cached=True)

    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:  # pragma: no cover - rede
        raise SourceError(f"HTTP {exc.code} em {url}") from exc
    except (urllib.error.URLError, socket.timeout, OSError) as exc:  # pragma: no cover - rede
        raise SourceError(f"falha de rede em {url}: {exc}") from exc

    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:  # pragma: no cover - rede
        raise SourceError(f"resposta não-JSON em {url}") from exc

    cache_store(cache_dir, url, body, now)
    return body, SourceMeta(name=url, url=url, retrieved_at=iso(now))


# ---------------------------------------------------------------- parsers
#
# Cada parser devolve (pacotes, motivo_de_falha). Falha nunca é silenciosa:
# o manifest entra no relatório como inventory-gap.


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse_composer_lock(path: Path) -> list[Package]:
    text = _read(path)
    data = json.loads(text)
    packages: list[Package] = []
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for item in data.get(section) or []:
            name = str(item.get("name", "")).strip()
            version = str(item.get("version", "")).strip()
            if not name or not version:
                continue
            line = locate_line(text, f'"{name}"')
            packages.append(Package("packagist", name, version.lstrip("v"), str(path),
                                    line, scope, True, "alta"))
    return packages


def parse_composer_json(path: Path) -> list[Package]:
    text = _read(path)
    data = json.loads(text)
    packages: list[Package] = []
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, constraint in block.items():
            if name in {"php", "ext-*"} or str(name).startswith("ext-"):
                continue
            line = locate_line(text, f'"{name}"')
            packages.append(Package("packagist", str(name), str(constraint), str(path),
                                    line, scope, False, "baixa"))
    return packages


def parse_package_lock(path: Path) -> list[Package]:
    text = _read(path)
    data = json.loads(text)
    packages: list[Package] = []
    entries = data.get("packages")
    if isinstance(entries, dict):
        for location, info in entries.items():
            if not isinstance(info, dict) or not location:
                continue
            name = str(info.get("name") or location.split("node_modules/")[-1])
            version = str(info.get("version") or "")
            if not name or not version:
                continue
            scope = "dev" if info.get("dev") else "runtime"
            line = locate_line(text, f'"{location}"')
            packages.append(Package("npm", name, version, str(path), line, scope, True, "alta"))
        return packages

    def walk(deps: dict[str, Any], scope: str) -> None:
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "")
            if version:
                line = locate_line(text, f'"{name}"')
                packages.append(Package("npm", str(name), version, str(path), line,
                                        scope, True, "alta"))
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, scope)

    walk(data.get("dependencies") or {}, "runtime")
    return packages


_YARN_V1_HEADER = re.compile(r"^([^\s#].*):\s*$")
_YARN_V1_VERSION = re.compile(r'^\s+version\s+"?([^"\s]+)"?\s*$')
_YARN_BERRY_VERSION = re.compile(r"^\s+version:\s*\"?([^\"\s]+)\"?\s*$")


def parse_yarn_lock(path: Path) -> list[Package]:
    packages: list[Package] = []
    current: str | None = None
    current_line = 0
    for number, raw in enumerate(_read(path).splitlines(), 1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        header = _YARN_V1_HEADER.match(line)
        if header and not line.startswith(" "):
            spec = header.group(1).split(",")[0].strip().strip('"')
            if "@" in spec:
                name, _, _range = spec.rpartition("@")
                current = name or spec
                current_line = number
                continue
        if current:
            match = _YARN_V1_VERSION.match(line) or _YARN_BERRY_VERSION.match(line)
            if match:
                packages.append(Package("npm", current, match.group(1), str(path),
                                        current_line, "runtime", True, "alta"))
                current = None
    return packages


_PNPM_KEY = re.compile(r"^  '?(?:/)?(?P<name>(?:@[^/@]+/)?[^@'\s]+)@(?P<version>[^:'\s(]+)")


def parse_pnpm_lock(path: Path) -> list[Package]:
    packages: list[Package] = []
    in_packages = False
    for number, raw in enumerate(_read(path).splitlines(), 1):
        if re.match(r"^(packages|snapshots):\s*$", raw):
            in_packages = True
            continue
        if in_packages and raw and not raw.startswith(" "):
            in_packages = False
        if not in_packages:
            continue
        match = _PNPM_KEY.match(raw)
        if match:
            packages.append(Package("npm", match.group("name"), match.group("version"),
                                    str(path), number, "runtime", True, "alta"))
    return packages


_REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#]+)")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def canonical_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path) -> list[Package]:
    packages: list[Package] = []
    for number, raw in enumerate(_read(path).splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        pinned = _REQ_PIN.match(line)
        if pinned:
            packages.append(Package("pypi", canonical_pypi(pinned.group(1)),
                                    pinned.group(2), str(path), number, "runtime", True, "alta"))
            continue
        named = _REQ_NAME.match(line)
        if named:
            packages.append(Package("pypi", canonical_pypi(named.group(1)),
                                    named.group(2) or "*", str(path), number,
                                    "runtime", False, "baixa"))
    return packages


def _toml_packages(path: Path, ecosystem: str) -> list[Package]:
    if tomllib is None:
        raise ValueError("tomllib requer Python 3.11+")
    data = tomllib.loads(_read(path))
    text = _read(path)
    packages: list[Package] = []
    for item in data.get("package") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        version = str(item.get("version", "")).strip()
        if not name or not version:
            continue
        line = locate_line(text, f'name = "{name}"')
        packages.append(Package(ecosystem, name, version, str(path), line, "runtime", True, "alta"))
    return packages


def parse_poetry_lock(path: Path) -> list[Package]:
    return _toml_packages(path, "pypi")


def parse_cargo_lock(path: Path) -> list[Package]:
    return _toml_packages(path, "crates")


def parse_pipfile_lock(path: Path) -> list[Package]:
    text = _read(path)
    data = json.loads(text)
    packages: list[Package] = []
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, info in block.items():
            version = ""
            if isinstance(info, dict):
                version = str(info.get("version", "")).strip()
            version = version.lstrip("=")
            if not version:
                continue
            line = locate_line(text, f'"{name}"')
            packages.append(Package("pypi", canonical_pypi(str(name)), version, str(path),
                                    line, scope, True, "alta"))
    return packages


def parse_go_sum(path: Path) -> list[Package]:
    seen: set[tuple[str, str]] = set()
    packages: list[Package] = []
    for number, raw in enumerate(_read(path).splitlines(), 1):
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if module.endswith("/go.mod"):
            module = module[: -len("/go.mod")]
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        key = (module, version)
        if key in seen:
            continue
        seen.add(key)
        packages.append(Package("go", module, version, str(path), number, "runtime", True, "alta"))
    return packages


_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.@+-]+) \(([^)]+)\)\s*$")
_GEM_PLATFORM = re.compile(
    r"^(?P<version>\d[^-]*)-(?:x86_64|arm64|aarch64|universal|x64|java|"
    r"mingw32|mingw-ucrt|mswin32|mswin64|ruby|linux|darwin|windows)[\w.-]*$"
)


def parse_gemfile_lock(path: Path) -> list[Package]:
    packages: list[Package] = []
    in_specs = False
    for number, raw in enumerate(_read(path).splitlines(), 1):
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and raw and not raw.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = _GEM_SPEC.match(raw)
        if match:
            version = match.group(2)
            platform = _GEM_PLATFORM.match(version)
            if platform:
                version = platform.group("version")
            packages.append(Package("rubygems", match.group(1), version,
                                    str(path), number, "runtime", True, "alta"))
    return packages


def parse_gradle_lockfile(path: Path) -> list[Package]:
    packages: list[Package] = []
    for number, raw in enumerate(_read(path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) < 3:
            continue
        packages.append(Package("maven", f"{parts[0]}:{parts[1]}", parts[2],
                                str(path), number, "runtime", True, "alta"))
    return packages


def parse_pom(path: Path) -> list[Package]:
    text = _read(path)
    root = ET.fromstring(text)
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"

    def strip(tag: str) -> str:
        return tag[len(namespace):] if namespace and tag.startswith(namespace) else tag

    def children(node: ET.Element, name: str) -> list[ET.Element]:
        return [child for child in list(node) if strip(child.tag) == name]

    properties: dict[str, str] = {}
    for node in root.iter():
        if strip(node.tag) == "properties":
            for child in list(node):
                properties[strip(child.tag)] = (child.text or "").strip()

    def resolve(value: str) -> str:
        match = re.fullmatch(r"\$\{([^}]+)\}", value.strip())
        if match:
            return properties.get(match.group(1), value.strip())
        return value.strip()

    def fields_of(node: ET.Element) -> dict[str, str]:
        return {strip(child.tag): (child.text or "").strip() for child in list(node)}

    # Versões geridas (dependencyManagement/BOM) não são dependências por si só:
    # usá-las como inventário geraria falso positivo. Servem só para resolver
    # a versão de uma dependência declarada sem <version>.
    managed: dict[tuple[str, str], str] = {}
    for node in root.iter():
        if strip(node.tag) != "dependencyManagement":
            continue
        for block in children(node, "dependencies"):
            for dep in children(block, "dependency"):
                fields = fields_of(dep)
                group = resolve(fields.get("groupId", ""))
                artifact = resolve(fields.get("artifactId", ""))
                version = resolve(fields.get("version", ""))
                if group and artifact and version and not version.startswith("$"):
                    managed[(group, artifact)] = version

    # Apenas <dependencies> do projeto e de perfis. Plugin e build não são
    # dependências de runtime da aplicação.
    containers: list[ET.Element] = [root]
    for profiles in children(root, "profiles"):
        containers.extend(children(profiles, "profile"))

    packages: list[Package] = []
    for container in containers:
        for block in children(container, "dependencies"):
            for dep in children(block, "dependency"):
                fields = fields_of(dep)
                group = resolve(fields.get("groupId", ""))
                artifact = resolve(fields.get("artifactId", ""))
                version = resolve(fields.get("version", ""))
                if not group or not artifact:
                    continue
                if not version:
                    version = managed.get((group, artifact), "")
                name = f"{group}:{artifact}"
                line = locate_line(text, artifact)
                pinned = bool(version) and not version.startswith("$")
                packages.append(Package("maven", name, version or "*", str(path), line,
                                        "runtime", pinned, "alta" if pinned else "baixa"))
    return packages


def parse_nuget_lock(path: Path) -> list[Package]:
    text = _read(path)
    data = json.loads(text)
    packages: list[Package] = []
    for framework, block in (data.get("dependencies") or {}).items():
        if not isinstance(block, dict):
            continue
        for name, info in block.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("resolved") or "")
            if not version:
                continue
            scope = "dev" if str(info.get("type", "")).lower() == "transitive" else "runtime"
            line = locate_line(text, f'"{name}"')
            packages.append(Package("nuget", str(name), version, str(path), line,
                                    scope, True, "alta"))
    return packages


_DOCKER_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE)


def parse_dockerfile(path: Path) -> list[Package]:
    images: list[Package] = []
    for number, raw in enumerate(_read(path).splitlines(), 1):
        match = _DOCKER_FROM.match(raw)
        if not match:
            continue
        image = match.group(1)
        if image.lower() == "scratch":
            continue
        digest = ""
        if "@" in image:
            image, _, digest = image.partition("@")
        # registry com porta (registry:5000/app) não tem tag
        head, separator, tail = image.rpartition(":")
        if separator and "/" not in tail:
            name, version = head, tail
        else:
            name, version = image, "latest"
        if digest:
            images.append(Package("docker", name, f"{version}@{digest}", str(path),
                                  number, "runtime", True, "media"))
        else:
            images.append(Package("docker", name, version, str(path), number,
                                  "runtime", version != "latest", "baixa"))
    return images


PARSERS: dict[str, tuple[str, Callable[[Path], list[Package]]]] = {
    "composer.lock": ("composer.lock", parse_composer_lock),
    "composer.json": ("composer.json", parse_composer_json),
    "package-lock.json": ("package-lock.json", parse_package_lock),
    "npm-shrinkwrap.json": ("package-lock.json", parse_package_lock),
    "yarn.lock": ("yarn.lock", parse_yarn_lock),
    "pnpm-lock.yaml": ("pnpm-lock.yaml", parse_pnpm_lock),
    "requirements.txt": ("requirements.txt", parse_requirements),
    "constraints.txt": ("requirements.txt", parse_requirements),
    "poetry.lock": ("poetry.lock", parse_poetry_lock),
    "Pipfile.lock": ("Pipfile.lock", parse_pipfile_lock),
    "go.sum": ("go.sum", parse_go_sum),
    "Cargo.lock": ("Cargo.lock", parse_cargo_lock),
    "Gemfile.lock": ("Gemfile.lock", parse_gemfile_lock),
    "gradle.lockfile": ("gradle.lockfile", parse_gradle_lockfile),
    "pom.xml": ("pom.xml", parse_pom),
    "packages.lock.json": ("packages.lock.json", parse_nuget_lock),
    "Dockerfile": ("Dockerfile", parse_dockerfile),
}


def discover(root: Path, extra_ignore: Sequence[str], max_files: int) -> list[Path]:
    found: list[Path] = []
    ignore = set(extra_ignore)
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE_DIRS and d not in ignore
                         and not d.startswith(".git"))
        for name in sorted(files):
            candidate = name
            if candidate in PARSERS or (candidate.startswith("Dockerfile")
                                        and candidate not in PARSERS):
                found.append(Path(current) / candidate)
                if len(found) >= max_files:
                    return found
    return found


def build_inventory(root: Path, paths: Iterable[Path]) -> Inventory:
    inventory = Inventory()
    seen: set[tuple[str, str, str, str]] = set()
    for path in paths:
        parser_entry = PARSERS.get(path.name)
        if parser_entry is None and path.name.startswith("Dockerfile"):
            parser_entry = ("Dockerfile", parse_dockerfile)
        if parser_entry is None:
            continue
        fmt, parser = parser_entry
        display = _display(path, root)
        try:
            packages = parser(path)
        except Exception as exc:  # parser incompleto = cobertura declarada
            inventory.manifests.append(Manifest(display, fmt, False,
                                                reason=f"{type(exc).__name__}: {exc}"))
            continue
        if fmt == "Dockerfile":
            inventory.docker_images.extend(packages)
            inventory.manifests.append(Manifest(display, fmt, True, len(packages)))
            continue
        for package in packages:
            package = Package(package.ecosystem, package.name, package.version,
                              display, package.line, package.scope,
                              package.pinned, package.confidence)
            identity = (package.ecosystem, package.name.lower(),
                        package.version, package.source)
            if identity in seen:
                continue
            seen.add(identity)
            inventory.add(package)
        inventory.manifests.append(Manifest(display, fmt, True, len(packages)))
    return inventory


def _display(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def os_packages() -> list[Package]:
    """Pacotes da distro, somente leitura. Best-effort: cobertura varia."""
    packages: list[Package] = []
    if shutil.which("dpkg-query"):
        try:
            out = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            out = ""
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 3 or "installed" not in parts[2]:
                continue
            packages.append(Package("debian" if _distro_id() != "ubuntu" else "ubuntu",
                                    parts[0], parts[1], "dpkg-query", 0,
                                    "runtime", True, "media"))
        return packages
    if shutil.which("rpm"):
        try:
            out = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout
        except (subprocess.SubprocessError, OSError):
            out = ""
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            packages.append(Package("rpm", parts[0], parts[1], "rpm -qa", 0,
                                    "runtime", True, "baixa"))
    return packages


def _distro_id() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass
    return ""


def _distro_version() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("VERSION_ID="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def osv_ecosystem(package: Package) -> str | None:
    base = OSV_ECOSYSTEM.get(package.ecosystem)
    if base is None:
        return None
    if package.ecosystem in {"debian", "ubuntu", "alpine"}:
        version = _distro_version()
        if not version:
            return None
        if package.ecosystem == "ubuntu":
            return f"Ubuntu:{version}:LTS"
        if package.ecosystem == "alpine":
            return f"Alpine:v{version}"
        return f"Debian:{version.split('.')[0]}"
    return base


# ---------------------------------------------------------------- CVSS


def cvss_v3_base_score(vector: str) -> float | None:
    """Calcula o base score de CVSS v3.0/3.1 a partir do vetor.

    Implementado para não depender de serviço externo na hora de classificar:
    OSV entrega o vetor, não o número.
    """
    if not vector.startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    scope_changed = metrics.get("S") == "C"
    if None in (av, ac, ui):
        return None

    pr_map = {
        False: {"N": 0.85, "L": 0.62, "H": 0.27},
        True: {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    pr = pr_map[scope_changed].get(metrics.get("PR", ""))
    if pr is None:
        return None

    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    try:
        c, i, a = cia[metrics["C"]], cia[metrics["I"]], cia[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    import math
    return math.ceil(round(raw * 10, 6)) / 10


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critico"
    if score >= 7.0:
        return "alto"
    if score >= 4.0:
        return "medio"
    return "baixo"


# ---------------------------------------------------------------- fontes


def osv_payload(packages: list[Package]) -> tuple[list[dict[str, Any]], list[Package]]:
    """Monta as queries do OSV e mantém o índice pacote↔resultado."""
    queries: list[dict[str, Any]] = []
    index: list[Package] = []
    for package in packages:
        ecosystem = osv_ecosystem(package)
        if ecosystem is None:
            continue
        queries.append({"package": {"name": package.name, "ecosystem": ecosystem},
                        "version": package.version})
        index.append(package)
    return queries, index


def osv_cache_url(payload: dict[str, Any]) -> str:
    """Chave de cache do POST: URL + hash do corpo."""
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    return f"{OSV_BATCH_URL}#{digest}"


def epss_cache_url(cve_ids: Sequence[str]) -> str:
    return f"{EPSS_URL}?cve={','.join(urllib.parse.quote(c) for c in cve_ids)}"


def nvd_cache_url(cve_id: str) -> str:
    return f"{NVD_CVE_URL}?cveId={urllib.parse.quote(cve_id)}"


def osv_query(packages: list[Package], *, cache_dir: Path, offline: bool,
              refresh: bool) -> tuple[list[dict[str, Any]], SourceMeta, list[Package]]:
    queries, index = osv_payload(packages)

    bodies: list[dict[str, Any]] = []
    meta = SourceMeta(name="OSV.dev", url=OSV_BATCH_URL)
    chunk = 200
    for start in range(0, len(queries), chunk):
        payload = {"queries": queries[start:start + chunk]}
        body = _post_json(OSV_BATCH_URL, payload,
                          cache_url=osv_cache_url(payload),
                          cache_dir=cache_dir, ttl=TTL_OSV,
                          offline=offline, refresh=refresh)
        bodies.extend(body.get("results") or [])
        meta.retrieved_at = body.get("_gaara_retrieved_at", meta.retrieved_at)
        if body.get("_gaara_stale"):
            meta.stale = True
    return bodies, meta, index


def _post_json(url: str, payload: dict[str, Any], *, cache_url: str,
               cache_dir: Path, ttl: timedelta, offline: bool,
               refresh: bool) -> dict[str, Any]:
    """POST com cache pela URL + body (OSV aceita GET só para query simples)."""
    key_dir = cache_dir / "osv"
    now = utcnow()
    if not refresh:
        cached = cache_load(key_dir, cache_url, ttl, now)
        if cached is not None:
            body, fetched_at, stale = cached
            if offline or not stale:
                body = dict(body)
                body["_gaara_retrieved_at"] = iso(fetched_at)
                body["_gaara_stale"] = stale
                return body
    if offline:
        cached = cache_load(key_dir, cache_url, ttl, now)
        if cached is None:
            raise SourceError(f"offline: sem cache para {url}")
        body, fetched_at, _ = cached
        body = dict(body)
        body["_gaara_retrieved_at"] = iso(fetched_at)
        body["_gaara_stale"] = True
        return body

    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout,
            OSError, json.JSONDecodeError) as exc:  # pragma: no cover - rede
        raise SourceError(f"falha ao consultar {url}: {exc}") from exc
    cache_store(key_dir, cache_url, body, now)
    body["_gaara_retrieved_at"] = iso(now)
    body["_gaara_stale"] = False
    return body


def kev_ids(*, cache_dir: Path, offline: bool, refresh: bool) -> tuple[set[str], SourceMeta]:
    body, meta = http_json(KEV_URL, cache_dir=cache_dir / "kev", ttl=TTL_KEV,
                           offline=offline, refresh=refresh)
    meta.name = "CISA KEV"
    ids = {str(item.get("cveID")) for item in body.get("vulnerabilities") or []}
    return ids, meta


def epss_scores(cve_ids: Sequence[str], *, cache_dir: Path, offline: bool,
                refresh: bool) -> tuple[dict[str, float], SourceMeta]:
    scores: dict[str, float] = {}
    meta = SourceMeta(name="EPSS (FIRST)", url=EPSS_URL)
    unique = sorted(set(cve_ids))
    for start in range(0, len(unique), 100):
        chunk = unique[start:start + 100]
        url = epss_cache_url(chunk)
        body, source = http_json(url, cache_dir=cache_dir / "epss", ttl=TTL_EPSS,
                                 offline=offline, refresh=refresh)
        meta.retrieved_at = source.retrieved_at
        meta.stale = meta.stale or source.stale
        for item in body.get("data") or []:
            try:
                scores[str(item["cve"])] = float(item["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    return scores, meta


def nvd_lookup(cve_id: str, *, cache_dir: Path, offline: bool, refresh: bool,
               api_key: str | None) -> tuple[dict[str, Any] | None, SourceMeta]:
    url = nvd_cache_url(cve_id)
    headers = {"apiKey": api_key} if api_key else None
    body, meta = http_json(url, cache_dir=cache_dir / "nvd", ttl=TTL_NVD,
                           offline=offline, refresh=refresh, headers=headers)
    meta.name = "NVD"
    items = body.get("vulnerabilities") or []
    if not items:
        return None, meta
    return items[0].get("cve") or None, meta


def nvd_metrics(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score), str(data.get("vectorString") or "")
    return None, None


# ---------------------------------------------------------------- correlação


def _same_package(ours: str, theirs: str) -> bool:
    """Compara nome do inventário com o nome usado pelo advisory.

    Maven usa `group:artifact` no inventário e `artifact` no OSV; Composer e Go
    usam o nome completo. Comparação por igualdade ou sufixo separado por `:`/`/`.
    """
    a, b = ours.lower(), theirs.lower()
    if not b:
        return False
    return a == b or a.endswith(":" + b) or a.endswith("/" + b)


def extract_fixed(affected: dict[str, Any]) -> str | None:
    fixed: list[str] = []
    for item in affected.get("ranges") or []:
        for event in item.get("events") or []:
            value = event.get("fixed")
            if value:
                fixed.append(str(value))
    return max(fixed) if fixed else None


def parse_osv_vuln(vuln: dict[str, Any], package: Package) -> Hit:
    aliases = [str(a) for a in vuln.get("aliases") or []]
    osv_id = str(vuln.get("id", ""))
    cve_id = next((a for a in aliases if a.upper().startswith("CVE-")), None)
    if cve_id is None and osv_id.upper().startswith("CVE-"):
        cve_id = osv_id

    cvss_score: float | None = None
    cvss_vector: str | None = None
    for entry in vuln.get("severity") or []:
        vector = str(entry.get("score") or "")
        score = cvss_v3_base_score(vector)
        if score is not None:
            cvss_score, cvss_vector = score, vector
            break

    label = None
    for block in ("database_specific", "ecosystem_specific"):
        data = vuln.get(block) or {}
        if isinstance(data, dict) and data.get("severity"):
            label = str(data["severity"]).upper()
            break

    fixed = None
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        name = str(affected.get("package", {}).get("name", ""))
        if not _same_package(package.name, name):
            continue
        fixed = extract_fixed(affected) or fixed

    references = [str(r.get("url")) for r in vuln.get("references") or []
                  if isinstance(r, dict) and r.get("url")]

    return Hit(
        package=package,
        osv_id=osv_id,
        cve_id=cve_id,
        summary=clean_text(str(vuln.get("summary") or vuln.get("details") or cve_id or osv_id), 220),
        fixed=fixed,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        cvss_source="OSV/CVSS" if cvss_score is not None else None,
        severity_label=label,
        published=str(vuln.get("published") or ""),
        references=references[:5],
        aliases=aliases,
    )


def hit_severity(hit: Hit, *, internet_exposed: bool, epss_threshold: float) -> tuple[str, list[str]]:
    rationale: list[str] = []
    if hit.cvss_score is not None:
        severity = cvss_to_severity(hit.cvss_score)
        rationale.append(f"CVSS {hit.cvss_score:.1f} ({hit.cvss_source})")
    elif hit.severity_label and hit.severity_label in LABEL_SEVERITY:
        severity = LABEL_SEVERITY[hit.severity_label]
        rationale.append(f"rótulo da fonte: {hit.severity_label}")
    else:
        severity = "medio"
        rationale.append("sem CVSS na fonte; severidade conservadora")

    if hit.kev and severity != "critico":
        severity = SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity) + 1, 3)]
        rationale.append("+1 nível: CISA KEV (explorado ativamente)")
    if (internet_exposed and hit.epss is not None and hit.epss >= epss_threshold
            and severity != "critico"):
        severity = SEVERITY_ORDER[min(SEVERITY_ORDER.index(severity) + 1, 3)]
        rationale.append(f"+1 nível: EPSS {hit.epss:.2f} com exposição à internet")
    return severity, rationale


def hit_confidence(hit: Hit) -> str:
    if hit.package.confidence == "baixa" or not hit.package.pinned:
        return "baixa"
    if hit.package.source in {"dpkg-query", "rpm -qa"}:
        return "media"
    return "alta"


def update_command(package: Package, fixed: str | None) -> str | None:
    target = fixed or "<versão corrigida>"
    if package.ecosystem == "packagist":
        return f"composer require {package.name}:{target} --with-all-dependencies"
    if package.ecosystem == "npm":
        return f"npm install {package.name}@{target}"
    if package.ecosystem == "pypi":
        return f"python3 -m pip install \"{package.name}>={target}\""
    if package.ecosystem == "go":
        return f"go get {package.name}@{target}"
    if package.ecosystem == "crates":
        return f"cargo update -p {package.name} --precise {target}"
    if package.ecosystem == "rubygems":
        return f"bundle update {package.name} --conservative"
    if package.ecosystem in {"debian", "ubuntu"}:
        return f"apt-get install --only-upgrade {package.name}"
    if package.ecosystem == "alpine":
        return f"apk add --upgrade {package.name}"
    if package.ecosystem == "rpm":
        return f"dnf upgrade {package.name}"
    return None


def hit_finding(hit: Hit, *, internet_exposed: bool, epss_threshold: float,
                retrieved_at: str | None) -> dict[str, Any]:
    severity, rationale = hit_severity(hit, internet_exposed=internet_exposed,
                                       epss_threshold=epss_threshold)
    package = hit.package
    fixed = hit.fixed
    command = update_command(package, fixed)
    rollback = (f"reverter {package.source} para {package.name} {package.version} "
                f"(git checkout -- {package.source})")
    identifier = hit.cve_id or hit.osv_id
    category = (f"cve/{hit.cve_id.lower()}" if hit.cve_id
                else "supply-chain/known-vulnerability")

    impact_parts = [hit.summary.rstrip(".") + "."]
    if fixed:
        impact_parts.append(f"Corrigido em {fixed}.")
    else:
        impact_parts.append("A fonte não informa versão corrigida.")
    if hit.kev:
        impact_parts.append("Exploração ativa confirmada no catálogo CISA KEV.")

    evidence = [{
        "source": f"OSV {hit.osv_id}",
        "locator": f"{package.source}:{package.line or 1}",
        "excerpt": clean_text(f"{package.name} {package.version} — {hit.summary}"),
        "redacted": True,
        "source_type": "api",
        "url": f"https://osv.dev/vulnerability/{hit.osv_id}",
        "retrieved_at": retrieved_at,
    }]
    if hit.references:
        evidence.append({
            "source": "advisory",
            "locator": identifier,
            "excerpt": clean_text(hit.references[0]),
            "redacted": True,
            "source_type": "advisory",
            "url": hit.references[0],
            "retrieved_at": retrieved_at,
        })

    observations: dict[str, Any] = {
        "package": package.name,
        "installed": package.version,
        "ecosystem": package.ecosystem,
        "fixed_versions": fixed,
        "cvss": hit.cvss_score,
        "cvss_vector": hit.cvss_vector,
        "kev": hit.kev,
        "epss": hit.epss,
        "published": hit.published or None,
        "severity_rationale": rationale,
        "aliases": hit.aliases[:5],
        "manifests": hit.manifests,
    }

    recommendation: dict[str, Any] = {
        "action": "patch",
        "target": f"{package.name}@{fixed or 'corrigido'}",
        "rollback": rollback,
        "requires_approval": True,
    }
    if command:
        recommendation["command"] = command

    return {
        "title": f"{identifier} em {package.name} {package.version}",
        "category": category,
        "severity": severity,
        "confidence": hit_confidence(hit),
        "frameworks": ["OWASP-A03:2025"],
        "evidence": evidence,
        "impact": " ".join(impact_parts),
        "recommendation": recommendation,
        "observations": observations,
        "false_positive_notes": (
            "OSV casa pacote+versão; se o lockfile não reflete o deploy, "
            "a versão em produção pode divergir."
        ),
        "not_observed": [] if fixed else ["a fonte não publicou versão corrigida"],
    }


def inventory_findings(inventory: Inventory, root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed = [m for m in inventory.manifests if not m.parsed]
    if failed:
        findings.append({
            "title": f"{len(failed)} manifest(s) não puderam ser lidos",
            "category": "supply-chain/inventory-gap",
            "severity": "medio",
            "confidence": "alta",
            "frameworks": ["OWASP-A03:2025"],
            "evidence": [{
                "source": m.path,
                "locator": m.fmt,
                "excerpt": clean_text(m.reason or "parser indisponível"),
                "redacted": True,
                "source_type": "code",
            } for m in failed[:3]],
            "impact": ("Dependências nesses arquivos não foram avaliadas. "
                       "Ausência de achado ali não significa ausência de risco."),
            "recommendation": {
                "action": "investigate",
                "command": "python3 scripts/deps_audit.py --list-parsers",
                "requires_approval": False,
            },
            "observations": {"manifests": [m.path for m in failed]},
            "not_observed": ["as dependências desses manifests ficaram fora da correlação"],
        })

    if not inventory.manifests:
        findings.append({
            "title": "Nenhum manifest de dependência encontrado",
            "category": "supply-chain/inventory-gap",
            "severity": "medio",
            "confidence": "alta",
            "evidence": [{
                "source": str(root),
                "locator": "varredura de manifests",
                "excerpt": "nenhum lockfile ou manifest reconhecido",
                "redacted": True,
                "source_type": "command",
            }],
            "impact": ("Sem inventário não é possível dizer se o projeto usa "
                       "componente vulnerável. A resposta correta é 'não avaliado'."),
            "recommendation": {"action": "investigate", "requires_approval": False},
            "not_observed": ["todas as dependências"],
        })

    if inventory.unpinned:
        total = len(inventory.unpinned)
        findings.append({
            "title": f"{total} dependência(s) sem versão resolvida",
            "category": "supply-chain/unpinned-dependency",
            "severity": "medio" if total >= 3 else "baixo",
            "confidence": "alta",
            "frameworks": ["OWASP-A03:2025"],
            "evidence": [{
                "source": p.source,
                "locator": f"linha {p.line}" if p.line else "manifest",
                "excerpt": clean_text(f"{p.name} {p.version}"),
                "redacted": True,
                "source_type": "code",
            } for p in inventory.unpinned[:3]],
            "impact": ("Sem versão resolvida não há correlação com CVE, e duas "
                       "instalações do mesmo commit podem divergir."),
            "recommendation": {
                "action": "investigate",
                "command": "gerar lockfile e commitar (composer install / npm install / pip-compile)",
                "requires_approval": False,
            },
            "observations": {"total": total},
            "not_observed": ["CVE dessas dependências"],
        })

    if inventory.docker_images:
        findings.append({
            "title": f"{len(inventory.docker_images)} imagem(ns) Docker sem varredura de camada",
            "category": "supply-chain/docker-base-image",
            "severity": "baixo",
            "confidence": "alta",
            "frameworks": ["OWASP-A03:2025"],
            "evidence": [{
                "source": image.source,
                "locator": f"linha {image.line}",
                "excerpt": clean_text(f"FROM {image.name}:{image.version}"),
                "redacted": True,
                "source_type": "code",
            } for image in inventory.docker_images[:3]],
            "impact": ("O sistema operacional da imagem não foi avaliado. "
                       "Pacotes dentro da imagem podem estar vulneráveis."),
            "recommendation": {
                "action": "investigate",
                "command": "trivy image --severity HIGH,CRITICAL <imagem>  # ferramenta externa, não incluída",
                "requires_approval": False,
            },
            "observations": {"images": [f"{i.name}:{i.version}" for i in inventory.docker_images]},
            "not_observed": ["CVE de pacotes dentro da imagem"],
        })
    return findings


# ---------------------------------------------------------------- resultado


def build_result(*, inventory: Inventory, hits: list[Hit], sources: list[SourceMeta],
                 root: Path, paths: list[Path], limits: dict[str, Any],
                 now: datetime, host: str, scan_id: str, queried: int,
                 skipped_ecosystems: list[str], not_evaluated: list[str],
                 internet_exposed: bool, epss_threshold: float,
                 max_findings: int, online: bool) -> dict[str, Any]:
    findings = inventory_findings(inventory, root)
    retrieved_at = next((s.retrieved_at for s in sources
                         if s.name.startswith("OSV") and s.retrieved_at), None)

    # Um achado por fato: mesmo pacote+versão+advisory vindo de dois manifests
    # (pom.xml e gradle.lockfile, por exemplo) é o mesmo risco, não dois.
    unique: dict[tuple[str, str, str, str], Hit] = {}
    for hit in hits:
        key = (hit.package.ecosystem, hit.package.name.lower(),
               hit.package.version, hit.osv_id)
        existing = unique.get(key)
        if existing is not None:
            if hit.package.source not in existing.manifests:
                existing.manifests.append(hit.package.source)
            continue
        hit.manifests = [hit.package.source]
        unique[key] = hit
    hits = list(unique.values())

    hits = sorted(hits, key=lambda h: (
        not h.kev,
        -(h.epss or 0.0),
        -(h.cvss_score or 0.0),
        h.package.name,
        h.osv_id,
    ))
    truncated = False
    for hit in hits:
        if len([f for f in findings if f["category"].startswith(("cve/", "supply-chain/known"))]) >= max_findings:
            truncated = True
            break
        findings.append(hit_finding(hit, internet_exposed=internet_exposed,
                                    epss_threshold=epss_threshold,
                                    retrieved_at=retrieved_at))

    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]],
                                 CONFIDENCE_RANK[f["confidence"]], f["title"]))
    for index, item in enumerate(findings, 1):
        item["id"] = f"F-{index:03d}"

    counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
    for item in findings:
        counts[item["severity"]] += 1

    verdict = "estavel" if not findings else "atencao"

    coverage = {
        "manifests_found": len(inventory.manifests),
        "manifests_parsed": sum(1 for m in inventory.manifests if m.parsed),
        "manifests_failed": sum(1 for m in inventory.manifests if not m.parsed),
        "dependencies": len(inventory.packages),
        "dependencies_unpinned": len(inventory.unpinned),
        "docker_images": len(inventory.docker_images),
        "queried": queried,
        "with_advisory": len({(h.package.name, h.osv_id) for h in hits}),
        "skipped_ecosystems": sorted(set(skipped_ecosystems)),
        "sources": [
            {
                "name": s.name,
                "url": s.url,
                "retrieved_at": s.retrieved_at,
                "stale": s.stale,
                "cached": s.cached,
                "error": s.error,
            }
            for s in sources
        ],
        "not_evaluated": not_evaluated,
    }

    not_observed: list[str] = []
    osv_source = next((s for s in sources if s.name.startswith("OSV")), None)
    if hits:
        not_observed.append("nenhuma exploração observada — este script não lê logs")
    elif not online:
        not_observed.append(
            "fontes externas não consultadas (--online não usado); "
            "este relatório é apenas inventário"
        )
    elif osv_source is not None and osv_source.error:
        not_observed.append(
            "não foi possível afirmar ausência de advisories: a consulta OSV falhou"
        )
    else:
        not_observed.append(
            "nenhum advisory retornado pelas fontes consultadas; isso não prova ausência de falha"
        )
    stale_sources = [s.name for s in sources if s.stale]
    if stale_sources:
        not_observed.append(
            "dados possivelmente desatualizados (cache vencido): "
            + ", ".join(sorted(set(stale_sources)))
        )
    if truncated:
        not_observed.append(f"lista de achados truncada em {max_findings}")
    if not inventory.packages:
        not_observed.append("inventário vazio: a correlação de CVE não foi executada")

    return {
        "schema_version": SCHEMA_VERSION,
        "scan": {
            "id": scan_id,
            "tool": TOOL,
            "host": host,
            "started_at": iso(now),
            "finished_at": iso(now),
            "window": {"from": iso(now), "to": iso(now)},
            "sources": [str(p) for p in paths],
            "limits": limits,
        },
        "findings": findings,
        "summary": {
            "verdict": verdict,
            "counts": counts,
            "correlations": [],
            "not_observed": not_observed,
            "coverage": coverage,
        },
    }


def validate(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("schema_version") not in {"1.0", "1.1"}:
        errors.append("schema_version não suportada")
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        return ["findings não é lista"]
    for item in findings:
        category = str(item.get("category", ""))
        if not (category in SUPPLY_CHAIN_CATEGORIES or CVE_CATEGORY_RE.match(category)):
            errors.append(f"{item.get('id')}: categoria fora da lista ({category})")
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
            if ev.get("source_type") in {"advisory", "api"}:
                if not ev.get("url"):
                    errors.append(f"{item.get('id')}: {ev.get('source_type')} sem url")
                if not ev.get("retrieved_at"):
                    errors.append(f"{item.get('id')}: {ev.get('source_type')} sem retrieved_at")
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
    coverage = result.get("summary", {}).get("coverage")
    if isinstance(coverage, dict):
        found = coverage.get("manifests_found")
        parsed = coverage.get("manifests_parsed")
        failed = coverage.get("manifests_failed")
        if None not in (found, parsed, failed) and parsed + failed != found:
            errors.append("coverage: manifests_parsed + manifests_failed != manifests_found")
    return errors


def render_markdown(result: dict[str, Any]) -> str:
    scan = result["scan"]
    summary = result["summary"]
    coverage = summary.get("coverage", {})
    lines = [
        f"# Vulnerabilidades conhecidas — {scan['host']}",
        "",
        f"**Veredito:** {summary['verdict']}",
        f"**Achados:** " + " · ".join(
            f"{SEVERITY_LABEL[k].lower()} {v}" for k, v in summary["counts"].items()),
        "",
        "## Cobertura",
        "",
        "| Item | Valor |",
        "|---|---|",
        f"| Manifests encontrados | {coverage.get('manifests_found', 0)} |",
        f"| Manifests lidos | {coverage.get('manifests_parsed', 0)} |",
        f"| Manifests com falha | {coverage.get('manifests_failed', 0)} |",
        f"| Dependências identificadas | {coverage.get('dependencies', 0)} |",
        f"| Sem versão resolvida | {coverage.get('dependencies_unpinned', 0)} |",
        f"| Consultadas nas fontes | {coverage.get('queried', 0)} |",
        f"| Com advisory | {coverage.get('with_advisory', 0)} |",
        "",
        "**Fontes consultadas:**",
        "",
    ]
    for source in coverage.get("sources") or []:
        state = "cache" if source.get("cached") else "consulta"
        if source.get("stale"):
            state += ", desatualizada"
        if source.get("error"):
            state += f", erro: {source['error']}"
        lines.append(f"- {source.get('name')} — {source.get('retrieved_at') or 'sem data'} ({state})")
    if not coverage.get("sources"):
        lines.append("- nenhuma: inventário offline")

    lines += ["", "## Achados", ""]
    if not result["findings"]:
        lines += ["Nenhuma vulnerabilidade conhecida nas fontes consultadas.", ""]
    for item in result["findings"]:
        lines += [
            f"### [{SEVERITY_LABEL[item['severity']]}] {item['title']} ({item['id']})",
            "",
            f"- **Categoria:** `{item['category']}`"
            + (f" · {', '.join(item.get('frameworks', []))}" if item.get("frameworks") else ""),
            f"- **Confiança:** {item['confidence']}",
            "- **Evidência:**",
        ]
        for ev in item["evidence"]:
            suffix = f" — {ev['url']}" if ev.get("url") else ""
            lines.append(f"  - `{ev['source']}` {ev['locator']}: `{ev['excerpt']}`{suffix}")
        lines.append(f"- **Impacto:** {item['impact']}")
        rec = item["recommendation"]
        lines.append(f"- **Recomendação:** {rec['action']}"
                     + (f" — `{rec['command']}`" if rec.get("command") else ""))
        if rec.get("rollback"):
            lines.append(f"- **Rollback:** {rec['rollback']}")
        rationale = item.get("observations", {}).get("severity_rationale")
        if rationale:
            lines.append(f"- **Severidade:** {'; '.join(rationale)}")
        if item.get("false_positive_notes"):
            lines.append(f"- **Falso positivo:** {item['false_positive_notes']}")
        for note in item.get("not_observed", []):
            lines.append(f"- **Não observado:** {note}")
        lines.append("")

    lines += ["## Não avaliado", ""]
    for note in coverage.get("not_evaluated") or ["nada declarado"]:
        lines.append(f"- {note}")
    if summary.get("not_observed"):
        lines += ["", "## Não observado", ""] + [f"- {n}" for n in summary["not_observed"]]
    lines += [
        "",
        "> Vulnerabilidade conhecida não é comprometimento. Exploração exige "
        "correlação com log (`log_triage.py`) e host (`harden_check.py`).",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="deps_audit.py",
        description="Inventário de dependências e correlação com vulnerabilidades conhecidas.",
        epilog="Somente leitura. Nenhum comando de atualização é executado.",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="diretórios ou arquivos do projeto (padrão: .)")
    parser.add_argument("--inventory", action="store_true",
                        help="somente inventário offline (padrão quando --online não é usado)")
    parser.add_argument("--online", action="store_true",
                        help="consultar OSV, KEV, EPSS e NVD")
    parser.add_argument("--offline", action="store_true",
                        help="com --online, usar apenas o cache local")
    parser.add_argument("--nvd", choices=("auto", "on", "off"), default="auto",
                        help="enriquecimento NVD (auto: só CVE sem CVSS, com limite)")
    parser.add_argument("--max-nvd", type=int, default=MAX_NVD_DEFAULT,
                        help=f"máximo de consultas NVD por execução (padrão: {MAX_NVD_DEFAULT})")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                        help="chave NVD (padrão: variável NVD_API_KEY)")
    parser.add_argument("--epss-threshold", type=float, default=EPSS_THRESHOLD_DEFAULT,
                        help=f"EPSS que escala severidade com --internet-exposed (padrão: {EPSS_THRESHOLD_DEFAULT})")
    parser.add_argument("--internet-exposed", action="store_true",
                        help="o projeto está exposto à internet (habilita escalada por EPSS)")
    parser.add_argument("--os-packages", action="store_true",
                        help="incluir pacotes da distro (dpkg/rpm), somente leitura")
    parser.add_argument("--include-dev", action="store_true",
                        help="incluir dependências de desenvolvimento")
    parser.add_argument("--max-findings", type=int, default=MAX_FINDINGS_DEFAULT,
                        help=f"teto de achados de CVE (padrão: {MAX_FINDINGS_DEFAULT})")
    parser.add_argument("--max-files", type=int, default=MAX_FILES,
                        help=f"teto de manifests visitados (padrão: {MAX_FILES})")
    parser.add_argument("--exclude", action="append", default=[],
                        help="diretório extra a ignorar (repetível)")
    parser.add_argument("--since", default=None,
                        help="considerar apenas advisories publicados nos últimos N (ex.: 30d)")
    parser.add_argument("--cache-dir", default=None,
                        help="diretório de cache (padrão: ~/.cache/gaara)")
    parser.add_argument("--refresh", action="store_true", help="ignorar cache e reconsultar")
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--output", default=None, help="arquivo de saída (padrão: stdout)")
    parser.add_argument("--list-parsers", action="store_true", help="listar formatos suportados")
    return parser.parse_args(argv)


def parse_since(value: str | None, now: datetime) -> datetime | None:
    if not value:
        return None
    match = re.fullmatch(r"(\d+)([dwmy])", value.strip())
    if not match:
        raise SystemExit("--since aceita N seguido de d ou w (ex.: 30d)")
    amount, unit = int(match.group(1)), match.group(2)
    days = {"d": amount, "w": amount * 7, "m": amount * 30, "y": amount * 365}[unit]
    return now - timedelta(days=days)


def list_parsers() -> str:
    lines = ["| Arquivo | Formato | Ecossistema |", "|---|---|---|"]
    ecosystem_of = {
        "composer": "Packagist", "package": "npm", "npm": "npm", "yarn": "npm",
        "pnpm": "npm", "requirements": "PyPI", "constraints": "PyPI",
        "poetry": "PyPI", "Pipfile": "PyPI", "go": "Go", "Cargo": "crates.io",
        "Gemfile": "RubyGems", "gradle": "Maven", "pom": "Maven",
        "packages.lock": "NuGet", "Dockerfile": "imagem (não avaliada)",
    }
    for name, (fmt, _parser) in sorted(PARSERS.items()):
        prefix = name.split(".")[0].split("-")[0]
        lines.append(f"| `{name}` | `{fmt}` | {ecosystem_of.get(prefix, '?')} |")
    lines += ["", "Formatos não listados entram como `supply-chain/inventory-gap`."]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_parsers:
        print(list_parsers())
        return 0
    if args.inventory:
        args.online = False

    root = Path(args.paths[0]).resolve() if args.paths else Path.cwd()
    if not root.exists():
        print(f"caminho inexistente: {root}", file=sys.stderr)
        return 2
    if root.is_file():
        root = root.parent

    now = utcnow()
    host = platform.node() or "local"
    suffix = hashlib.sha256(str(root).encode()).hexdigest()[:4]
    scan_id = f"gaara-{now.strftime('%Y%m%d')}-{suffix}"

    explicit = [Path(p).resolve() for p in args.paths if Path(p).is_file()]
    if explicit:
        files = explicit
    else:
        files = discover(root, args.exclude, args.max_files)

    inventory = build_inventory(root, files)
    if not args.include_dev:
        inventory.packages = [p for p in inventory.packages if p.scope != "dev"]

    if args.os_packages:
        for package in os_packages():
            inventory.add(package)

    sources: list[SourceMeta] = []
    not_evaluated: list[str] = [
        "OWASP A01 (controle de acesso) e A06 (design): exigem revisão humana rota a rota",
        "código-fonte fora de PHP: nenhum analisador estático nesta versão",
        "lógica de negócio, regras de autorização e segredos fora de manifest",
        "zero-day e falha ainda não publicada em OSV/NVD",
    ]
    if inventory.docker_images:
        not_evaluated.append("camadas da imagem Docker: sem scanner (Trivy/Grype) nesta versão")
    if any(p.ecosystem == "rpm" for p in inventory.packages):
        not_evaluated.append("pacotes RPM: cobertura de OSV é fraca; consultar advisory da distro")
    if any(p.ecosystem == "docker" for p in inventory.packages):
        not_evaluated.append("componentes dentro de imagens Docker")

    hits: list[Hit] = []
    queried = 0
    skipped: list[str] = []

    if args.online and inventory.packages:
        cache_dir = Path(args.cache_dir or os.path.expanduser("~/.cache/gaara"))
        try:
            osv_results, osv_meta, index = osv_query(
                inventory.packages, cache_dir=cache_dir,
                offline=args.offline, refresh=args.refresh,
            )
            sources.append(osv_meta)
        except SourceError as exc:
            osv_results, index = [], []
            sources.append(SourceMeta(name="OSV.dev", url=OSV_BATCH_URL, error=str(exc)))
            not_evaluated.append(f"OSV indisponível: {exc}")

        for package in inventory.packages:
            if not osv_ecosystem(package) and package.ecosystem not in skipped:
                skipped.append(package.ecosystem)

        for position, result in enumerate(osv_results):
            if position >= len(index):
                break
            for vuln in result.get("vulns") or []:
                hits.append(parse_osv_vuln(vuln, index[position]))
        queried = min(len(osv_results), len(index))

        since = parse_since(args.since, now)
        if since is not None:
            hits = [h for h in hits if _published_after(h, since)]

        cve_ids = [h.cve_id for h in hits if h.cve_id]

        try:
            kev, kev_meta = kev_ids(cache_dir=cache_dir, offline=args.offline,
                                    refresh=args.refresh)
            sources.append(kev_meta)
            for hit in hits:
                if hit.cve_id and hit.cve_id in kev:
                    hit.kev = True
        except SourceError as exc:
            sources.append(SourceMeta(name="CISA KEV", url=KEV_URL, error=str(exc)))
            not_evaluated.append(f"KEV indisponível: exploração ativa não verificada ({exc})")

        if cve_ids:
            try:
                scores, epss_meta = epss_scores(cve_ids, cache_dir=cache_dir,
                                                offline=args.offline, refresh=args.refresh)
                sources.append(epss_meta)
                for hit in hits:
                    if hit.cve_id:
                        hit.epss = scores.get(hit.cve_id)
            except SourceError as exc:
                sources.append(SourceMeta(name="EPSS (FIRST)", url=EPSS_URL, error=str(exc)))
                not_evaluated.append(f"EPSS indisponível: priorização não refinada ({exc})")

        if args.nvd != "off":
            nvd_meta = _enrich_nvd(hits, args, cache_dir, not_evaluated)
            if nvd_meta.retrieved_at or nvd_meta.error:
                sources.append(nvd_meta)

    limits = {
        "bytes_read": sum(p.stat().st_size for p in files if p.is_file()),
        "truncated": len(files) >= args.max_files,
        "manifests_visited": len(files),
        "max_findings": args.max_findings,
    }

    result = build_result(
        inventory=inventory, hits=hits, sources=sources, root=root,
        paths=files, limits=limits, now=now, host=host, scan_id=scan_id,
        queried=queried, skipped_ecosystems=skipped,
        not_evaluated=not_evaluated, internet_exposed=args.internet_exposed,
        epss_threshold=args.epss_threshold, max_findings=args.max_findings,
        online=args.online,
    )

    errors = validate(result)
    if errors:
        for message in errors:
            print(f"validação: {message}", file=sys.stderr)
        return 1

    output = render_markdown(result) if args.format == "md" else json.dumps(
        result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    counts = result["summary"]["counts"]
    return 3 if counts["alto"] or counts["critico"] else 0


def _published_after(hit: Hit, since: datetime) -> bool:
    if not hit.published:
        return True
    try:
        published = datetime.fromisoformat(hit.published.replace("Z", "+00:00"))
    except ValueError:
        return True
    return published >= since


def _enrich_nvd(hits: list[Hit], args: argparse.Namespace, cache_dir: Path,
                not_evaluated: list[str]) -> SourceMeta:
    candidates = [h for h in hits if h.cve_id and h.cvss_score is None]
    pending = len(candidates)
    if args.nvd == "auto":
        candidates = candidates[: max(0, args.max_nvd)]
    candidates = [h for h in candidates if h.cve_id]

    meta = SourceMeta(name="NVD", url=NVD_CVE_URL)
    seen: dict[str, tuple[float | None, str | None]] = {}
    delay = 0.7 if args.nvd_api_key else 6.0

    for index, hit in enumerate(candidates):
        assert hit.cve_id is not None
        if hit.cve_id in seen:
            score, vector = seen[hit.cve_id]
        else:
            try:
                data, source = nvd_lookup(hit.cve_id, cache_dir=cache_dir,
                                          offline=args.offline, refresh=args.refresh,
                                          api_key=args.nvd_api_key)
                meta.retrieved_at = source.retrieved_at
                meta.stale = meta.stale or source.stale
                if data is None:
                    score, vector = None, None
                else:
                    score, vector = nvd_metrics(data)
                seen[hit.cve_id] = (score, vector)
            except SourceError as exc:
                meta.error = str(exc)
                not_evaluated.append(f"NVD indisponível para {hit.cve_id}: {exc}")
                break
            if index < len(candidates) - 1:
                time.sleep(delay)
        if score is not None:
            hit.cvss_score = score
            hit.cvss_vector = vector
            hit.cvss_source = "NVD"
    if args.nvd == "auto" and pending > args.max_nvd:
        not_evaluated.append(
            f"NVD consultado para no máximo {args.max_nvd} de {pending} CVE(s) sem CVSS; "
            "o restante ficou com a severidade da fonte OSV"
        )
    return meta


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
