#!/usr/bin/env python3
"""Save an already-redacted Gaara log summary after explicit user consent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import stat
import sys
from datetime import datetime, timezone


def default_report_dir(env: dict[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    state_home = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(state_home).expanduser() / "gaara" / "reports"


def save_report(markdown: str, report_dir: Path, *, now: datetime | None = None) -> Path:
    if not markdown.strip():
        raise ValueError("o relatório Markdown está vazio")
    if "\x00" in markdown:
        raise ValueError("o relatório contém caractere NUL")

    report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = report_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PermissionError("a pasta de relatórios precisa ser um diretório do usuário atual")
    report_dir.chmod(0o700)

    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    prefix = "gaara-log-report-" + stamp.strftime("%Y%m%dT%H%M%SZ")
    payload = markdown.rstrip() + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    for _ in range(10):
        destination = report_dir / f"{prefix}-{secrets.token_hex(4)}.md"
        try:
            fd = os.open(destination, flags, 0o600)
        except FileExistsError:
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return destination
    raise FileExistsError("não foi possível reservar um nome exclusivo para o relatório")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Salva um resumo Markdown de logs após consentimento explícito."
    )
    parser.add_argument(
        "--confirmed", action="store_true",
        help="confirma que a pessoa autorizou salvar este resumo redigido",
    )
    args = parser.parse_args(argv)
    if not args.confirmed:
        parser.error("salvamento requer --confirmed após consentimento explícito")

    try:
        destination = save_report(sys.stdin.read(), default_report_dir())
    except (OSError, ValueError) as exc:
        print(f"erro ao salvar relatório: {exc}", file=sys.stderr)
        return 1
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
