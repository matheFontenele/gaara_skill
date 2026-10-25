"""Testes do guardião de Fail2ban (f2b_guard.py).

Cobrem o critério de aceitação do Lote 5:
- detecção (log_triage.py) → ban → unban de ponta a ponta;
- allowlist, IP do operador, sessão SSH e jail inválido recusados;
- dry-run é o padrão e não grava estado nem auditoria;
- TTL por severidade, teto de 72 h e sweep de vencidos;
- auditoria append-only 0600, com intenção + resultado e segredos redigidos;
- cliente falso: o Fail2ban real do host nunca é tocado.

Executar:
    python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "f2b_guard.py"
LOG_TRIAGE = ROOT / "scripts" / "log_triage.py"
EXAMPLE = ROOT / "assets" / "config.example.json"
AUTH_SAMPLE = ROOT / "tests" / "corpus" / "auth-sample.log"
NOW = "2026-10-24T23:00:00Z"

FAKE_CLIENT = r'''#!/usr/bin/env python3
import json
import os
import sys

state_path = os.environ["F2B_STATE"]
log_path = os.environ.get("F2B_LOG")
argv = sys.argv[1:]
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\n")
if argv[:1] == ["-s"]:
    argv = argv[2:]
try:
    with open(state_path, encoding="utf-8") as handle:
        state = json.load(handle)
except Exception:
    state = {}
if not argv:
    sys.exit(255)
command = argv[0]
if command == "status":
    jail = argv[1]
    if os.environ.get("F2B_FAIL_STATUS"):
        print("falha simulada de status", file=sys.stderr)
        sys.exit(255)
    if jail not in state:
        print("Sorry but the jail '%s' does not exist" % jail, file=sys.stderr)
        sys.exit(255)
    ips = state[jail]
    count = len(ips) + (1 if os.environ.get("F2B_BAD_COUNT") else 0)
    print("Status for the jail: %s" % jail)
    print("|- Filter")
    print("|  |- Currently failed: 0")
    print("|  `- File list: /var/log/auth.log")
    print("`- Actions")
    print("   |- Currently banned: %d" % count)
    print("   |- Total banned: %d" % count)
    print("   `- Banned IP list:\t%s" % " ".join(ips))
elif command == "set":
    jail, action, ip = argv[1], argv[2], argv[3]
    if jail not in state:
        print("jail not found", file=sys.stderr)
        sys.exit(255)
    if action == "banip":
        if os.environ.get("F2B_FAIL_BAN"):
            print("falha simulada de ban", file=sys.stderr)
            sys.exit(255)
        if os.environ.get("F2B_NOOP_BAN"):
            print("OK")
            sys.exit(0)
        if ip in state[jail]:
            print("already banned", file=sys.stderr)
            sys.exit(255)
        state[jail].append(ip)
    elif action == "unbanip":
        if os.environ.get("F2B_FAIL_UNBAN"):
            print("falha simulada de unban", file=sys.stderr)
            sys.exit(255)
        if ip not in state[jail]:
            print("not banned", file=sys.stderr)
            sys.exit(255)
        state[jail].remove(ip)
    else:
        sys.exit(255)
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    print("OK")
else:
    sys.exit(255)
'''


class F2bGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gaara-f2b-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.fake = self.tmp / "fail2ban-client"
        self.fake.write_text(FAKE_CLIENT, encoding="utf-8")
        self.fake.chmod(0o755)
        self.state_path = self.tmp / "state.json"
        self.calls_path = self.tmp / "calls.jsonl"
        self.audit_path = self.tmp / "audit.jsonl"
        self.socket_path = self.tmp / "fail2ban.sock"
        self.config_path = self.tmp / "config.json"
        self.set_state(sshd=[], **{"nginx-http-auth": []})
        self.write_config()

    # ------------------------------------------------------------ helpers

    def write_config(self, **overrides) -> None:
        config = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        config.update({"client": str(self.fake), "audit_path": str(self.audit_path)})
        config.update(overrides)
        self.config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

    def set_state(self, **jails) -> None:
        self.state_path.write_text(json.dumps(jails), encoding="utf-8")

    def state(self) -> dict[str, list[str]]:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def calls(self) -> list[list[str]]:
        if not self.calls_path.exists():
            return []
        return [json.loads(line) for line in self.calls_path.read_text(encoding="utf-8").splitlines() if line]

    def mutations(self) -> list[list[str]]:
        result: list[list[str]] = []
        for call in self.calls():
            if "set" in call:
                result.append(call[call.index("set"):])
        return result

    def audit(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]

    def f2b(
        self,
        *args: str,
        fmt: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(SCRIPT), "--config", str(self.config_path)]
        if fmt:
            command += ["--format", fmt]
        command += list(args)
        run_env = os.environ.copy()
        run_env.pop("SSH_CONNECTION", None)
        run_env.pop("SSH_CLIENT", None)
        run_env.update({"F2B_STATE": str(self.state_path), "F2B_LOG": str(self.calls_path)})
        if env:
            run_env.update(env)
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout, env=run_env)

    def ban_args(
        self,
        ip: str,
        *,
        severity: str = "alto",
        confidence: str = "alta",
        ttl: str | None = None,
        execute: bool = False,
        approved: str | None = "teste",
        correlation: str | None = None,
        now: str = NOW,
    ) -> list[str]:
        args = [
            "--now", now, "ban",
            "--ip", ip,
            "--jail", "sshd",
            "--severity", severity,
            "--confidence", confidence,
            "--reason", "312 falhas SSH em 31 min",
            "--evidence", "auth.log:1234-1560",
        ]
        if ttl is not None:
            args += ["--ttl", ttl]
        if correlation:
            args += ["--correlation-id", correlation]
        if execute:
            args += ["--execute"]
            if approved is not None:
                args += ["--approved-by", approved]
        return args

    def unban_args(
        self,
        ip: str,
        *,
        execute: bool = False,
        approved: str | None = "teste",
        now: str = NOW,
    ) -> list[str]:
        args = [
            "--now", now, "unban",
            "--ip", ip,
            "--jail", "sshd",
            "--reason", "falso positivo",
        ]
        if execute:
            args += ["--execute"]
            if approved is not None:
                args += ["--approved-by", approved]
        return args

    def sweep_args(
        self,
        *,
        execute: bool = False,
        approved: str | None = "teste",
        limit: int | None = None,
        now: str = NOW,
    ) -> list[str]:
        args = ["--now", now, "sweep"]
        if limit is not None:
            args += ["--limit", str(limit)]
        if execute:
            args += ["--execute"]
            if approved is not None:
                args += ["--approved-by", approved]
        return args

    def ban(self, ip: str, **kwargs) -> subprocess.CompletedProcess[str]:
        return self.f2b(*self.ban_args(ip, execute=True, **kwargs))

    # ------------------------------------------------------------- check

    def test_check_lists_banned_and_uses_exact_ip_match(self) -> None:
        self.set_state(sshd=["203.0.113.45"], **{"nginx-http-auth": []})
        result = json.loads(self.f2b("--now", NOW, "check", "--jail", "sshd", "--ip", "203.0.113.4", fmt="json").stdout)
        self.assertFalse(result["ip_banned"])
        self.assertIn("203.0.113.45", result["banned"])
        self.assertEqual(result["currently_banned"], 1)

        result = json.loads(self.f2b("--now", NOW, "check", "--jail", "sshd", "--ip", "203.0.113.45", fmt="json").stdout)
        self.assertTrue(result["ip_banned"])

    def test_check_blocks_allowlisted_ip(self) -> None:
        result = self.f2b("--now", NOW, "check", "--jail", "sshd", "--ip", "127.0.0.1", fmt="json")
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["policy"]["allowed"], "false")

    def test_check_rejects_invalid_jail_and_reports_client_failure(self) -> None:
        self.assertEqual(self.f2b("--now", NOW, "check", "--jail", "nao-existe").returncode, 2)
        failure = self.f2b("--now", NOW, "check", "--jail", "sshd", env={"F2B_FAIL_STATUS": "1"}, fmt="json")
        self.assertEqual(failure.returncode, 1)
        self.assertEqual(json.loads(failure.stdout)["status"], "error")

        inconsistent = self.f2b(
            "--now", NOW, "check", "--jail", "sshd", env={"F2B_BAD_COUNT": "1"}, fmt="json"
        )
        self.assertEqual(inconsistent.returncode, 1)
        self.assertEqual(json.loads(inconsistent.stdout)["status"], "error")

    # --------------------------------------------------------------- ban

    def test_dry_run_is_default_and_never_mutates(self) -> None:
        result = self.f2b(*self.ban_args("203.0.113.45"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.audit_path.exists())
        self.assertIn("SIMULAÇÃO", result.stdout)
        self.assertIn("203.0.113.45", result.stdout)

        report = json.loads(self.f2b(*self.ban_args("203.0.113.45"), fmt="json").stdout)
        self.assertEqual(report["status"], "planned")
        self.assertEqual(report["ttl"], 86400)
        self.assertIn("banip", report["command"])
        self.assertIn("unbanip", report["rollback"])

    def test_execute_requires_approved_by(self) -> None:
        result = self.f2b(*self.ban_args("203.0.113.45", execute=True, approved=None))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.audit_path.exists())

    def test_ban_execute_changes_state_and_writes_audit(self) -> None:
        result = self.ban("203.0.113.45", correlation="gaara-test-ban")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["sshd"], ["203.0.113.45"])
        self.assertEqual(self.mutations(), [["set", "sshd", "banip", "203.0.113.45"]])
        self.assertEqual(stat.S_IMODE(self.audit_path.stat().st_mode), 0o600)

        records = self.audit()
        self.assertEqual([record["phase"] for record in records], ["intent", "result"])
        self.assertEqual(records[1]["result"], "ok")
        self.assertEqual(records[1]["correlation_id"], "gaara-test-ban")
        self.assertEqual(records[1]["expires_at"], "2026-10-25T23:00:00Z")
        self.assertTrue(records[1]["verified_banned"])

    def test_already_banned_is_refused_without_action(self) -> None:
        self.set_state(sshd=["203.0.113.45"], **{"nginx-http-auth": []})
        result = self.ban("203.0.113.45")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.audit_path.exists())
        self.assertIn("já estava banido", result.stdout)
        self.assertNotIn("unbanip", result.stdout)

    def test_allowlist_loopback_private_and_special_ranges_are_refused(self) -> None:
        for ip in (
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.10",
            "169.254.169.254", "100.64.0.1", "224.0.0.1",
            "::1", "fc00::1", "fe80::1",
        ):
            with self.subTest(ip=ip):
                result = self.f2b(*self.ban_args(ip))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("allowlist", result.stderr)
        self.assertFalse(self.audit_path.exists())

    def test_operator_protected_and_ssh_session_are_refused(self) -> None:
        self.write_config(operator_ips=["198.51.100.7"], protected_ips=["192.0.2.10"])
        self.assertEqual(self.f2b(*self.ban_args("198.51.100.7")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("192.0.2.10")).returncode, 2)
        ssh = self.f2b(
            *self.ban_args("198.51.100.50"),
            env={"SSH_CONNECTION": "198.51.100.50 50000 192.0.2.1 22"},
        )
        self.assertEqual(ssh.returncode, 2)
        self.assertIn("sessão SSH", ssh.stderr)
        self.assertEqual(self.mutations(), [])

    def test_invalid_ip_cidr_and_jail_are_refused(self) -> None:
        for ip in ("203.0.113.0/24", "nao-e-ip", "203.0.113.999", "::ffff:127.0.0.1"):
            with self.subTest(ip=ip):
                self.assertEqual(self.f2b(*self.ban_args(ip)).returncode, 2)
        for jail in ("nao-existe", "../sshd", "sshd ruim"):
            with self.subTest(jail=jail):
                args = self.ban_args("203.0.113.45")
                args[args.index("--jail") + 1] = jail
                self.assertEqual(self.f2b(*args).returncode, 2)
        self.assertEqual(self.mutations(), [])

    def test_low_severity_and_low_confidence_are_refused(self) -> None:
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", severity="baixo")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", confidence="baixa")).returncode, 2)
        self.assertEqual(self.mutations(), [])

    def test_ttl_limits_and_critical_requires_explicit_ttl(self) -> None:
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", severity="medio", ttl="5h")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", severity="alto", ttl="73h")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", severity="critico")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", ttl="0")).returncode, 2)
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45", ttl="abc")).returncode, 2)

        critical = self.f2b(*self.ban_args("203.0.113.45", severity="critico", ttl="1h"), fmt="json")
        self.assertEqual(critical.returncode, 0, critical.stderr)
        self.assertEqual(json.loads(critical.stdout)["ttl"], 3600)
        medium = self.f2b(*self.ban_args("203.0.113.45", severity="medio", ttl="30m"), fmt="json")
        self.assertEqual(json.loads(medium.stdout)["ttl"], 1800)

    def test_client_failure_is_audited_and_leaves_state_unchanged(self) -> None:
        result = self.f2b(
            *self.ban_args("203.0.113.45", execute=True, correlation="gaara-fail"),
            env={"F2B_FAIL_BAN": "1"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()["sshd"], [])
        records = self.audit()
        self.assertEqual([record["phase"] for record in records], ["intent", "result"])
        self.assertEqual(records[1]["result"], "error")

    def test_success_without_verified_state_is_an_error(self) -> None:
        result = self.f2b(*self.ban_args("203.0.113.45", execute=True), env={"F2B_NOOP_BAN": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()["sshd"], [])
        self.assertEqual(self.audit()[1]["result"], "error")
        self.assertFalse(self.audit()[1]["verified_banned"])

    def test_secrets_are_redacted_even_in_audit(self) -> None:
        args = self.ban_args("203.0.113.45", execute=True)
        args[args.index("--reason") + 1] = "password=Hunter2 token=abc123"
        args[args.index("--evidence") + 1] = "admin@example.com authorization: Bearer abcdefghijkl"
        result = self.f2b(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = self.audit_path.read_text(encoding="utf-8") + result.stdout
        for secret in ("Hunter2", "abc123", "admin@example.com", "abcdefghijkl"):
            self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTADO]", rendered)
        self.assertIn("[EMAIL]", rendered)

    def test_socket_is_passed_without_shell(self) -> None:
        self.write_config(socket=str(self.socket_path))
        result = self.ban("203.0.113.45")
        self.assertEqual(result.returncode, 0, result.stderr)
        mutation = next(call for call in self.calls() if "set" in call)
        self.assertEqual(mutation[:3], ["-s", str(self.socket_path), "set"])

    # ------------------------------------------------------------- unban

    def test_unban_foreign_ban_is_refused(self) -> None:
        self.set_state(sshd=["198.51.100.99"], **{"nginx-http-auth": []})
        result = self.f2b(*self.unban_args("198.51.100.99", execute=True))
        self.assertEqual(result.returncode, 2)
        self.assertIn("não há ban ativo criado por esta ferramenta", result.stderr)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.state()["sshd"], ["198.51.100.99"])

    def test_unban_tool_owned_ban(self) -> None:
        self.assertEqual(self.ban("203.0.113.45", correlation="gaara-ban-1").returncode, 0)
        before = len(self.mutations())
        dry = self.f2b(*self.unban_args("203.0.113.45"), fmt="json")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(json.loads(dry.stdout)["ban_correlation_id"], "gaara-ban-1")
        self.assertEqual(len(self.mutations()), before)

        result = self.f2b(*self.unban_args("203.0.113.45", execute=True))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["sshd"], [])
        last = self.audit()[-1]
        self.assertEqual(last["action"], "unban")
        self.assertEqual(last["result"], "ok")
        self.assertEqual(last["ban_correlation_id"], "gaara-ban-1")

        again = self.f2b(*self.unban_args("203.0.113.45", execute=True))
        self.assertEqual(again.returncode, 2)

    def test_unban_when_not_banned_closes_the_audit_entry(self) -> None:
        self.assertEqual(self.ban("203.0.113.45").returncode, 0)
        self.set_state(sshd=[], **{"nginx-http-auth": []})
        result = self.f2b(*self.unban_args("203.0.113.45", execute=True))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("não estava banido", result.stdout)
        self.assertEqual(self.audit()[-1]["result"], "not_banned")
        sweep = self.f2b(*self.sweep_args(now="2026-10-26T23:00:00Z"), fmt="json")
        self.assertEqual(json.loads(sweep.stdout)["due_total"], 0)
        self.assertEqual(self.mutations()[-1], ["set", "sshd", "banip", "203.0.113.45"])

    def test_unban_requires_approval(self) -> None:
        self.assertEqual(self.ban("203.0.113.45").returncode, 0)
        result = self.f2b(*self.unban_args("203.0.113.45", execute=True, approved=None))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state()["sshd"], ["203.0.113.45"])

    # ------------------------------------------------------------- sweep

    def test_sweep_dry_run_lists_only_expired_tool_bans(self) -> None:
        self.set_state(sshd=["198.51.100.99"], **{"nginx-http-auth": []})
        self.assertEqual(self.ban("203.0.113.45", severity="medio", correlation="exp-1").returncode, 0)
        self.assertEqual(self.ban("203.0.113.46", severity="alto", now="2026-10-24T23:30:00Z", correlation="keep-1").returncode, 0)
        before = len(self.mutations())

        result = self.f2b(*self.sweep_args(now="2026-10-25T01:00:00Z"), fmt="json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["due_total"], 1)
        self.assertEqual([item["ip"] for item in report["due"]], ["203.0.113.45"])
        self.assertEqual(len(self.mutations()), before)

    def test_sweep_execute_unbans_expired_and_preserves_foreign(self) -> None:
        self.set_state(sshd=["198.51.100.99"], **{"nginx-http-auth": []})
        self.assertEqual(self.ban("203.0.113.45", severity="medio", correlation="exp-1").returncode, 0)
        self.assertEqual(self.ban("203.0.113.46", severity="alto", now="2026-10-24T23:30:00Z", correlation="keep-1").returncode, 0)

        result = self.f2b(*self.sweep_args(execute=True, now="2026-10-25T01:00:00Z"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["sshd"], ["198.51.100.99", "203.0.113.46"])
        last = self.audit()[-1]
        self.assertEqual(last["action"], "unban")
        self.assertEqual(last["result"], "ok")
        self.assertEqual(last["ban_correlation_id"], "exp-1")

    def test_sweep_still_unbans_after_jail_leaves_allowlist(self) -> None:
        self.assertEqual(self.ban("203.0.113.45", severity="medio", correlation="exp-1").returncode, 0)
        self.write_config(allowed_jails=["nginx-http-auth"])
        result = self.f2b(*self.sweep_args(execute=True, now="2026-10-25T01:00:00Z"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["sshd"], [])
        self.assertEqual(self.audit()[-1]["result"], "ok")

    def test_sweep_respects_limit_and_retries_next_run(self) -> None:
        for index, ip in enumerate(("203.0.113.51", "203.0.113.52", "203.0.113.53")):
            self.assertEqual(self.ban(ip, severity="medio", correlation=f"exp-{index}").returncode, 0)
        result = self.f2b(*self.sweep_args(execute=True, limit=1, now="2026-10-25T01:00:00Z"), fmt="json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["due_total"], 3)
        self.assertEqual(report["skipped"], 2)
        self.assertEqual(len(report["results"]), 1)
        self.assertEqual(len(self.state()["sshd"]), 2)

        second = self.f2b(*self.sweep_args(execute=True, limit=2, now="2026-10-25T01:00:00Z"), fmt="json")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)["due_total"], 2)
        self.assertEqual(self.state()["sshd"], [])

    def test_sweep_failure_is_audited_and_keeps_ban(self) -> None:
        self.assertEqual(self.ban("203.0.113.45", severity="medio", correlation="exp-1").returncode, 0)
        result = self.f2b(*self.sweep_args(execute=True, now="2026-10-25T01:00:00Z"), env={"F2B_FAIL_UNBAN": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()["sshd"], ["203.0.113.45"])
        self.assertEqual(self.audit()[-1]["result"], "error")

    def test_sweep_requires_approval(self) -> None:
        self.assertEqual(self.ban("203.0.113.45", severity="medio").returncode, 0)
        result = self.f2b(*self.sweep_args(execute=True, approved=None, now="2026-10-25T01:00:00Z"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state()["sshd"], ["203.0.113.45"])

    # ------------------------------------------------------------ config

    def test_config_fails_closed(self) -> None:
        self.write_config(allowlist=["127.0.0.0/8", "::1/128"])
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45")).returncode, 2)

        self.config_path.write_text("{", encoding="utf-8")
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45")).returncode, 2)

        self.write_config(extra="x")
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45")).returncode, 2)

        self.write_config(ttl={"medio": 3600, "alto": 86400, "max": 1000000})
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45")).returncode, 2)

        self.write_config(audit_path="relativo/audit.jsonl")
        self.assertEqual(self.f2b(*self.ban_args("203.0.113.45")).returncode, 2)

        self.write_config(client=" sudo ")
        self.assertEqual(self.f2b("--now", NOW, "check", "--jail", "sshd").returncode, 2)

        missing = self.tmp / "nao-existe.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--config", str(missing), "check", "--jail", "sshd"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)

        target = self.tmp / "config-real.json"
        target.write_text(json.dumps(json.loads(EXAMPLE.read_text(encoding="utf-8"))), encoding="utf-8")
        link = self.tmp / "config-link.json"
        link.symlink_to(target)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--config", str(link), "check", "--jail", "sshd"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)

    def test_audit_symlink_is_refused(self) -> None:
        target = self.tmp / "audit-real.jsonl"
        target.write_text("", encoding="utf-8")
        self.audit_path.symlink_to(target)
        result = self.f2b(*self.ban_args("203.0.113.45", execute=True))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()["sshd"], [])
        self.assertEqual(target.read_text(encoding="utf-8"), "")

    def test_audit_dir_world_writable_without_sticky_is_refused(self) -> None:
        unsafe = self.tmp / "unsafe"
        unsafe.mkdir()
        unsafe.chmod(0o777)
        self.write_config(audit_path=str(unsafe / "audit.jsonl"))
        result = self.f2b(*self.ban_args("203.0.113.45", execute=True))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state()["sshd"], [])
        self.assertFalse((unsafe / "audit.jsonl").exists())

    # ---------------------------------------------------------------- e2e

    def test_e2e_detection_ban_and_unban(self) -> None:
        triage = subprocess.run(
            [sys.executable, str(LOG_TRIAGE), str(AUTH_SAMPLE), "--now", NOW],
            capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(triage.returncode, 3, triage.stderr)
        findings = json.loads(triage.stdout)["findings"]
        critical = next(item for item in findings if item["severity"] == "critico")
        match = re.search(r"from ([0-9a-fA-F:.]+)", critical["evidence"][0]["excerpt"])
        self.assertIsNotNone(match, critical["evidence"][0]["excerpt"])
        attacker = match.group(1)
        self.assertFalse(ipaddress_is_allowlisted(attacker))

        ban = self.f2b(
            *self.ban_args(
                attacker, severity="critico", ttl="1h", execute=True,
                correlation="gaara-e2e-1",
            )
        )
        self.assertEqual(ban.returncode, 0, ban.stderr)
        self.assertIn(attacker, self.state()["sshd"])

        unban = self.f2b(*self.unban_args(attacker, execute=True))
        self.assertEqual(unban.returncode, 0, unban.stderr)
        self.assertNotIn(attacker, self.state()["sshd"])
        self.assertEqual(self.audit()[-1]["result"], "ok")


def ipaddress_is_allowlisted(ip: str) -> bool:
    import ipaddress
    address = ipaddress.ip_address(ip)
    for network in json.loads(EXAMPLE.read_text(encoding="utf-8"))["allowlist"]:
        candidate = ipaddress.ip_network(network)
        if candidate.version == address.version and address in candidate:
            return True
    return False


if __name__ == "__main__":
    unittest.main()
