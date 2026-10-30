"""Testes do auditor de postura harden_check.py.

Cobrem o critério de aceitação do Lote 6:
- host com controles bons recebe score alto e nenhum achado;
- host vulnerável gera achados críticos/altos e exit 3;
- permissões, UID 0, SSH, firewall, kernel e TLS são detectados;
- baseline é gravado em 0600 e a segunda execução detecta drift;
- parsers de Docker/portas e o contrato de finding-schema são exercitados.

Executar:
    python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "harden_check.py"
NOW = "2026-10-25T12:00:00Z"
SCAN_ID = "gaara-20261025-0006"

spec = importlib.util.spec_from_file_location("harden_check", SCRIPT)
harden_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["harden_check"] = harden_check
spec.loader.exec_module(harden_check)


def write(path: Path, content: str, mode: int | None = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def mkdir(path: Path, mode: int = 0o755) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def make_root(base: Path, variant: str) -> Path:
    """Cria uma árvore de host pequena e determinística para auditoria offline."""
    root = base / ("root-" + variant)
    root.mkdir(parents=True)
    mkdir(root / "etc/ssh/sshd_config.d")
    mkdir(root / "etc/ufw")
    mkdir(root / "etc/apt/apt.conf.d")
    mkdir(root / "etc/nginx/sites-enabled")
    mkdir(root / "etc/ssl/private", 0o710)
    mkdir(root / "root", 0o700)
    mkdir(root / "var/run")
    mkdir(root / "proc/sys/kernel")
    for name in (
        "net/ipv4",
        "net/ipv4/conf/all",
        "net/ipv4/conf/default",
        "fs",
    ):
        mkdir(root / "proc/sys" / name)

    write(root / "etc/os-release",
          'PRETTY_NAME="Ubuntu 26.04 LTS"\nID=ubuntu\nVERSION_ID="26.04"\n')

    if variant == "vuln":
        ssh = (
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "PermitEmptyPasswords yes\n"
            "MaxAuthTries 10\n"
            "PubkeyAuthentication no\n"
            "X11Forwarding yes\n"
        )
        write(root / "etc/ssh/sshd_config", ssh, 0o666)
        write(root / "etc/ufw/ufw.conf", "ENABLED=no\n")
        write(root / "etc/shadow", "root:*:19000:0:99999:7:::\n", 0o644)
        write(root / "etc/passwd",
              "root:x:0:0:root:/root:/bin/bash\n"
              "backdoor:x:0:0:backdoor:/root:/bin/bash\n", 0o644)
        write(root / "etc/group", "root:x:0:\n", 0o666)
        write(root / "etc/sudoers", "root ALL=(ALL) ALL\n", 0o666)
        write(root / "etc/ssh/ssh_host_ed25519_key", "fake-key\n", 0o644)
        (root / "etc/ssl/private").chmod(0o755)
        (root / "root").chmod(0o755)
        write(root / "var/run/reboot-required", "")
        write(root / "etc/nginx/sites-enabled/default",
              "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n")
        values = {
            "kernel/randomize_va_space": "0",
            "kernel/kptr_restrict": "0",
            "kernel/dmesg_restrict": "0",
            "net/ipv4/tcp_syncookies": "0",
            "net/ipv4/conf/all/rp_filter": "0",
            "net/ipv4/conf/default/rp_filter": "0",
            "net/ipv4/conf/all/accept_redirects": "1",
            "net/ipv4/conf/default/accept_redirects": "1",
            "fs/protected_hardlinks": "0",
            "fs/protected_symlinks": "0",
        }
    else:
        ssh = (
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "MaxAuthTries 3\n"
            "PubkeyAuthentication yes\n"
            "X11Forwarding no\n"
        )
        write(root / "etc/ssh/sshd_config", ssh, 0o644)
        write(root / "etc/ufw/ufw.conf", "ENABLED=yes\n")
        write(root / "etc/shadow", "root:*:19000:0:99999:7:::\n", 0o640)
        write(root / "etc/passwd",
              "root:x:0:0:root:/root:/bin/bash\n"
              "app:x:1000:1000:app:/home/app:/bin/bash\n", 0o644)
        write(root / "etc/group", "root:x:0:\napp:x:1000:\n", 0o644)
        write(root / "etc/sudoers", "root ALL=(ALL) ALL\n", 0o440)
        write(root / "etc/ssh/ssh_host_ed25519_key", "fake-key\n", 0o600)
        write(root / "etc/apt/apt.conf.d/20auto-upgrades",
              'APT::Periodic::Update-Package-Lists "1";\n'
              'APT::Periodic::Unattended-Upgrade "1";\n')
        values = {
            "kernel/randomize_va_space": "2",
            "kernel/kptr_restrict": "1",
            "kernel/dmesg_restrict": "1",
            "net/ipv4/tcp_syncookies": "1",
            "net/ipv4/conf/all/rp_filter": "1",
            "net/ipv4/conf/default/rp_filter": "1",
            "net/ipv4/conf/all/accept_redirects": "0",
            "net/ipv4/conf/default/accept_redirects": "0",
            "fs/protected_hardlinks": "1",
            "fs/protected_symlinks": "1",
        }

    for relative, value in values.items():
        write(root / "proc/sys" / relative, value + "\n")
    return root


class HardenCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gaara-harden-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def root(self, variant: str = "good") -> Path:
        return make_root(self.tmp / variant, variant)

    def run_script(self, root: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(SCRIPT), "--now", NOW, "--root", str(root),
                "--host", "test-host", "--scan-id", SCAN_ID, *args,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def run_json(self, root: Path, *args: str) -> tuple[dict, subprocess.CompletedProcess[str]]:
        proc = self.run_script(root, "--format", "json", *args)
        if proc.returncode not in (0, 3):
            raise AssertionError(proc.stderr)
        return json.loads(proc.stdout), proc

    @staticmethod
    def by_key(result: dict, key: str) -> list[dict]:
        return [item for item in result["findings"] if item["observations"].get("key") == key]

    # ------------------------------------------------------------- aceitação

    def test_good_host_has_high_score_and_no_findings(self) -> None:
        result, proc = self.run_json(self.root("good"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["score"], 100)
        self.assertEqual(result["summary"]["score_status"], "calculado")
        self.assertEqual(result["summary"]["counts"],
                         {"critico": 0, "alto": 0, "medio": 0, "baixo": 0})

    def test_vulnerable_host_has_critical_and_exits_3(self) -> None:
        result, proc = self.run_json(self.root("vuln"))
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(result["summary"]["verdict"], "incidente")
        self.assertGreaterEqual(result["summary"]["counts"]["critico"], 3)
        self.assertGreaterEqual(result["summary"]["counts"]["alto"], 3)
        self.assertLess(result["summary"]["score"], 70)
        categories = {item["category"] for item in result["findings"]}
        for expected in (
            "posture/ssh-config", "posture/firewall", "posture/permissions",
            "posture/tls", "posture/updates",
        ):
            self.assertIn(expected, categories)

    def test_schema_contract_and_action_gate(self) -> None:
        result, _ = self.run_json(self.root("vuln"))
        counts = {level: 0 for level in ("critico", "alto", "medio", "baixo")}
        for item in result["findings"]:
            counts[item["severity"]] += 1
            self.assertIn(item["category"], harden_check.triage.CATEGORIES)
            self.assertTrue(item["evidence"])
            self.assertTrue(item["evidence"][0]["locator"])
            rec = item["recommendation"]
            self.assertTrue(rec.get("requires_approval") or rec["action"] in harden_check.triage.NO_APPROVAL_ACTIONS)
            if rec.get("requires_approval"):
                self.assertTrue(rec.get("rollback"))
        self.assertEqual(counts, result["summary"]["counts"])

    def test_check_is_read_only(self) -> None:
        root = self.root("good")
        before: dict[str, tuple[int, int]] = {}
        for path in sorted(root.rglob("*")):
            st = path.stat()
            before[str(path)] = (stat.S_IMODE(st.st_mode), st.st_size)
        proc = self.run_script(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after: dict[str, tuple[int, int]] = {}
        for path in sorted(root.rglob("*")):
            st = path.stat()
            after[str(path)] = (stat.S_IMODE(st.st_mode), st.st_size)
        self.assertEqual(before, after)

    # ------------------------------------------------------------- SSH

    def test_ssh_root_login_and_empty_password(self) -> None:
        root = self.root("good")
        write(root / "etc/ssh/sshd_config",
              "PermitRootLogin yes\n"
              "PasswordAuthentication no\n"
              "PermitEmptyPasswords yes\n"
              "MaxAuthTries 3\n"
              "PubkeyAuthentication yes\n"
              "X11Forwarding no\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        self.assertTrue(self.by_key(result, "ssh.permit_root_login"))
        empty = self.by_key(result, "ssh.permit_empty_passwords")
        self.assertTrue(empty)
        self.assertEqual(empty[0]["severity"], "critico")

    def test_ssh_include_respects_first_value(self) -> None:
        root = self.root("good")
        write(root / "etc/ssh/sshd_config",
              "PasswordAuthentication no\n"
              "Include /etc/ssh/sshd_config.d/*.conf\n"
              "PermitRootLogin no\n")
        write(root / "etc/ssh/sshd_config.d/50-cloud.conf",
              "PasswordAuthentication yes\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.by_key(result, "ssh.password_authentication"))

    def test_ssh_include_can_enable_password(self) -> None:
        root = self.root("good")
        write(root / "etc/ssh/sshd_config",
              "Include /etc/ssh/sshd_config.d/*.conf\n"
              "PermitRootLogin no\n")
        write(root / "etc/ssh/sshd_config.d/50-cloud.conf",
              "PasswordAuthentication yes\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        self.assertTrue(self.by_key(result, "ssh.password_authentication"))

    # ------------------------------------------------------------- kernel/permissões

    def test_kernel_aslr_zero_is_high(self) -> None:
        root = self.root("good")
        write(root / "proc/sys/kernel/randomize_va_space", "0\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        finding = self.by_key(result, "kernel.aslr")
        self.assertTrue(finding)
        self.assertEqual(finding[0]["severity"], "alto")

    def test_syncookies_always_is_accepted(self) -> None:
        root = self.root("good")
        write(root / "proc/sys/net/ipv4/tcp_syncookies", "2\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.by_key(result, "net.syncookies"))

    def test_shadow_world_readable_is_critical(self) -> None:
        root = self.root("good")
        (root / "etc/shadow").chmod(0o644)
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        finding = self.by_key(result, "perm.shadow")
        self.assertTrue(finding)
        self.assertEqual(finding[0]["severity"], "critico")

    def test_extra_uid0_is_critical(self) -> None:
        root = self.root("good")
        path = root / "etc/passwd"
        path.write_text(path.read_text() + "toor:x:0:0:toor:/root:/bin/bash\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        finding = self.by_key(result, "accounts.uid0")
        self.assertTrue(finding)
        self.assertEqual(finding[0]["severity"], "critico")
        self.assertIn("toor", finding[0]["observations"]["accounts"])

    def test_host_key_and_sudoers_permissions(self) -> None:
        root = self.root("good")
        (root / "etc/ssh/ssh_host_ed25519_key").chmod(0o644)
        (root / "etc/sudoers").chmod(0o644)
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(self.by_key(result, "perm.ssh_host_keys")[0]["severity"], "critico")
        self.assertTrue(self.by_key(result, "perm.sudoers"))

    # ------------------------------------------------------------- TLS

    def test_tls_old_protocol_is_high(self) -> None:
        root = self.root("good")
        write(root / "etc/nginx/sites-enabled/default",
              "server { listen 443 ssl; ssl_protocols TLSv1.0 TLSv1.2; }\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 3)
        finding = self.by_key(result, "tls.protocols")
        self.assertTrue(finding)
        self.assertEqual(finding[0]["severity"], "alto")

    def test_tls_modern_protocol_passes(self) -> None:
        root = self.root("good")
        write(root / "etc/nginx/sites-enabled/default",
              "server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.by_key(result, "tls.protocols"))

    def test_tls_apache_negation_is_not_false_positive(self) -> None:
        root = self.root("good")
        write(root / "etc/apache2/sites-enabled/ssl.conf",
              "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n")
        result, proc = self.run_json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.by_key(result, "tls.protocols"))

    # ------------------------------------------------------------- parsers

    def test_docker_published_port_parser_deduplicates_and_ignores_loopback(self) -> None:
        text = (
            "0.0.0.0:3307->3306/tcp, [::]:3307->3306/tcp, "
            ":::3307->3306/tcp, 127.0.0.1:5433->5432/tcp"
        )
        self.assertEqual(harden_check.parse_docker_ports(text), [(3307, 3306, "tcp")])

    def test_exposed_listener_does_not_emit_ufw_command_without_firewall_context(self) -> None:
        host = harden_check.Host(self.root("good"), True, harden_check.parse_now(NOW))
        host.no_commands = False
        proc = subprocess.CompletedProcess(
            ["ss"], 0, "LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*\n", ""
        )
        with patch.object(host, "run", return_value=proc):
            finding = harden_check.check_listening(host, set())[0]
        self.assertEqual(finding.action, "investigate")
        self.assertIsNone(finding.command)
        self.assertIsNone(finding.rollback)
        self.assertIn("firewall local/externo", finding.false_positive_notes)

    def test_docker_published_database_port_is_context_check_not_ufw_block(self) -> None:
        host = harden_check.Host(self.root("good"), True, harden_check.parse_now(NOW))
        host.no_commands = False
        outputs = [
            subprocess.CompletedProcess(
                ["docker", "ps"], 0,
                json.dumps({"Names": "db", "Ports": "0.0.0.0:3306->3306/tcp"}) + "\n", "",
            ),
            subprocess.CompletedProcess(["docker", "ps", "-q"], 0, "container-id\n", ""),
            subprocess.CompletedProcess(["docker", "inspect"], 0, "/db\tfalse\tbridge\n", ""),
        ]
        with patch.object(harden_check.shutil, "which", return_value="/usr/bin/docker"):
            with patch.object(host, "run", side_effect=outputs):
                findings = harden_check.check_docker(host)
        finding = next(item for item in findings if item.key == "docker.published_high_risk")
        self.assertEqual(finding.action, "investigate")
        self.assertIsNone(finding.command)
        self.assertIsNone(finding.rollback)

    def test_ufw_config_without_effective_status_is_unknown_and_unscored(self) -> None:
        root = self.root("vuln")
        host = harden_check.Host(root, True, harden_check.parse_now(NOW))
        controls = harden_check.check_firewall(host)
        self.assertEqual(controls[0].status, "unknown")
        self.assertIn("ENABLED=no", controls[0].excerpt)
        score, _, assessed, total, _ = harden_check.score_controls(controls)
        self.assertIsNone(score)
        self.assertEqual(assessed, 0)
        self.assertEqual(total, 12)

    def test_confirmed_inactive_ufw_is_investigation_without_generic_enable_command(self) -> None:
        root = self.root("vuln")
        host = harden_check.Host(root, True, harden_check.parse_now(NOW))
        host.no_commands = False

        def run(argv: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str]:
            if argv[:2] == ["ufw", "status"]:
                return subprocess.CompletedProcess(argv, 0, "Status: inactive\n", "")
            if argv[:2] == ["systemctl", "is-active"]:
                return subprocess.CompletedProcess(argv, 3, "inactive\n", "")
            if argv[:2] == ["nft", "list"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:2] == ["iptables", "-S"]:
                return subprocess.CompletedProcess(argv, 0, "-P INPUT ACCEPT\n", "")
            return subprocess.CompletedProcess(argv, 127, "", "not found")

        with patch.object(host, "run", side_effect=run):
            finding = harden_check.check_firewall(host)[0]
        self.assertEqual(finding.status, "fail")
        self.assertEqual(finding.severity, "alto")
        self.assertEqual(finding.action, "investigate")
        self.assertIsNone(finding.command)
        self.assertIsNone(finding.rollback)
        self.assertIn("porta SSH real", finding.false_positive_notes)

    def test_sysctl_recommendations_are_runtime_only_with_runtime_rollback(self) -> None:
        result, _ = self.run_json(self.root("vuln"))
        expected = {
            "kernel.aslr": ("sysctl -w kernel.randomize_va_space=2",
                            "sysctl -w kernel.randomize_va_space=0"),
            "net.syncookies": ("sysctl -w net.ipv4.tcp_syncookies=1",
                               "sysctl -w net.ipv4.tcp_syncookies=0"),
            "net.accept_redirects": (
                "sysctl -w net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0",
                "sysctl -w net.ipv4.conf.all.accept_redirects=1 net.ipv4.conf.default.accept_redirects=1",
            ),
            "fs.protected_links": (
                "sysctl -w fs.protected_hardlinks=1 fs.protected_symlinks=1",
                "sysctl -w fs.protected_hardlinks=0 fs.protected_symlinks=0",
            ),
        }
        for key, (command, rollback) in expected.items():
            with self.subTest(key=key):
                finding = self.by_key(result, key)[0]
                rec = finding["recommendation"]
                self.assertEqual(rec["command"], command)
                self.assertEqual(rec["rollback"], rollback)
                self.assertNotIn("/etc/sysctl.d/", rec["command"])
                self.assertNotIn("/etc/sysctl.d/", rec["rollback"])
                self.assertIn("runtime", finding["impact"])

    def test_redirects_cover_existing_interfaces_and_restore_each_runtime_value(self) -> None:
        root = self.root("vuln")
        write(root / "proc/sys/net/ipv4/conf/enp0s3/accept_redirects", "1\n")
        result, _ = self.run_json(root)
        finding = self.by_key(result, "net.accept_redirects")[0]
        rec = finding["recommendation"]
        self.assertIn("net.ipv4.conf.enp0s3.accept_redirects=0", rec["command"])
        self.assertIn("net.ipv4.conf.enp0s3.accept_redirects=1", rec["rollback"])

    def test_ufw_config_parser_accepts_quotes(self) -> None:
        root = self.root("good")
        write(root / "etc/ufw/ufw.conf", 'ENABLED="yes"\n')
        host = harden_check.Host(root, True, harden_check.parse_now(NOW))
        self.assertTrue(harden_check._ufw_enabled(host))

    def test_iptables_only_counts_real_input_filtering(self) -> None:
        self.assertFalse(harden_check._has_iptables_input_rules(
            "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        ))
        self.assertTrue(harden_check._has_iptables_input_rules(
            "-P INPUT DROP\n"
        ))
        self.assertTrue(harden_check._has_iptables_input_rules(
            "-A INPUT -m conntrack --ctstate INVALID -j DROP\n"
        ))

    def test_nft_requires_input_hook_with_drop_or_reject(self) -> None:
        accept_only = (
            "table inet filter {\n"
            "  chain input {\n"
            "    type filter hook input priority filter; policy accept;\n"
            "    tcp dport 22 accept\n"
            "  }\n"
            "}\n"
        )
        self.assertFalse(harden_check._nft_has_input_filter(accept_only))
        drop_policy = accept_only.replace("policy accept", "policy drop")
        self.assertTrue(harden_check._nft_has_input_filter(drop_policy))
        drop_rule = accept_only.replace(
            "tcp dport 22 accept", "tcp dport 22 drop"
        )
        self.assertTrue(harden_check._nft_has_input_filter(drop_rule))

    def test_ss_wildcard_parser(self) -> None:
        text = (
            "LISTEN 0 4096 0.0.0.0:3306 0.0.0.0:*\n"
            "LISTEN 0 4096 [::]:8080 [::]:*\n"
            "LISTEN 0 4096 127.0.0.1:6379 0.0.0.0:*\n"
        )
        self.assertEqual(harden_check.parse_ss_listeners(text), {3306, 8080})

    def test_proc_listener_parser_ignores_loopback(self) -> None:
        root = self.root("good")
        mkdir(root / "proc/net")
        write(root / "proc/net/tcp",
              "  sl  local_address rem_address   st\n"
              "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n"
              "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n")
        write(root / "proc/net/tcp6",
              "  sl  local_address rem_address   st\n"
              "   0: 00000000000000000000000000000000:1F91 "
              "00000000000000000000000000000000:0000 0A 00000000:00000000\n")
        host = harden_check.Host(root, True, harden_check.parse_now(NOW))
        self.assertEqual(harden_check._proc_listeners(host), {8080, 8081})

    # ------------------------------------------------------------- baseline/drift

    def test_baseline_roundtrip_and_drift_regression(self) -> None:
        root = self.root("good")
        app = self.tmp / "app"
        write(app / ".env", "APP_KEY=segredo\n", 0o600)
        baseline = self.tmp / "baseline.json"
        result, proc = self.run_json(root, "--app-root", str(app), "--write-baseline", str(baseline))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(stat.S_IMODE(baseline.stat().st_mode), 0o600)
        self.assertFalse(self.by_key(result, "secrets.app_files"))

        (app / ".env").chmod(0o644)
        drifted, proc = self.run_json(root, "--app-root", str(app), "--baseline", str(baseline))
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertTrue(self.by_key(drifted, "secrets.app_files"))
        drift = drifted["summary"]["drift"]
        self.assertLess(drift["score_delta"], 0)
        self.assertEqual(drift["regressions"], 1)
        self.assertEqual(drift["items"][0]["key"], "secrets.app_files")
        self.assertEqual(drift["items"][0]["direction"], "regressao")

    def test_baseline_second_run_without_change_reports_no_drift(self) -> None:
        root = self.root("good")
        baseline = self.tmp / "baseline.json"
        first, proc = self.run_json(root, "--write-baseline", str(baseline))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        second, proc = self.run_json(root, "--baseline", str(baseline))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(second["summary"]["drift"]["changed"], 0)
        self.assertEqual(first["summary"]["score"], second["summary"]["score"])

    def test_baseline_invalid_is_rejected(self) -> None:
        root = self.root("good")
        baseline = self.tmp / "bad.json"
        baseline.write_text("{}", encoding="utf-8")
        proc = self.run_script(root, "--baseline", str(baseline))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("baseline", proc.stderr)

    def test_write_baseline_refuses_symlink(self) -> None:
        root = self.root("good")
        target = self.tmp / "real-baseline.json"
        link = self.tmp / "link-baseline.json"
        os.symlink(target, link)
        proc = self.run_script(root, "--write-baseline", str(link))
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(target.exists())
        self.assertIn("symlink", proc.stderr)

    def test_baseline_host_mismatch_is_reported(self) -> None:
        root = self.root("good")
        baseline = self.tmp / "baseline.json"
        self.run_json(root, "--write-baseline", str(baseline))
        result, proc = self.run_json(root, "--baseline", str(baseline), "--host", "outro-host")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("outro host", result["summary"]["drift"]["host_note"])

    # ------------------------------------------------------------- CLI/cobertura

    def test_empty_root_has_insufficient_coverage(self) -> None:
        empty = self.tmp / "empty"
        empty.mkdir()
        proc = self.run_script(empty, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertIsNone(result["summary"]["score"])
        self.assertEqual(result["summary"]["score_status"], "insuficiente")

    def test_redact_off_requires_reason(self) -> None:
        proc = self.run_script(self.root("good"), "--redact", "off")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--redact-off-reason", proc.stderr)

    def test_markdown_is_readable_and_does_not_leak_private_key(self) -> None:
        root = self.root("vuln")
        output = self.tmp / "postura.md"
        proc = self.run_script(root, "--format", "md", "--output", str(output))
        self.assertEqual(proc.returncode, 3, proc.stderr)
        text = output.read_text(encoding="utf-8")
        self.assertIn("# Postura de segurança", text)
        self.assertIn("**Score:**", text)
        self.assertIn("somente leitura", text)
        self.assertNotIn("BEGIN PRIVATE KEY", text)

    def test_markdown_separates_corrections_from_context_checks(self) -> None:
        result, _ = self.run_json(self.root("vuln"))
        text = harden_check.render_markdown(result)
        corrections = text.split("## Correções priorizadas (revisar e aprovar)", 1)[1].split("## ", 1)[0]
        self.assertNotIn("UFW desabilitado", corrections)
        not_observed = text.split("## Não observado", 1)[1]
        self.assertIn("ENABLED=no", not_observed)

    def test_missing_app_root_is_usage_error(self) -> None:
        proc = self.run_script(self.root("good"), "--app-root", str(self.tmp / "nao-existe"))
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
