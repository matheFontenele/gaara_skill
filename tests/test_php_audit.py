"""Testes do auditor estático de PHP (php_audit.py).

Cobrem o critério de aceitação do Lote 4:
- a amostra vulnerável tem todos os padrões conhecidos detectados;
- a amostra sadia produz zero achados, inclusive com comentários/strings;
- segredos não vazam no relatório padrão;
- o contrato de finding-schema.md é respeitado.

Executar:
    python3 -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "php_audit.py"
VULNERABLE = ROOT / "tests" / "corpus" / "php-vulnerable"
CLEAN = ROOT / "tests" / "corpus" / "php-clean"
NOW = "2026-10-24T23:00:00Z"
SCAN_ID = "gaara-20261024-0004"

spec = importlib.util.spec_from_file_location("php_audit", SCRIPT)
php_audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["php_audit"] = php_audit
spec.loader.exec_module(php_audit)


def write(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def run_json(path: Path, *args: str) -> tuple[dict, subprocess.CompletedProcess[str]]:
    proc = run(str(path), "--now", NOW, "--scan-id", SCAN_ID, *args)
    if proc.returncode not in (0, 3):
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout), proc


class PhpAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # O modo do .env faz parte do teste de permissões.
        (VULNERABLE / ".env").chmod(0o644)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="gaara-php-audit-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))

    # ------------------------------------------------------------- aceitação

    def test_vulnerable_tree_is_detected(self) -> None:
        result, proc = run_json(VULNERABLE)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(result["summary"]["verdict"], "incidente")
        self.assertEqual(result["summary"]["counts"],
                         {"critico": 4, "alto": 25, "medio": 3, "baixo": 0})
        categories = {item["category"] for item in result["findings"]}
        for expected in ("code/rce", "code/injection", "code/upload", "posture/secrets",
                         "posture/permissions", "legacy/eol-runtime", "legacy/migration-blocker"):
            self.assertIn(expected, categories)

    def test_clean_tree_has_zero_findings(self) -> None:
        result, proc = run_json(CLEAN)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(result["summary"]["verdict"], "estavel")
        self.assertEqual(result["findings"], [])
        self.assertEqual(sum(result["summary"]["counts"].values()), 0)

    def test_all_migration_symbols_are_detected(self) -> None:
        result, _ = run_json(VULNERABLE)
        symbols = {
            item["observations"].get("symbol")
            for item in result["findings"]
            if item["category"] == "legacy/migration-blocker"
        }
        expected = {
            "$HTTP_RAW_POST_DATA", "curly-offset", "ereg", "mysql_connect",
            "mysql_query", "split", "mcrypt_encrypt", "__autoload",
            "create_function", "each", "get_magic_quotes_gpc", "money_format",
        }
        self.assertTrue(expected.issubset(symbols), expected - symbols)

    def test_dangerous_patterns_are_detected(self) -> None:
        result, _ = run_json(VULNERABLE)
        titles = " | ".join(item["title"] for item in result["findings"])
        for expected in (
            "eval", "system", "Desserialização", "preg_replace",
            "Inclusão de arquivo", "extraídas", "Consulta SQL", "Upload de arquivo",
        ):
            self.assertIn(expected, titles)

    def test_sql_sink_is_not_duplicated_as_migration(self) -> None:
        result, _ = run_json(VULNERABLE)
        migration_sources = {
            Path(item["evidence"][0]["source"]).name
            for item in result["findings"]
            if item["category"] == "legacy/migration-blocker"
            and item["observations"].get("symbol") == "mysql_query"
        }
        self.assertNotIn("index.php", migration_sources)

    def test_multiple_include_lines_are_aggregated(self) -> None:
        result, _ = run_json(VULNERABLE)
        finding = next(
            item for item in result["findings"]
            if item["category"] == "code/injection" and "Inclusão de arquivo" in item["title"]
        )
        self.assertEqual([ev["locator"] for ev in finding["evidence"]], ["linha 4", "linha 5"])
        self.assertEqual(finding["observations"]["occurrences"], 2)

    # ------------------------------------------------------------- segredos

    def test_secrets_are_redacted_by_default(self) -> None:
        _, proc = run_json(VULNERABLE)
        for secret in (
            "ConfigSecret123", "LegacyDbPass", "EnvSecret123",
            "SuperSecretDocker", "KeySecret456", "TokenSecret789",
        ):
            self.assertNotIn(secret, proc.stdout)

    def test_secret_excerpts_mark_redaction(self) -> None:
        result, _ = run_json(VULNERABLE)
        secrets = [item for item in result["findings"]
                   if item["category"] == "posture/secrets"
                   and ("Credencial literal" in item["title"] or "Chave privada" in item["title"])]
        self.assertTrue(secrets)
        for item in secrets:
            self.assertTrue(item["evidence"][0]["redacted"])
            self.assertIn("[REDACTADO]", item["evidence"][0]["excerpt"])

    def test_redact_off_requires_reason_and_shows_raw(self) -> None:
        missing = run(str(VULNERABLE), "--redact", "off")
        self.assertEqual(missing.returncode, 2)
        proc = run(str(VULNERABLE), "--redact", "off",
                   "--redact-off-reason", "perícia autorizada",
                   "--now", NOW, "--scan-id", SCAN_ID)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("ConfigSecret123", proc.stdout)
        result = json.loads(proc.stdout)
        secret = next(item for item in result["findings"]
                      if "db_pass" in item["title"])
        self.assertFalse(secret["evidence"][0]["redacted"])

    def test_private_key_is_detected_without_leaking_material(self) -> None:
        root = self.tmp / "keys"
        write(root / "deploy.pem",
              "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsegredo\n-----END RSA PRIVATE KEY-----\n")
        result, proc = run_json(root)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        finding = next(item for item in result["findings"]
                       if "Chave privada" in item["title"])
        self.assertEqual(finding["severity"], "critico")
        self.assertTrue(finding["evidence"][0]["redacted"])
        self.assertNotIn("MIIEowIBAAKCAQEAsegredo", proc.stdout)

        off = run(str(root), "--redact", "off",
                  "--redact-off-reason", "perícia autorizada",
                  "--now", NOW, "--scan-id", SCAN_ID)
        self.assertEqual(off.returncode, 3, off.stderr)
        self.assertNotIn("MIIEowIBAAKCAQEAsegredo", off.stdout)
        off_finding = next(item for item in json.loads(off.stdout)["findings"]
                           if "Chave privada" in item["title"])
        self.assertTrue(off_finding["evidence"][0]["redacted"])

    def test_env_permissions(self) -> None:
        root = self.tmp / "env"
        write(root / ".env", "DB_PASSWORD=Secret123\n", mode=0o644)
        result, _ = run_json(root)
        self.assertTrue(any(item["category"] == "posture/permissions"
                            for item in result["findings"]))
        (root / ".env").chmod(0o600)
        result, _ = run_json(root)
        self.assertFalse(any(item["category"] == "posture/permissions"
                             for item in result["findings"]))

    # ------------------------------------------------------------- configuração

    def test_eol_signals_from_composer_and_dockerfile(self) -> None:
        result, _ = run_json(VULNERABLE)
        eol = [item for item in result["findings"] if item["category"] == "legacy/eol-runtime"]
        self.assertEqual(len(eol), 2)
        versions = {version for item in eol for version in item["observations"]["versions"]}
        self.assertIn("5.6", versions)
        sources = {Path(item["evidence"][0]["source"]).name for item in eol}
        self.assertEqual(sources, {"Dockerfile", "composer.json"})

    def test_php_version_file(self) -> None:
        root = self.tmp / "version"
        write(root / ".php-version", "7.4\n")
        result, _ = run_json(root)
        finding = next(item for item in result["findings"]
                       if item["category"] == "legacy/eol-runtime")
        self.assertEqual(finding["severity"], "alto")
        self.assertIn("7.4", finding["observations"]["versions"])

    def test_tool_versions_file(self) -> None:
        root = self.tmp / "tools"
        write(root / ".tool-versions", "php 5.6.40\nnodejs 20.0.0\n")
        result, _ = run_json(root)
        finding = next(item for item in result["findings"]
                       if item["category"] == "legacy/eol-runtime")
        self.assertEqual(finding["severity"], "critico")

    def test_classify_constraint(self) -> None:
        self.assertEqual(php_audit.classify_constraint(">=5.6 <7.0"), ("critico", "5.6"))
        self.assertEqual(php_audit.classify_constraint("^7.4"), ("alto", "7.4"))
        self.assertEqual(php_audit.classify_constraint("7.4.*"), ("alto", "7.4"))
        self.assertEqual(php_audit.classify_constraint("5.6.40"), ("critico", "5.6.40"))
        self.assertIsNone(php_audit.classify_constraint(">=8.2"))
        self.assertIsNone(php_audit.classify_constraint(">=7.4"))
        self.assertIsNone(php_audit.classify_constraint(">=5.6"))
        self.assertIsNone(php_audit.classify_constraint("^8.1"))
        self.assertIsNone(php_audit.classify_constraint("^7.4 || ^8.0"))

    # ------------------------------------------------------------- FP / vendor

    def test_vendor_is_ignored_by_default_and_included_on_request(self) -> None:
        clean, _ = run_json(CLEAN)
        self.assertEqual(clean["findings"], [])
        with_vendor, proc2 = run_json(CLEAN, "--include-vendor")
        self.assertEqual(proc2.returncode, 3, proc2.stderr)
        categories = {item["category"] for item in with_vendor["findings"]}
        self.assertEqual(categories, {"code/rce", "code/injection"})
        self.assertTrue(any("vendor" in item["evidence"][0]["source"]
                            for item in with_vendor["findings"]))

    def test_comments_and_strings_do_not_trigger(self) -> None:
        result, _ = run_json(CLEAN)
        self.assertEqual(result["findings"], [])
        masked, strings = php_audit.lex_php(
            "<?php\n// eval($_POST['x']);\n$doc = 'mysql_query(';\n$ok = 1;\n"
        )
        self.assertNotIn("eval", masked)
        self.assertNotIn("mysql_query", masked)
        self.assertIn("mysql_query", " ".join(value for value, _ in strings))

    # ------------------------------------------------------------- contrato

    def test_schema_validates(self) -> None:
        result, _ = run_json(VULNERABLE)
        self.assertEqual(php_audit.triage.validate(result), [])
        for item in result["findings"]:
            for evidence in item["evidence"]:
                self.assertEqual(evidence["source_type"], "code")
                self.assertTrue(evidence["locator"])

    def test_artifacts_match_file_hashes(self) -> None:
        import hashlib
        result, _ = run_json(VULNERABLE)
        artifacts = {item["path"]: item["sha256"] for item in result["scan"]["artifacts"]}
        self.assertTrue(artifacts)
        for path, digest in artifacts.items():
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), digest)

    def test_deterministic_findings(self) -> None:
        first, _ = run_json(VULNERABLE)
        second, _ = run_json(VULNERABLE)
        self.assertEqual(first["findings"], second["findings"])

    def test_markdown_output(self) -> None:
        proc = run(str(VULNERABLE), "--format", "md",
                   "--now", NOW, "--scan-id", SCAN_ID)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn("# Auditoria de código PHP", proc.stdout)
        self.assertIn("**Veredito:** incidente", proc.stdout)
        self.assertIn("Não observado", proc.stdout)
        self.assertNotIn("ConfigSecret123", proc.stdout)

    def test_output_file(self) -> None:
        output = self.tmp / "audit.json"
        proc = run(str(VULNERABLE), "--output", str(output),
                   "--now", NOW, "--scan-id", SCAN_ID)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertTrue(output.is_file())
        self.assertIsInstance(json.loads(output.read_text(encoding="utf-8")), dict)

    def test_missing_path_and_invalid_limits(self) -> None:
        missing = run(str(self.tmp / "nao-existe"))
        self.assertEqual(missing.returncode, 1)
        invalid = run(str(CLEAN), "--max-files", "0")
        self.assertEqual(invalid.returncode, 2)


if __name__ == "__main__":
    unittest.main()
