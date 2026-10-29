#!/usr/bin/env python3
"""Tests for the read-only guided assessment report builder."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import assessment_report as ar  # noqa: E402


def report(tool: str, category: str, severity: str = "alto", title: str = "Finding",
           observations: dict | None = None, evidence: list | None = None,
           summary: dict | None = None, limits: dict | None = None) -> dict:
    return {
        "schema_version": "1.1",
        "scan": {"tool": tool, "finished_at": "2026-10-29T12:00:00Z", "limits": limits or {}},
        "findings": [{
            "id": "F-001", "category": category, "severity": severity,
            "confidence": "alta", "title": title,
            "observations": observations or {}, "evidence": evidence or [],
        }],
        "summary": summary or {"not_observed": []},
    }


class AssessmentTests(unittest.TestCase):
    def test_combines_dependencies_php_hardening_and_logs(self) -> None:
        reports = [
            ("deps", report("deps_audit", "cve/CVE-2026-12345", observations={"package": "lib-x", "installed": "1.0", "aliases": ["CVE-2026-12345"]})),
            ("php", report("php_audit", "code/sql-injection", severity="medio")),
            ("host", report("harden_check", "posture/ssh-root-login", severity="baixo", summary={"score": 70, "not_observed": []}, limits={"controls_assessed": 8})),
            ("logs", report("log_triage", "detection/ssh-bruteforce", severity="alto")),
        ]
        result = ar.build_assessment(reports)
        self.assertEqual(result["summary"]["reports_received"], 4)
        self.assertEqual(result["summary"]["unique_findings"], 4)
        text = ar.render_markdown(result)
        self.assertIn("score de host 70", text)
        self.assertIn("CVE-2026-12345", text)
        self.assertIn("não confirma", text)

    def test_deduplicates_same_advisory_across_labels(self) -> None:
        common = {"package": "lib-x", "installed": "1.0", "aliases": ["CVE-2026-12345"]}
        result = ar.build_assessment([
            ("api", report("deps", "cve/CVE-2026-12345", observations=common)),
            ("web", report("deps", "cve/CVE-2026-12345", observations=common)),
        ])
        self.assertEqual(result["summary"]["unique_findings"], 1)
        self.assertEqual(result["findings"][0]["sources"], ["api", "web"])
        self.assertEqual(result["findings"][0]["occurrences"], 2)

    def test_counts_advisories_separately_from_cves(self) -> None:
        result = ar.build_assessment([("deps", report(
            "deps", "supply-chain/known-vulnerability", severity="alto",
            title="GHSA-example-1234-5678 em pacote 1.0",
            observations={"package": "pacote", "installed": "1.0",
                          "aliases": ["CVE-2026-12345"]},
        ))])
        self.assertEqual(result["summary"]["unique_advisories"], 1)
        self.assertEqual(result["summary"]["unique_cves"], 1)
        self.assertIn("**Avisos únicos:** 1", ar.render_markdown(result))

    def test_reports_coverage_and_unknowns(self) -> None:
        source = report("deps", "cve/CVE-2026-12345", observations={"aliases": ["CVE-2026-12345"]},
                        summary={"coverage": {"dependencies": 3, "manifests_found": 2,
                                               "manifests_parsed": 1, "not_evaluated": ["runtime"]}})
        result = ar.build_assessment([("deps", source)])
        markdown = ar.render_markdown(result)
        self.assertIn("1/2 manifests lidos", markdown)
        self.assertIn("deps: runtime", markdown)
        self.assertIn("não confirma", markdown)

    def test_json_summary_does_not_copy_full_inventory_or_nested_metadata(self) -> None:
        source = report("deps", "cve/CVE-2026-12345", observations={"aliases": ["CVE-2026-12345"]},
                        summary={"coverage": {"dependencies": 1,
                                               "inventory": [{"name": "private-internal-package"}],
                                               "custom_metadata": {"token": "sensitive"}}})
        result = ar.build_assessment([("deps", source)])
        output = json.dumps(result)
        self.assertIn('"dependencies": 1', output)
        self.assertNotIn("private-internal-package", output)
        self.assertNotIn("sensitive", output)

    def test_markdown_escapes_untrusted_title_and_omits_evidence_content(self) -> None:
        item = report("log_triage", "detection/test", title="**token** | <script>",
                      evidence=[{"source": "/var/log/private.log", "locator": "line 4", "excerpt": "secret=abc123"}])
        text = ar.render_markdown(ar.build_assessment([("logs", item)]))
        self.assertIn(r"\*\*token\*\* \| \<script\>", text)
        self.assertIn("private.log:line 4", text)
        self.assertNotIn("abc123", text)

    def test_cli_writes_json_and_markdown_and_rejects_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input.json"
            source.write_text(json.dumps(report("deps", "cve/CVE-2026-12345")), encoding="utf-8")
            output = Path(temp) / "result.json"
            code = ar.main(["--input", f"deps={source}", "--format", "json", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["reports_received"], 1)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = ar.main(["--input", f"deps={source}"])
            self.assertEqual(code, 0)
            self.assertIn("Resumo de segurança", out.getvalue())
            self.assertEqual(err.getvalue(), "")
            with redirect_stdout(io.StringIO()), redirect_stderr(err := io.StringIO()):
                code = ar.main(["--input", f"bad={Path(temp) / 'missing.json'}"])
            self.assertEqual(code, 2)
            self.assertIn("não foi possível ler", err.getvalue())


if __name__ == "__main__":
    unittest.main()
