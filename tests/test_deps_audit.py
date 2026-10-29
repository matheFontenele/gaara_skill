#!/usr/bin/env python3
"""Testes do deps_audit.py — parsers, CVSS, severidade e correlação offline."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import deps_audit as da  # noqa: E402

CORPUS = ROOT / "tests" / "corpus" / "deps-app"
BROKEN = ROOT / "tests" / "corpus" / "deps-broken"


def inventory_of(root: Path) -> da.Inventory:
    files = da.discover(root, [], da.MAX_FILES)
    return da.build_inventory(root, files)


def by_name(inventory: da.Inventory, name: str) -> list[da.Package]:
    return [p for p in inventory.packages if p.name == name]


def run_main(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = da.main(args)
    return code, out.getvalue(), err.getvalue()


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = inventory_of(CORPUS)

    def test_composer_lock_strips_v_prefix(self) -> None:
        monolog = by_name(self.inventory, "monolog/monolog")
        self.assertEqual(len(monolog), 1)
        self.assertEqual(monolog[0].version, "2.9.1")
        self.assertEqual(monolog[0].ecosystem, "packagist")
        self.assertEqual(monolog[0].line, 5)

    def test_package_lock_v3(self) -> None:
        lodash = by_name(self.inventory, "lodash")
        self.assertEqual([p.version for p in lodash], ["4.17.20"])
        express = by_name(self.inventory, "express")
        self.assertEqual([p.version for p in express], ["4.18.2"])

    def test_dev_dependency_marked(self) -> None:
        jsdom = by_name(self.inventory, "jsdom")
        self.assertEqual([p.scope for p in jsdom], ["dev"])

    def test_requirements_pinned_and_unpinned(self) -> None:
        pinned = by_name(self.inventory, "requests")
        self.assertEqual([p.version for p in pinned], ["2.19.0"])
        self.assertTrue(pinned[0].pinned)
        unpinned = [p for p in self.inventory.unpinned if p.name == "urllib3"]
        self.assertEqual(len(unpinned), 1)
        self.assertFalse(unpinned[0].pinned)

    @unittest.skipIf(da.tomllib is None, "tomllib requer Python 3.11+")
    def test_poetry_and_cargo(self) -> None:
        self.assertEqual([p.version for p in by_name(self.inventory, "flask")], ["1.0.0"])
        self.assertEqual([p.version for p in by_name(self.inventory, "time")], ["0.1.42"])

    def test_go_sum_dedup(self) -> None:
        modules = by_name(self.inventory, "golang.org/x/text")
        self.assertEqual([p.version for p in modules], ["v0.3.6"])

    def test_gemfile_lock(self) -> None:
        self.assertEqual([p.version for p in by_name(self.inventory, "nokogiri")], ["1.10.0"])
        self.assertEqual([p.version for p in by_name(self.inventory, "rack")], ["2.0.9"])

    def test_pom_resolves_property(self) -> None:
        log4j = by_name(self.inventory, "org.apache.logging.log4j:log4j-core")
        self.assertTrue(log4j)
        self.assertTrue(all(p.version == "2.14.1" for p in log4j))
        self.assertIn("pom.xml", {p.source for p in log4j})
        managed = [p for p in self.inventory.packages + self.inventory.unpinned
                   if p.name == "com.example:managed-without-version"]
        self.assertEqual(len(managed), 1)
        self.assertFalse(managed[0].pinned)

    def test_gradle_lockfile(self) -> None:
        names = [p.name for p in self.inventory.packages if p.source == "gradle.lockfile"]
        self.assertIn("org.apache.logging.log4j:log4j-core", names)

    def test_nuget_lock(self) -> None:
        self.assertEqual([p.version for p in by_name(self.inventory, "Newtonsoft.Json")],
                         ["12.0.3"])

    def test_dockerfile_registry_port_and_scratch(self) -> None:
        images = self.inventory.docker_images
        self.assertEqual(len(images), 1)  # scratch é ignorado
        self.assertEqual(images[0].name, "registry.internal:5000/base/php")
        self.assertEqual(images[0].version, "8.1-fpm")

    def test_node_modules_pruned(self) -> None:
        self.assertEqual(by_name(self.inventory, "should-not-be-read"), [])
        sources = {m.path for m in self.inventory.manifests}
        self.assertFalse(any("node_modules" in source for source in sources))

    def test_broken_manifest_is_declared(self) -> None:
        broken = inventory_of(BROKEN)
        self.assertEqual(len(broken.manifests), 1)
        self.assertFalse(broken.manifests[0].parsed)
        findings = da.inventory_findings(broken, BROKEN)
        gaps = [f for f in findings if f["category"] == "supply-chain/inventory-gap"]
        self.assertTrue(gaps)
        self.assertTrue(gaps[0]["evidence"][0]["source"].endswith("packages.lock.json"))

    def test_no_manifest_declares_not_evaluated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            empty = inventory_of(Path(temp))
            findings = da.inventory_findings(empty, Path(temp))
            self.assertTrue(any(f["title"].startswith("Nenhum manifest") for f in findings))


class TempParserTests(unittest.TestCase):
    def _parse(self, name: str, content: str) -> list[da.Package]:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / name
            path.write_text(content, encoding="utf-8")
            return da.PARSERS[name][1](path)

    def test_yarn_v1(self) -> None:
        packages = self._parse("yarn.lock", (
            '# yarn lockfile v1\n\n'
            'lodash@^4.17.0, lodash@^4.17.20:\n'
            '  version "4.17.20"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"\n\n'
            '"@babel/core@^7.0.0":\n'
            '  version "7.24.0"\n'
        ))
        found = {p.name: p.version for p in packages}
        self.assertEqual(found["lodash"], "4.17.20")
        self.assertEqual(found["@babel/core"], "7.24.0")

    def test_yarn_berry(self) -> None:
        packages = self._parse("yarn.lock", (
            '__metadata:\n  version: 6\n\n'
            '"lodash@npm:^4.17.0":\n'
            '  version: 4.17.21\n'
            '  resolution: "lodash@npm:4.17.21"\n'
        ))
        self.assertEqual([p.version for p in packages], ["4.17.21"])

    def test_pnpm_lock_scoped_and_peer_suffix(self) -> None:
        packages = self._parse("pnpm-lock.yaml", (
            "lockfileVersion: '9.0'\n\n"
            "packages:\n"
            "  /lodash@4.17.20:\n"
            "    resolution: {integrity: sha512-fixture}\n"
            "  /@babel/core@7.24.0(esbuild@0.20.0):\n"
            "    resolution: {integrity: sha512-fixture}\n"
        ))
        found = {p.name: p.version for p in packages}
        self.assertEqual(found["lodash"], "4.17.20")
        self.assertEqual(found["@babel/core"], "7.24.0")

    def test_requirements_markers_and_extras(self) -> None:
        packages = self._parse("requirements.txt", (
            "django[argon2]==3.2.0 ; python_version >= '3.8'\n"
            "requests===2.19.0\n"
            "-r other.txt\n"
        ))
        found = {p.name: p.version for p in packages}
        self.assertEqual(found["django"], "3.2.0")
        self.assertEqual(found["requests"], "2.19.0")

    def test_pom_ignores_dependency_management_and_plugins(self) -> None:
        packages = self._parse("pom.xml", """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><jackson.version>2.15.0</jackson.version></properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
      <dependency>
        <groupId>only.managed</groupId>
        <artifactId>not-a-real-dep</artifactId>
        <version>9.9.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
  <build><plugins><plugin><dependencies>
    <dependency>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-plugin-dep</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies></plugin></plugins></build>
</project>
""")
        found = {p.name: p for p in packages}
        self.assertEqual(set(found), {"com.fasterxml.jackson.core:jackson-databind"})
        self.assertEqual(found["com.fasterxml.jackson.core:jackson-databind"].version, "2.15.0")
        self.assertTrue(found["com.fasterxml.jackson.core:jackson-databind"].pinned)

    def test_gemfile_platform_suffix_is_normalized(self) -> None:
        packages = self._parse("Gemfile.lock", (
            "GEM\n  specs:\n"
            "    nokogiri (1.16.0-x86_64-linux)\n"
            "    ffi (1.17.0-java)\n"
        ))
        found = {p.name: p.version for p in packages}
        self.assertEqual(found["nokogiri"], "1.16.0")
        self.assertEqual(found["ffi"], "1.17.0")


class CvssTests(unittest.TestCase):
    def test_spec_examples(self) -> None:
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(da.cvss_v3_base_score(vector), expected)

    def test_rejects_v4_and_garbage(self) -> None:
        self.assertIsNone(da.cvss_v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"))
        self.assertIsNone(da.cvss_v3_base_score(""))

    def test_thresholds(self) -> None:
        self.assertEqual(da.cvss_to_severity(9.0), "critico")
        self.assertEqual(da.cvss_to_severity(8.9), "alto")
        self.assertEqual(da.cvss_to_severity(7.0), "alto")
        self.assertEqual(da.cvss_to_severity(4.0), "medio")
        self.assertEqual(da.cvss_to_severity(3.9), "baixo")


class NvdTests(unittest.TestCase):
    def test_prefers_v31(self) -> None:
        cve = {"metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                                            "vectorString": "CVSS:3.1/AV:N"}}],
        }}
        self.assertEqual(da.nvd_metrics(cve), (9.8, "CVSS:3.1/AV:N"))

    def test_missing_metrics(self) -> None:
        self.assertEqual(da.nvd_metrics({}), (None, None))
        self.assertEqual(da.nvd_metrics({"metrics": {"cvssMetricV31": []}}), (None, None))


class SeverityTests(unittest.TestCase):
    def _hit(self, **kwargs) -> da.Hit:
        package = da.Package("npm", "x", "1.0.0", "package-lock.json", 1)
        base = da.Hit(package=package, osv_id="GHSA-x", cve_id="CVE-2026-0001",
                      summary="x", fixed="1.0.1")
        for key, value in kwargs.items():
            setattr(base, key, value)
        return base

    def test_kev_escalates(self) -> None:
        hit = self._hit(cvss_score=5.3, cvss_source="OSV/CVSS", kev=True)
        severity, rationale = da.hit_severity(hit, internet_exposed=False, epss_threshold=0.1)
        self.assertEqual(severity, "alto")
        self.assertTrue(any("KEV" in item for item in rationale))

    def test_epss_only_escalates_when_exposed(self) -> None:
        hit = self._hit(cvss_score=5.3, cvss_source="test", epss=0.9)
        unexposed, _ = da.hit_severity(hit, internet_exposed=False, epss_threshold=0.1)
        exposed, _ = da.hit_severity(hit, internet_exposed=True, epss_threshold=0.1)
        self.assertEqual(unexposed, "medio")
        self.assertEqual(exposed, "alto")

    def test_never_downgrades(self) -> None:
        hit = self._hit(cvss_score=9.8, cvss_source="test", kev=False, epss=0.0001)
        severity, _ = da.hit_severity(hit, internet_exposed=True, epss_threshold=0.1)
        self.assertEqual(severity, "critico")

    def test_no_cvss_uses_conservative_default(self) -> None:
        hit = self._hit()
        severity, rationale = da.hit_severity(hit, internet_exposed=False, epss_threshold=0.1)
        self.assertEqual(severity, "medio")
        self.assertTrue(any("conservadora" in item for item in rationale))


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.cache = Path(cls.temp.name)
        cls.inventory = inventory_of(CORPUS)
        cls.packages = [p for p in cls.inventory.packages if p.scope != "dev"]
        queries, index = da.osv_payload(cls.packages)
        cls.index = index
        cls.payload = {"queries": queries}
        cls.results = [cls._result_for(package) for package in index]
        cls.osv_body = {"results": cls.results}
        da.cache_store(cls.cache / "osv", da.osv_cache_url(cls.payload), cls.osv_body)
        cls.cves = sorted({cve for result in cls.results for cve in
                           [da.parse_osv_vuln(v, index[i]).cve_id
                            for i, r in enumerate(cls.results) for v in r.get("vulns") or []]
                           if cve})
        da.cache_store(cls.cache / "kev", da.KEV_URL,
                       {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
        da.cache_store(cls.cache / "epss", da.epss_cache_url(cls.cves),
                       {"data": [{"cve": "CVE-2021-44228", "epss": "0.97"},
                                 {"cve": "CVE-2021-23337", "epss": "0.02"}]})

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    @staticmethod
    def _result_for(package: da.Package) -> dict:
        if (package.name, package.version) == ("lodash", "4.17.20"):
            return {"vulns": [{
                "id": "GHSA-35jh-r3h4-6jhm",
                "aliases": ["CVE-2021-23337"],
                "summary": "Command injection in lodash template",
                "severity": [{"type": "CVSS_V3",
                              "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "lodash"},
                              "ranges": [{"type": "ECOSYSTEM",
                                          "events": [{"fixed": "4.17.21"}]}]}],
                "references": [{"url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}],
                "published": "2021-02-15T13:15:00Z",
            }]}
        if package.name.startswith("org.apache.logging.log4j"):
            return {"vulns": [{
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": ["CVE-2021-44228"],
                "summary": "Remote code execution in Log4j2",
                "severity": [{"type": "CVSS_V3",
                              "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"name": "log4j-core"},
                              "ranges": [{"type": "ECOSYSTEM",
                                          "events": [{"fixed": "2.15.0"}]}]}],
                "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
                "published": "2021-12-10T00:00:00Z",
            }]}
        if package.name == "requests" and package.version == "2.19.0":
            return {"vulns": [{
                "id": "GHSA-9hjg-9r4m-mvj7",
                "aliases": ["CVE-2018-18074"],
                "summary": "Credentials leak on redirect",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "requests"},
                              "ranges": [{"type": "ECOSYSTEM",
                                          "events": [{"fixed": "2.20.0"}]}]}],
                "references": [{"url": "https://github.com/advisories/GHSA-9hjg-9r4m-mvj7"}],
                "published": "2018-10-10T00:00:00Z",
            }]}
        return {}

    def _run(self, extra: list[str]) -> tuple[int, dict]:
        args = [str(CORPUS), "--online", "--offline", "--nvd", "off",
                "--cache-dir", str(self.cache), *extra]
        code, out, err = run_main(args)
        self.assertEqual(err, "", msg=err)
        return code, json.loads(out)

    def test_findings_and_evidence(self) -> None:
        code, result = self._run([])
        self.assertEqual(code, 3)
        self.assertEqual(da.validate(result), [])
        ids = {f["category"] for f in result["findings"]}
        self.assertIn("cve/cve-2021-44228", ids)
        self.assertIn("cve/cve-2021-23337", ids)

        log4j = [f for f in result["findings"] if f["category"] == "cve/cve-2021-44228"][0]
        self.assertEqual(log4j["severity"], "critico")
        self.assertTrue(log4j["observations"]["kev"])
        self.assertAlmostEqual(log4j["observations"]["epss"], 0.97)
        self.assertEqual(log4j["observations"]["fixed_versions"], "2.15.0")
        self.assertEqual(sorted(log4j["observations"]["manifests"]),
                         ["gradle.lockfile", "pom.xml"])
        self.assertEqual(len([f for f in result["findings"]
                              if f["category"] == "cve/cve-2021-44228"]), 1)
        self.assertEqual(log4j["evidence"][0]["source_type"], "api")
        self.assertTrue(log4j["evidence"][0]["url"].startswith("https://osv.dev/"))
        self.assertIsNotNone(log4j["evidence"][0]["retrieved_at"])
        self.assertEqual(log4j["recommendation"]["action"], "patch")
        self.assertTrue(log4j["recommendation"]["requires_approval"])
        self.assertIn("rollback", log4j["recommendation"])

    def test_coverage_is_declared(self) -> None:
        _, result = self._run([])
        coverage = result["summary"]["coverage"]
        self.assertGreater(coverage["dependencies"], 5)
        self.assertLessEqual(len(coverage["inventory"]), coverage["dependencies"] +
                             coverage["docker_images"])
        self.assertEqual(coverage["manifests_failed"], 0)
        self.assertIn("OSV", " ".join(s["name"] for s in coverage["sources"]))
        self.assertTrue(any("A01" in item for item in coverage["not_evaluated"]))
        self.assertTrue(any("Docker" in item for item in coverage["not_evaluated"]))

    def test_inventory_only_does_not_consult_sources(self) -> None:
        code, out, _ = run_main([str(CORPUS), "--format", "json"])
        result = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(result["summary"]["coverage"]["sources"], [])
        self.assertTrue(any("--online" in n for n in result["summary"]["not_observed"]))

    def test_markdown_has_mandatory_blocks(self) -> None:
        code, out, _ = run_main([str(CORPUS), "--online", "--offline", "--nvd", "off",
                                 "--cache-dir", str(self.cache), "--format", "md"])
        self.assertEqual(code, 3)
        for heading in ("## Cobertura", "## Achados", "## Não avaliado"):
            self.assertIn(heading, out)
        self.assertIn("Vulnerabilidade conhecida não é comprometimento", out)

    def test_offline_cache_miss_degrades_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            code, out, _ = run_main([str(CORPUS), "--online", "--offline",
                                     "--cache-dir", empty, "--format", "json"])
            result = json.loads(out)
            self.assertIn(code, (0, 3))
            self.assertTrue(any("OSV indisponível" in item
                                for item in result["summary"]["coverage"]["not_evaluated"]))
            self.assertTrue(any("consulta OSV falhou" in item
                                for item in result["summary"]["not_observed"]))

    def test_stale_cache_is_reported_as_not_observed(self) -> None:
        _, result = self._run([])
        cache_entry = da.cache_path(self.cache / "osv", da.osv_cache_url(self.payload))
        payload = json.loads(cache_entry.read_text(encoding="utf-8"))
        payload["fetched_at"] = "2020-01-01T00:00:00Z"
        cache_entry.write_text(json.dumps(payload), encoding="utf-8")
        _, stale_result = self._run([])
        stale_source = next(s for s in stale_result["summary"]["coverage"]["sources"]
                            if s["name"].startswith("OSV"))
        self.assertTrue(stale_source["stale"])
        self.assertTrue(any("cache vencido" in item
                            for item in stale_result["summary"]["not_observed"]))
        # Restaura a entrada usada pelos demais testes.
        da.cache_store(self.cache / "osv", da.osv_cache_url(self.payload), self.osv_body)

    def test_dev_dependencies_excluded_by_default(self) -> None:
        _, result = self._run([])
        packages = {f.get("observations", {}).get("package")
                    for f in result["findings"] if f["category"].startswith("cve/")}
        self.assertNotIn("jsdom", packages)

    def test_validation_rejects_broken_coverage(self) -> None:
        _, result = self._run([])
        result["summary"]["coverage"]["manifests_failed"] += 1
        errors = da.validate(result)
        self.assertTrue(any("coverage" in item for item in errors), errors)

    def test_sbom_cyclonedx_and_spdx_are_deterministic(self) -> None:
        _, report = self._run([])
        cdx = da.make_sbom(report, "cyclonedx")
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.6")
        self.assertEqual(cdx, da.make_sbom(report, "cyclonedx"))
        self.assertTrue(any(c.get("purl", "").startswith("pkg:npm/lodash@")
                            for c in cdx["components"]))
        spdx = da.make_sbom(report, "spdx")
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(spdx["packages"]), len(report["summary"]["coverage"]["inventory"]))
        self.assertTrue(all(p["downloadLocation"] == "NOASSERTION" for p in spdx["packages"]))

    def test_dev_scope_is_excluded_in_cyclonedx(self) -> None:
        code, output, error = run_main([str(CORPUS), "--include-dev", "--format", "json"])
        self.assertEqual(code, 0, error)
        report = json.loads(output)
        sbom = da.make_sbom(report, "cyclonedx")
        jsdom = next(c for c in sbom["components"] if c["name"] == "jsdom")
        self.assertEqual(jsdom["scope"], "excluded")

    def test_sarif_has_stable_rules_and_results(self) -> None:
        _, report = self._run([])
        sarif = da.sarif_report(report)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertEqual(len(run["results"]), len(report["findings"]))
        critical = next(r for r in run["results"]
                        if r["properties"]["gaara:severity"] == "critico")
        self.assertEqual(critical["level"], "error")

    def test_report_comparison_uses_component_and_finding_identity(self) -> None:
        _, before = self._run([])
        after = json.loads(json.dumps(before))
        after["scan"]["id"] = "later"
        inventory = after["summary"]["coverage"]["inventory"]
        removed_component = next(c for c in inventory if c["name"] == "requests")
        inventory.remove(removed_component)
        inventory.append({"type": "library", "ecosystem": "npm", "name": "new-package",
                          "version": "1.2.3", "scope": "runtime", "pinned": True,
                          "sources": ["package-lock.json"]})
        lodash = next(c for c in inventory if c["name"] == "lodash")
        lodash["version"] = "4.17.21"
        old_vuln = next(f for f in before["findings"]
                        if f["category"] == "cve/cve-2018-18074")
        after["findings"].remove(old_vuln)
        delta = da.compare_reports(before, after)
        self.assertEqual([c["name"] for c in delta["components"]["added"]], ["new-package"])
        self.assertEqual([c["name"] for c in delta["components"]["removed"]], ["requests"])
        self.assertEqual(len(delta["components"]["updated"]), 1)
        self.assertEqual(delta["components"]["updated"][0]["before"]["name"], "lodash")
        self.assertEqual(len(delta["vulnerabilities"]["resolved"]), 1)
        self.assertEqual(delta["vulnerabilities"]["persistent"], 2)
        self.assertIn("lodash: 4.17.20 → 4.17.21",
                      da.render_comparison_markdown(delta))

    def test_comparison_ignores_source_timestamp_for_coverage(self) -> None:
        _, before = self._run([])
        after = json.loads(json.dumps(before))
        for source in after["summary"]["coverage"]["sources"]:
            if source.get("retrieved_at"):
                source["retrieved_at"] = "2099-01-01T00:00:00Z"
        delta = da.compare_reports(before, after)
        self.assertFalse(delta["coverage_changed"])

    def test_cli_emits_sarif_and_sbom_json(self) -> None:
        for fmt in ("sarif", "cyclonedx", "spdx"):
            with self.subTest(fmt=fmt):
                code, output, error = run_main([str(CORPUS), "--format", fmt])
                self.assertEqual(code, 0, error)
                parsed = json.loads(output)
                if fmt == "sarif":
                    self.assertEqual(parsed["version"], "2.1.0")
                elif fmt == "cyclonedx":
                    self.assertEqual(parsed["bomFormat"], "CycloneDX")
                else:
                    self.assertEqual(parsed["spdxVersion"], "SPDX-2.3")

    def test_cli_compares_saved_json_reports(self) -> None:
        report = self._run([])[1]
        with tempfile.TemporaryDirectory() as temp:
            before = Path(temp) / "before.json"
            after = Path(temp) / "after.json"
            before.write_text(json.dumps(report), encoding="utf-8")
            after.write_text(json.dumps(report), encoding="utf-8")
            code, output, error = run_main(["--compare", str(before), str(after)])
            self.assertEqual(code, 0, error)
            delta = json.loads(output)
            self.assertEqual(delta["components"]["added"], [])
            self.assertEqual(delta["components"]["removed"], [])
            code, markdown, error = run_main(["--compare", str(before), str(after),
                                              "--format", "md"])
            self.assertEqual(code, 0, error)
            self.assertIn("## Vulnerabilidades", markdown)

    def test_broken_manifest_blocks_clean_verdict(self) -> None:
        code, out, _ = run_main([str(BROKEN), "--format", "json"])
        result = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(result["summary"]["verdict"], "atencao")
        self.assertTrue(any(f["category"] == "supply-chain/inventory-gap"
                            for f in result["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
