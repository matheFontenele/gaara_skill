#!/usr/bin/env python3
"""assessment_report.py — resume relatórios Gaara para decisão não técnica.

Somente leitura dos relatórios JSON informados. Não executa scanners, não acessa
a rede, não abre o projeto e não altera hosts. A saída separa sinais observados,
impactos possíveis e o que ainda precisa de confirmação.

Uso:
    python3 assessment_report.py --input api=/tmp/api-deps.json \
        --input web=/tmp/web-deps.json --input php=/tmp/php-audit.json
    python3 assessment_report.py --input api=/tmp/api.json --format json \
        --output /tmp/resumo.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

VERSION = "1.0.0"
MAX_INPUT_BYTES = 64 * 1024 * 1024
SEVERITY_ORDER = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3}
SEVERITY_LABEL = {"critico": "Crítico", "alto": "Alto", "medio": "Médio", "baixo": "Baixo"}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MARKDOWN_RE = re.compile(r"([\\`*_{}\[\]()#+!|<>])")


def plain(value: Any, limit: int = 400) -> str:
    text = ANSI_RE.sub("", str(value or ""))
    text = CONTROL_RE.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def md(value: Any, limit: int = 400) -> str:
    return MARKDOWN_RE.sub(r"\\\1", plain(value, limit))


def load_report(spec: str) -> tuple[str, dict[str, Any]]:
    if "=" in spec:
        label, filename = spec.split("=", 1)
    else:
        filename = spec
        label = Path(filename).stem
    label = plain(label, 80)
    if not label or not filename:
        raise ValueError("use --input rótulo=caminho.json ou --input caminho.json")
    path = Path(filename)
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"relatório acima do limite de {MAX_INPUT_BYTES} bytes")
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"não foi possível ler {label}: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError(f"{label}: raiz JSON precisa ser um objeto")
    if not isinstance(report.get("findings", []), list):
        raise ValueError(f"{label}: findings precisa ser uma lista")
    if not isinstance(report.get("scan", {}), dict) or not isinstance(report.get("summary", {}), dict):
        raise ValueError(f"{label}: estrutura scan/summary inválida")
    return label, report


def _cve_id(finding: dict[str, Any]) -> str | None:
    category = str(finding.get("category", ""))
    match = re.search(r"CVE-\d{4}-\d{4,}", category, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    observations = finding.get("observations") or {}
    for alias in observations.get("aliases") or []:
        match = re.search(r"CVE-\d{4}-\d{4,}", str(alias), re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return None


def _advisory_id(finding: dict[str, Any]) -> str:
    cve = _cve_id(finding)
    if cve:
        return cve
    observations = finding.get("observations") or {}
    aliases = observations.get("aliases") or []
    for alias in aliases:
        if str(alias).upper().startswith("GHSA-"):
            return plain(alias, 80).upper()
    title = str(finding.get("title", ""))
    match = re.match(r"(GHSA-[\w-]+|OSV-[\w-]+)", title, re.IGNORECASE)
    return match.group(1).upper() if match else ""


def _package(finding: dict[str, Any]) -> tuple[str, str]:
    observations = finding.get("observations") or {}
    name = str(observations.get("package") or "")
    version = str(observations.get("installed") or "")
    if name:
        return name, version
    title = str(finding.get("title", ""))
    match = re.search(r"\bem\s+(.+?)\s+([^\s]+)$", title)
    return (match.group(1), match.group(2)) if match else ("", "")


def _finding_identity(label: str, finding: dict[str, Any]) -> tuple[str, ...]:
    category = str(finding.get("category", ""))
    advisory = _advisory_id(finding)
    package, version = _package(finding)
    if advisory:
        return ("advisory", advisory, package.lower(), version)
    title = plain(finding.get("title", ""), 240).lower()
    evidence = finding.get("evidence") or []
    locator = plain(evidence[0].get("locator", ""), 120).lower() if evidence else ""
    # IDs F-001 are regenerated per report; do not use them as cross-report identity.
    local_disambiguator = "" if locator else str(finding.get("id", ""))
    return (label.lower(), category.lower(), title, locator, local_disambiguator)


def _priority(finding: dict[str, Any]) -> tuple[str, str]:
    severity = str(finding.get("severity", "baixo"))
    observations = finding.get("observations") or {}
    if severity in {"critico", "alto"}:
        if observations.get("kev"):
            return "Investigar primeiro", "Há um achado alto/crítico associado a falha no catálogo de exploração ativa. Isso não prova ataque contra este sistema."
        return "Investigar primeiro", "O relatório classifica este achado como alto/crítico. Confirme o impacto e o escopo antes de alterar produção."
    if severity == "medio":
        return "Investigar e planejar", "Há um sinal relevante que merece confirmação; o relatório não demonstra, por si só, exploração ou impacto em produção."
    return "Acompanhar ou corrigir em lote", "O relatório classifica este achado como baixo; mantenha a evidência e trate conforme o contexto do projeto."


def _plain_finding(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", ""))
    package, version = _package(finding)
    if category.startswith("cve/") or category == "supply-chain/known-vulnerability":
        item = f"{package} {version}".strip() or "um componente"
        advisory = _advisory_id(finding)
        reference = f" ({advisory})" if advisory else ""
        return (f"O relatório relaciona {item}{reference} a um aviso de segurança. "
                "Isso confirma a associação registrada na análise; não confirma que a mesma versão está em produção, "
                "que o recurso afetado é usado ou que houve exploração.")
    if category.startswith("code/") or category.startswith("legacy/"):
        return ("A análise encontrou um padrão de código ou runtime que merece revisão. "
                "O padrão não prova, isoladamente, que um atacante consiga explorá-lo.")
    if category.startswith("detection/"):
        return ("O relatório encontrou atividade compatível com este sinal nos registros analisados. "
                "Isso não confirma, por si só, que uma tentativa teve sucesso.")
    if category.startswith("posture/"):
        return ("A verificação observou uma configuração que merece atenção neste escopo. "
                "Confirme que o relatório corresponde ao servidor e ambiente que você quer avaliar.")
    if category.startswith("ir/"):
        return ("O relatório encontrou um sinal que deve ser investigado preservando as evidências. "
                "Não conclua comprometimento sem correlação suficiente.")
    return "O relatório contém um achado para revisão; confirme o escopo e a evidência antes de agir."


def _evidence_refs(finding: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for evidence in finding.get("evidence") or []:
        source = str(evidence.get("source") or "")
        if source.startswith("/"):
            source = Path(source).name
        locator = plain(evidence.get("locator", ""), 120)
        if source or locator:
            ref = f"{source}:{locator}" if locator else source
            if ref not in refs:
                refs.append(ref)
    return refs[:4]


def _safe_coverage(coverage: dict[str, Any]) -> dict[str, Any]:
    # Keep only scalar counts needed for the summary; dependency inventories,
    # source URLs, and arbitrary nested metadata belong in the original report.
    allowed = {
        "dependencies", "dependencies_unpinned", "manifests_found",
        "manifests_parsed", "manifests_failed", "queried", "with_advisory",
        "docker_images",
    }
    return {
        key: value for key, value in coverage.items()
        if key in allowed and isinstance(value, (str, int, float, bool, type(None)))
    }


def build_assessment(reports: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    report_summaries: list[dict[str, Any]] = []
    not_evaluated: list[str] = []
    not_observed: list[str] = []
    counts = Counter({level: 0 for level in SEVERITY_ORDER})
    kev_unique: set[str] = set()
    cves: set[str] = set()
    advisories: set[str] = set()

    for label, report in reports:
        scan = report.get("scan", {})
        summary = report.get("summary", {})
        coverage = summary.get("coverage") or {}
        if not isinstance(coverage, dict):
            coverage = {}
        scan_limits = scan.get("limits") or {}
        findings = report.get("findings") or []
        report_summaries.append({
            "label": label,
            "tool": plain(scan.get("tool", "ferramenta não identificada"), 80),
            "finished_at": plain(scan.get("finished_at", ""), 40),
            "finding_records": len(findings),
            "coverage": _safe_coverage(coverage),
            "scan_limits": scan_limits,
            "score": summary.get("score"),
            "not_observed": [plain(x, 240) for x in (summary.get("not_observed") or [])[:8]],
            "not_evaluated": [plain(x, 240) for x in (coverage.get("not_evaluated") or [])[:8]],
        })
        for note in report_summaries[-1]["not_evaluated"]:
            not_evaluated.append(f"{label}: {note}")
        for note in report_summaries[-1]["not_observed"]:
            not_observed.append(f"{label}: {note}")

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "baixo"))
            if severity not in counts:
                severity = "baixo"
            identity = _finding_identity(label, finding)
            observations = finding.get("observations") or {}
            advisory = _advisory_id(finding)
            if advisory:
                advisories.add(advisory)
            if advisory.startswith("CVE-"):
                cves.add(advisory)
            if observations.get("kev"):
                kev_unique.add(advisory or identity[-1])
            item = grouped.get(identity)
            if item is None:
                action, explanation = _priority(finding)
                package, version = _package(finding)
                item = {
                    "label": label,
                    "severity": severity,
                    "confidence": str(finding.get("confidence", "baixa")),
                    "title": plain(finding.get("title", "Achado sem título"), 300),
                    "category": plain(finding.get("category", ""), 120),
                    "advisory_id": advisory or None,
                    "package": plain(package, 180),
                    "version": plain(version, 100),
                    "priority": action,
                    "priority_explanation": explanation,
                    "plain_explanation": _plain_finding(finding),
                    "evidence": _evidence_refs(finding),
                    "sources": [label],
                    "occurrences": 1,
                    "kev": bool(observations.get("kev")),
                }
                grouped[identity] = item
            else:
                item["occurrences"] += 1
                if label not in item["sources"]:
                    item["sources"].append(label)
                if SEVERITY_ORDER[severity] < SEVERITY_ORDER[item["severity"]]:
                    item["severity"] = severity
                item["kev"] = item["kev"] or bool(observations.get("kev"))
                action, explanation = _priority({
                    "severity": item["severity"],
                    "observations": {"kev": item["kev"]},
                })
                item["priority"] = action
                item["priority_explanation"] = explanation

    findings = sorted(grouped.values(), key=lambda item: (
        SEVERITY_ORDER[item["severity"]],
        0 if item.get("advisory_id") in kev_unique else 1,
        item["label"].lower(),
        item["title"].lower(),
    ))
    for item in findings:
        counts[item["severity"]] += 1

    high_or_critical = counts["critico"] + counts["alto"]
    if high_or_critical:
        headline = (f"Os relatórios fornecidos contêm {high_or_critical} achado(s) classificado(s) como alto/crítico. "
                   "Isso indica prioridade de investigação; não confirma exploração nem impacto em produção.")
    elif findings:
        headline = (f"Os relatórios fornecidos contêm {len(findings)} achado(s), sem classificação alta/crítica. "
                    "Ainda é necessário considerar o escopo e as lacunas de cada análise.")
    else:
        headline = ("Os relatórios fornecidos não contêm achados. Isso não é um atestado de segurança: "
                    "a conclusão vale somente para o que foi analisado e para as fontes consultadas.")

    if findings:
        recommended_next = findings[0]["priority_explanation"]
    else:
        recommended_next = "Revise a cobertura e confirme se os relatórios correspondem ao código e ambiente desejados."

    return {
        "assessment_version": VERSION,
        "summary": {
            "headline": headline,
            "reports_received": len(reports),
            "unique_findings": len(findings),
            "unique_advisories": len(advisories),
            "severity_counts": dict(counts),
            "unique_cves": len(cves),
            "findings_with_kev": len(kev_unique),
            "next_step": recommended_next,
            "not_a_compromise_verdict": True,
        },
        "reports": report_summaries,
        "findings": findings,
        "not_evaluated": list(dict.fromkeys(not_evaluated)),
        "not_observed": list(dict.fromkeys(not_observed)),
        "limitations": [
            "Este arquivo apenas resume os relatórios informados; não executa scanners nem valida seus resultados.",
            "Relatório local não confirma a versão implantada, exposição real, uso de recurso vulnerável ou exploração.",
            "Achado ausente de um relatório não prova correção; compare escopo, cobertura, data e fontes.",
        ],
    }


def render_markdown(assessment: dict[str, Any]) -> str:
    summary = assessment["summary"]
    lines = [
        "# Resumo de segurança para decisão",
        "",
        "## Resumo para você",
        "",
        summary["headline"],
        "",
        "Este documento resume relatórios existentes; não executou análise adicional nem alterou sistemas.",
        "",
        "## O que os relatórios encontraram",
        "",
        (f"**Achados únicos:** {summary['unique_findings']} · "
         f"**Avisos únicos:** {summary['unique_advisories']} · "
         f"**CVEs identificados:** {summary['unique_cves']} · "
         f"**Achados KEV:** {summary['findings_with_kev']}"),
        "",
        "| Gravidade técnica | Quantidade | Como interpretar |\n|---|---:|---|",
        f"| Crítica | {summary['severity_counts']['critico']} | Exige confirmação e prioridade alta; não significa que houve ataque. |",
        f"| Alta | {summary['severity_counts']['alto']} | Investigue antes dos itens médios; valide exposição e uso. |",
        f"| Média | {summary['severity_counts']['medio']} | Confirme a condição e planeje tratamento compatível. |",
        f"| Baixa | {summary['severity_counts']['baixo']} | Acompanhe ou agrupe com correções de baixo risco. |",
        "",
    ]
    if findings := assessment["findings"]:
        lines += ["## Prioridades", ""]
        for index, finding in enumerate(findings[:3], 1):
            lines += [
                f"### {index}. [{SEVERITY_LABEL[finding['severity']]}] {md(finding['title'], 240)}",
                "",
                f"**O que significa:** {md(finding['plain_explanation'])}",
                f"**Prioridade:** {md(finding['priority'])} — {md(finding['priority_explanation'])}",
                f"**Confiança do relatório:** {md(finding['confidence'])}.",
                f"**Relatório(s):** {', '.join(md(x, 80) for x in finding['sources'])}.",
            ]
            if finding["evidence"]:
                lines.append("**Referência:** " + ", ".join(f"`{md(x, 180)}`" for x in finding["evidence"]))
            if finding["advisory_id"]:
                lines.append(f"**Identificador técnico:** `{md(finding['advisory_id'], 80)}`.")
            lines.append("")
        if len(findings) > 3:
            lines += [f"Há mais {len(findings) - 3} achado(s) no anexo técnico JSON ou nos relatórios originais.", ""]
    else:
        lines += ["Nenhum achado foi incluído nos relatórios recebidos. Isso não prova ausência de vulnerabilidades.", ""]

    lines += ["## De onde veio este resumo", "", "| Relatório | Ferramenta | Data | Registros | Cobertura declarada |",
              "|---|---|---|---:|---|"]
    for report in assessment["reports"]:
        coverage = report["coverage"] or {}
        coverage_text = []
        if "dependencies" in coverage:
            coverage_text.append(f"{coverage['dependencies']} dependências")
        if "manifests_found" in coverage:
            coverage_text.append(f"{coverage.get('manifests_parsed', '?')}/{coverage['manifests_found']} manifests lidos")
        limits = report.get("scan_limits") or {}
        if limits.get("php_files") is not None:
            coverage_text.append(f"{limits['php_files']} arquivos PHP")
        if isinstance(report.get("score"), (int, float)):
            coverage_text.append(f"score de host {report['score']} (cobertura parcial possível)")
        lines.append(
            f"| {md(report['label'], 80)} | {md(report['tool'], 80)} | "
            f"{md(report['finished_at'] or 'sem data', 40)} | {report['finding_records']} | "
            f"{md('; '.join(coverage_text) or 'ver anexo / relatório original', 160)} |"
        )
    lines += ["", "## O que ainda não foi avaliado", ""]
    if assessment["not_evaluated"]:
        lines.extend(f"- {md(note, 240)}" for note in assessment["not_evaluated"][:12])
    else:
        lines.append("Os relatórios recebidos não declararam lacunas estruturadas nesta seção.")
    lines += ["", "## O que não foi observado nos dados analisados", ""]
    if assessment["not_observed"]:
        lines.extend(f"- {md(note, 240)}" for note in assessment["not_observed"][:12])
    else:
        lines.append("Os relatórios não trouxeram itens estruturados de 'não observado'.")
    lines += ["", "## Próximo passo seguro", "", md(summary["next_step"]), "",
              "Antes de atualizar dependências, alterar configuração ou rotacionar credenciais, confirme o ambiente afetado, compatibilidade e autorização.",
              "", "## Limites deste resumo", ""]
    lines.extend(f"- {md(note, 260)}" for note in assessment["limitations"])
    lines += ["", "## Anexo técnico resumido", "", "| Prioridade | Achado | Categoria | Ocorrências | Evidência de referência |",
              "|---|---|---|---:|---|"]
    for finding in findings:
        refs = ", ".join(finding["evidence"]) or "sem referência estruturada"
        lines.append(
            f"| {SEVERITY_LABEL[finding['severity']]} | {md(finding['title'], 180)} | "
            f"`{md(finding['category'], 100)}` | {finding['occurrences']} | {md(refs, 200)} |"
        )
    lines += ["", "> Para a evidência completa, fontes e trechos redigidos, consulte o relatório JSON original. Este resumo não substitui esses registros.", ""]
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="assessment_report.py",
        description="Resume relatórios JSON da Gaara para uma decisão compreensível.",
        epilog="Somente lê os JSONs informados; não executa scanners nem acessa a rede.",
    )
    parser.add_argument("--input", action="append", required=True, metavar="[RÓTULO=]ARQUIVO.json",
                        help="relatório JSON existente; repetir para combinar análises")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--output", help="arquivo de saída; padrão: stdout")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        reports = [load_report(spec) for spec in args.input]
        labels = [label.lower() for label, _ in reports]
        if len(set(labels)) != len(labels):
            raise ValueError("rótulos de --input precisam ser únicos")
        assessment = build_assessment(reports)
        output = (render_markdown(assessment) if args.format == "md"
                  else json.dumps(assessment, ensure_ascii=False, indent=2))
        if args.output:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    except (OSError, ValueError) as exc:
        print(f"não foi possível montar o resumo: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
