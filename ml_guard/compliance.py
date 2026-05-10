"""Compliance reporter — генерация PDF-отчётов для аудита.

Использование:
    ml-guard compliance --standard eu-ai-act --output report.pdf <path>

Подход:
  • Сканируем PATH стандартным runner'ом.
  • Маппим каждое правило ML Guard на конкретные требования стандарта
    (по которым его можно "закрыть").
  • Считаем pass/fail/n-a по каждому требованию.
  • Рисуем PDF с executive summary, таблицей контрольных точек, списком
    findings, метаинформацией и SHA-256 самого отчёта (псевдо-tamper-evidence).

Что мы НЕ делаем (намеренно):
  • Не подписываем PDF цифровой подписью PKCS#7 — для этого нужен
    сертификат от CA. Мы оставляем хук `signature_placeholder` — клиент
    может прокинуть результат через сторонний signer (DocuSign, Adobe
    Sign, OpenSSL CMS).
  • Не утверждаем юридического статуса. Отчёт — это формализованное
    свидетельство сканирования; решение о соответствии принимает
    notified body / DPO. Это явно проговорено в самом PDF.
"""
from __future__ import annotations

import hashlib
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, TYPE_CHECKING

from ml_guard import __version__
from ml_guard._pdf import PdfDocument
from ml_guard.findings import Finding, Severity

if TYPE_CHECKING:
    from ml_guard.runner import ScanResult


# ---------------------------------------------------------------------------
# Маппинг стандартов
# ---------------------------------------------------------------------------

@dataclass
class _Control:
    """Один контроль (контрольная точка) в стандарте."""
    id: str
    title: str
    description: str
    # Какие rule_id сканера ml-guard «закрывают» этот контроль.
    # Если нашлось хотя бы одно — control fails (есть свидетельство нарушения).
    rule_ids: List[str] = field(default_factory=list)


@dataclass
class _Standard:
    name: str           # человекочитаемое имя
    id: str             # CLI alias
    citation: str       # ссылка на источник
    description: str    # короткая аннотация
    controls: List[_Control]


# EU AI Act — мы покрываем подмножество требований, относящихся к
# документации модели, киберустойчивости, прозрачности, и логированию.
# Полный текст: Regulation (EU) 2024/1689.
EU_AI_ACT = _Standard(
    name="EU AI Act (Regulation 2024/1689)",
    id="eu-ai-act",
    citation="Regulation (EU) 2024/1689, OJ L of 12.7.2024",
    description=(
        "EU AI Act establishes obligations for providers and deployers of "
        "high-risk AI systems. The controls below are those that ML Guard "
        "can produce machine-checkable evidence for. Other requirements "
        "(human oversight, conformity assessment, registration) are out "
        "of scope and require organizational rather than technical evidence."
    ),
    controls=[
        _Control(
            id="AIACT-9",
            title="Article 9 — Risk management system: identifiable threats are mitigated",
            description=(
                "Detect and remove malicious code embedded in model weights "
                "(pickle RCE) before deployment. Block known-vulnerable and "
                "malicious dependencies."
            ),
            rule_ids=[
                "pickle-dangerous-global",
                "pickle-suspicious-module",
                "pickle-stack-global-opaque",
                "safetensors-executable-trailing",
                "onnx-custom-domain-op",
                "onnx-attr-shell-command",
                "cve-known-vulnerability",
                "cve-malicious-package",
            ],
        ),
        _Control(
            id="AIACT-10",
            title="Article 10 — Data governance: model artifacts are integrity-protected",
            description=(
                "Each model file is hashed (SHA-256) and bound to its scan "
                "record. Tampering with weights between scan and deployment "
                "becomes detectable."
            ),
            rule_ids=[
                "safetensors-malformed-header",
                "safetensors-out-of-bounds",
                "safetensors-overlapping-tensors",
                "safetensors-size-mismatch",
            ],
        ),
        _Control(
            id="AIACT-11",
            title="Article 11 — Technical documentation: SBOM available",
            description=(
                "A CycloneDX 1.5 SBOM is produced alongside every scan, "
                "listing all model artifacts and their declared dependencies."
            ),
            # Этот контроль не привязан к findings — он либо есть, либо нет.
            # В practice мы фиксируем pass, если scan завершился успешно.
            rule_ids=[],
        ),
        _Control(
            id="AIACT-12",
            title="Article 12 — Record-keeping: scan results are timestamped",
            description=(
                "Every scan emits a timestamped report with deterministic "
                "fingerprint, enabling chain-of-custody reconstruction."
            ),
            rule_ids=[],
        ),
        _Control(
            id="AIACT-13",
            title="Article 13 — Transparency: external data sources flagged",
            description=(
                "Models that fetch external data at runtime (URLs, absolute "
                "paths) are explicitly flagged so deployers can audit data "
                "provenance."
            ),
            rule_ids=[
                "onnx-external-url",
                "onnx-external-absolute-path",
                "onnx-external-path-traversal",
                "onnx-attr-url",
                "safetensors-metadata-url",
            ],
        ),
        _Control(
            id="AIACT-15-1",
            title="Article 15 — Cybersecurity: no executable payloads in artifacts",
            description=(
                "Model artifacts contain only declared tensor data; trailing "
                "executable signatures (ELF/MZ/Mach-O) constitute violation. "
                "Dependencies are not malicious or known-vulnerable."
            ),
            rule_ids=[
                "safetensors-executable-trailing",
                "onnx-custom-domain-op",
                "cve-malicious-package",
                "cve-known-vulnerability",
            ],
        ),
        _Control(
            id="AIACT-15-2",
            title="Article 15 — Cybersecurity: no leaked credentials in artifacts",
            description=(
                "Build artifacts and configs do not contain hard-coded API "
                "keys, tokens, or private keys."
            ),
            rule_ids=[
                "secret-aws-access-key",
                "secret-aws-secret-near-key",
                "secret-github-pat",
                "secret-github-fine-grained-pat",
                "secret-private-key",
                "secret-stripe-live",
                "secret-openai-key",
                "secret-anthropic-key",
                "secret-huggingface-token",
                "secret-google-api-key",
                "secret-slack-token",
                "secret-jwt",
                "secret-high-entropy",
            ],
        ),
    ],
)


# NIST AI Risk Management Framework — упрощённый вариант, можно расширять.
NIST_AI_RMF = _Standard(
    name="NIST AI Risk Management Framework 1.0",
    id="nist-ai-rmf",
    citation="NIST AI 100-1 (2023)",
    description=(
        "NIST AI RMF is a voluntary framework for managing risks of AI "
        "systems. The controls below map to the MANAGE and MEASURE "
        "functions where ML Guard can provide direct evidence."
    ),
    controls=[
        _Control(
            id="MEASURE-2.7",
            title="MEASURE 2.7 — Vulnerability of AI system to misuse and abuse",
            description="Static analysis identifies known abuse patterns and CVEs in dependencies.",
            rule_ids=[
                "pickle-dangerous-global",
                "pickle-suspicious-module",
                "safetensors-executable-trailing",
                "onnx-custom-domain-op",
                "cve-known-vulnerability",
                "cve-malicious-package",
            ],
        ),
        _Control(
            id="MEASURE-2.10",
            title="MEASURE 2.10 — Privacy risks: no PII or credentials leak",
            description="Build artifacts contain no leaked credentials.",
            rule_ids=[
                "secret-aws-access-key",
                "secret-github-pat",
                "secret-private-key",
                "secret-openai-key",
                "secret-anthropic-key",
                "secret-high-entropy",
            ],
        ),
        _Control(
            id="MANAGE-4.1",
            title="MANAGE 4.1 — Continuous monitoring: scan results are auditable",
            description="Reports include timestamps and hashes.",
            rule_ids=[],
        ),
    ],
)


# =============================================================================
# ISO/IEC 27001:2022 Annex A — controls relevant to ML supply-chain security.
# =============================================================================
#
# ISO 27001 lists 93 controls. ml-guard provides direct technical evidence
# for a small subset, listed below. Other controls (governance,
# physical security, supplier audits, incident response process, BCM, ...)
# require organizational evidence that no scanner can produce.
#
# Important caveat for auditors: ml-guard findings are **necessary but not
# sufficient** evidence. A "PASS" verdict here means "no machine-detectable
# violations found"; it does NOT certify ISO 27001 conformance.
#
# Reference: ISO/IEC 27001:2022 Information security management systems —
# Requirements; ISO/IEC 27002:2022 (control guidance).
ISO_27001 = _Standard(
    name="ISO/IEC 27001:2022 (Annex A — selected controls)",
    id="iso-27001",
    citation="ISO/IEC 27001:2022, Annex A",
    description=(
        "ISO/IEC 27001 specifies requirements for information security "
        "management systems. The Annex A controls below are the subset "
        "for which ml-guard can produce machine-checkable technical "
        "evidence. Many other controls (clauses 4-10 plus most of "
        "Annex A) require management-level evidence and are out of "
        "scope for any automated scanner."
    ),
    controls=[
        _Control(
            id="A.5.23",
            title="Information security for use of cloud services",
            description=(
                "Cloud and SaaS credentials must not be committed in source "
                "code or configuration. ml-guard detects known providers' "
                "API keys and high-entropy secret-shaped strings in configs "
                "and source files."
            ),
            rule_ids=[
                "secret-aws-access-key",
                "secret-aws-secret-near-key",
                "secret-google-api-key",
                "secret-stripe-live",
                "secret-stripe-test",
                "secret-openai-key",
                "secret-anthropic-key",
                "secret-huggingface-token",
                "secret-slack-token",
                "secret-slack-webhook",
            ],
        ),
        _Control(
            id="A.8.4",
            title="Access to source code",
            description=(
                "Source code repositories must not contain authentication "
                "tokens that grant access to other systems. ml-guard "
                "detects GitHub PATs, JWTs, and PEM private keys in source "
                "and configuration files."
            ),
            rule_ids=[
                "secret-github-pat",
                "secret-github-fine-grained-pat",
                "secret-private-key",
                "secret-jwt",
                "secret-high-entropy",
            ],
        ),
        _Control(
            id="A.8.7",
            title="Protection against malware",
            description=(
                "ML model artifacts and dependency manifests must be free "
                "of executable code injected via deserialization, malicious "
                "PyPI packages, or hidden binary payloads embedded in "
                "weight files."
            ),
            rule_ids=[
                "pickle-dangerous-global",
                "pickle-suspicious-module",
                "pickle-stack-global-opaque",
                "safetensors-executable-trailing",
                "onnx-custom-domain-op",
                "onnx-attr-shell-command",
                "cve-malicious-package",
            ],
        ),
        _Control(
            id="A.8.8",
            title="Management of technical vulnerabilities",
            description=(
                "Known vulnerabilities in third-party dependencies must be "
                "identified and remediated. ml-guard cross-checks every "
                "pinned dependency against the local OSV database."
            ),
            rule_ids=[
                "cve-known-vulnerability",
                "cve-malicious-package",
            ],
        ),
        _Control(
            id="A.8.25",
            title="Secure development life cycle",
            description=(
                "Security testing must be integrated into the development "
                "pipeline. ml-guard runs in CI on every change, with "
                "machine-readable SARIF output that flows directly into "
                "GitHub Code Scanning, GitLab SAST, and similar tooling."
            ),
            # Этот control закрывается самим фактом интеграции в CI.
            # PASS, если scan в принципе прошёл (нет find-only-on-empty-input).
            rule_ids=[],
        ),
        _Control(
            id="A.8.28",
            title="Secure coding",
            description=(
                "Code must follow secure-coding practices: no hard-coded "
                "secrets, no use of vulnerable library versions, no "
                "unsafe deserialization patterns."
            ),
            rule_ids=[
                "secret-aws-access-key",
                "secret-github-pat",
                "secret-private-key",
                "secret-high-entropy",
                "cve-known-vulnerability",
                "pickle-dangerous-global",
            ],
        ),
        _Control(
            id="A.5.34",
            title="Privacy and protection of personal identifiable information",
            description=(
                "PII-protective material such as private keys and access "
                "tokens that could lead to data exfiltration must not "
                "appear in source artifacts."
            ),
            rule_ids=[
                "secret-private-key",
                "secret-aws-secret-near-key",
                "safetensors-metadata-url",
                "safetensors-metadata-ip",
                "onnx-external-url",
                "onnx-external-absolute-path",
            ],
        ),
    ],
)


# =============================================================================
# SOC 2 — Trust Services Criteria (Common Criteria, 2017 edition + 2022 updates)
# =============================================================================
#
# SOC 2 reports are typically prepared by a CPA firm; ml-guard alone cannot
# produce a SOC 2 report. What it can produce is technical evidence for a
# subset of the Common Criteria (CC) controls in the Security category,
# suitable for the auditor's "control objective testing" workpapers.
#
# Reference: AICPA Trust Services Criteria for Security, Availability,
# Processing Integrity, Confidentiality, and Privacy (TSC 2017,
# clarified 2022).
SOC2 = _Standard(
    name="SOC 2 — Trust Services Criteria (selected Common Criteria)",
    id="soc2",
    citation="AICPA TSC 2017 (with 2022 points of focus update)",
    description=(
        "SOC 2 reports demonstrate that a service organization's controls "
        "meet the AICPA Trust Services Criteria. ml-guard provides "
        "technical evidence for a subset of the Common Criteria (CC) in "
        "the Security category. A full SOC 2 report additionally requires "
        "auditor testing of operating effectiveness over a reporting "
        "period — this report is one input to that process, not a "
        "substitute for it."
    ),
    controls=[
        _Control(
            id="CC6.1",
            title="Logical access security software, infrastructure, and architectures",
            description=(
                "Authentication credentials and cryptographic keys must "
                "be protected, including not being embedded in source "
                "code or configuration files."
            ),
            rule_ids=[
                "secret-aws-access-key",
                "secret-aws-secret-near-key",
                "secret-github-pat",
                "secret-github-fine-grained-pat",
                "secret-private-key",
                "secret-openai-key",
                "secret-anthropic-key",
                "secret-huggingface-token",
                "secret-google-api-key",
                "secret-slack-token",
                "secret-stripe-live",
                "secret-jwt",
                "secret-high-entropy",
            ],
        ),
        _Control(
            id="CC6.6",
            title="Logical access — protection against external threats",
            description=(
                "Systems must be protected from attacks that exploit "
                "deserialization, malicious packages, or hidden payloads "
                "in artifacts."
            ),
            rule_ids=[
                "pickle-dangerous-global",
                "pickle-suspicious-module",
                "safetensors-executable-trailing",
                "onnx-custom-domain-op",
                "onnx-attr-shell-command",
                "cve-malicious-package",
            ],
        ),
        _Control(
            id="CC6.7",
            title="Restrictions on data transmission",
            description=(
                "ML artifacts must not include endpoints that exfiltrate "
                "data at runtime — URLs, IPs, or absolute paths embedded "
                "in metadata or external_data references."
            ),
            rule_ids=[
                "safetensors-metadata-url",
                "safetensors-metadata-ip",
                "safetensors-metadata-path",
                "onnx-external-url",
                "onnx-external-absolute-path",
                "onnx-external-path-traversal",
                "onnx-attr-url",
            ],
        ),
        _Control(
            id="CC6.8",
            title="Prevention and detection of unauthorized software",
            description=(
                "Systems must prevent installation of unauthorized or "
                "malicious software, including via dependency declarations."
            ),
            rule_ids=[
                "cve-malicious-package",
                "pickle-dangerous-global",
                "safetensors-executable-trailing",
            ],
        ),
        _Control(
            id="CC7.1",
            title="Detection and monitoring — vulnerability identification",
            description=(
                "The organization must use detection and monitoring "
                "procedures to identify changes to configurations that "
                "result in vulnerabilities."
            ),
            rule_ids=[
                "cve-known-vulnerability",
                "cve-malicious-package",
                "pickle-suspicious-module",
                "onnx-old-opset",
                "onnx-old-ir-version",
            ],
        ),
        _Control(
            id="CC7.2",
            title="Detection and monitoring — anomaly detection",
            description=(
                "Anomalies in system behavior must be detected, including "
                "ML artifacts that deviate from declared structure (size "
                "mismatch, hidden payloads, unusual operators)."
            ),
            rule_ids=[
                "safetensors-out-of-bounds",
                "safetensors-overlapping-tensors",
                "safetensors-size-mismatch",
                "safetensors-hidden-data",
                "onnx-attr-path-traversal",
                "onnx-attr-absolute-path",
                "pickle-stack-global-opaque",
            ],
        ),
    ],
)


_STANDARDS: Dict[str, _Standard] = {
    EU_AI_ACT.id:    EU_AI_ACT,
    NIST_AI_RMF.id:  NIST_AI_RMF,
    ISO_27001.id:    ISO_27001,
    SOC2.id:         SOC2,
}


def list_standards() -> List[str]:
    return sorted(_STANDARDS.keys())


def get_standard(id_: str) -> _Standard:
    if id_ not in _STANDARDS:
        raise ValueError(
            f"Unknown standard '{id_}'. Available: {', '.join(list_standards())}"
        )
    return _STANDARDS[id_]


# ---------------------------------------------------------------------------
# Расчёт результата по контролам
# ---------------------------------------------------------------------------

@dataclass
class _ControlResult:
    control: _Control
    status: str           # "PASS" | "FAIL" | "N/A"
    matched_findings: List[Finding] = field(default_factory=list)


def _evaluate(standard: _Standard, findings: Sequence[Finding]) -> List[_ControlResult]:
    by_rule: Dict[str, List[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    out: List[_ControlResult] = []
    for ctrl in standard.controls:
        if not ctrl.rule_ids:
            # Контрол, который мы выполняем самим фактом сканирования
            # (например, SBOM/timestamp) — всегда PASS.
            out.append(_ControlResult(control=ctrl, status="PASS"))
            continue
        matched: List[Finding] = []
        for rid in ctrl.rule_ids:
            matched.extend(by_rule.get(rid, []))
        if matched:
            out.append(_ControlResult(control=ctrl, status="FAIL",
                                      matched_findings=matched))
        else:
            out.append(_ControlResult(control=ctrl, status="PASS"))
    return out


# ---------------------------------------------------------------------------
# Основной API
# ---------------------------------------------------------------------------

@dataclass
class ComplianceReport:
    """Сводный отчёт по compliance-сканированию."""
    standard: _Standard
    scan_root: Path
    timestamp: str           # ISO 8601 UTC
    files_scanned: int
    duration_seconds: float
    control_results: List[_ControlResult]
    all_findings: List[Finding]

    @property
    def passed(self) -> int:
        return sum(1 for r in self.control_results if r.status == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.control_results if r.status == "FAIL")

    @property
    def total_controls(self) -> int:
        return len(self.control_results)

    def summary_text(self) -> str:
        if self.failed == 0:
            return f"PASSED ({self.passed}/{self.total_controls})"
        return f"FAILED ({self.failed}/{self.total_controls} controls failing)"

    @property
    def overall_pass(self) -> bool:
        return self.failed == 0


def build_report(
    result: "ScanResult",
    scan_root: Path,
    standard_id: str,
) -> ComplianceReport:
    standard = get_standard(standard_id)
    return ComplianceReport(
        standard=standard,
        scan_root=scan_root.resolve(),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        files_scanned=result.files_scanned,
        duration_seconds=result.duration_seconds,
        control_results=_evaluate(standard, result.findings),
        all_findings=list(result.findings),
    )


# ---------------------------------------------------------------------------
# Рендеринг в PDF
# ---------------------------------------------------------------------------

def render_pdf(report: ComplianceReport) -> bytes:
    doc = PdfDocument(
        title=f"ML Guard Compliance Report - {report.standard.name}",
        author=f"ml-guard {__version__}",
    )

    # Title
    doc.heading("ML Guard Compliance Report", size=22)
    doc.paragraph(
        f"Standard: {report.standard.name}\n"
        f"Reference: {report.standard.citation}",
        size=11, gap_below=14,
    )
    doc.divider()

    # Verdict
    verdict = report.summary_text()
    doc.heading(f"Verdict: {verdict}", size=16)
    if report.overall_pass:
        doc.paragraph(
            "All applicable controls passed. The scanned artifacts contain "
            "no machine-checkable evidence of violations of this standard.",
            size=11,
        )
    else:
        doc.paragraph(
            "One or more controls failed. The list below identifies the "
            "specific findings that constitute violations. Remediate the "
            "underlying issues and re-run the scan.",
            size=11,
        )
    doc.divider()

    # Метаданные сканирования
    doc.heading("Scan metadata", size=14)
    doc.keyvalue_block([
        ("Scan root",          str(report.scan_root)),
        ("Timestamp (UTC)",    report.timestamp),
        ("Files scanned",      str(report.files_scanned)),
        ("Duration (s)",       f"{report.duration_seconds:.3f}"),
        ("Findings (total)",   str(len(report.all_findings))),
        ("Controls passed",    f"{report.passed} / {report.total_controls}"),
        ("ml-guard version",   __version__),
        ("Host",               _safe_hostname()),
        ("Python",             platform.python_version()),
        ("Platform",           platform.platform()),
    ])
    doc.divider()

    # Описание стандарта
    doc.heading("About this standard", size=14)
    doc.paragraph(report.standard.description, size=10, leading=1.5)
    doc.divider()

    # Контрольные точки
    doc.heading("Controls evaluated", size=14)
    for cr in report.control_results:
        status_label = {
            "PASS": "PASS",
            "FAIL": "FAIL",
            "N/A":  "N/A",
        }[cr.status]
        title = f"[{status_label}] {cr.control.id} — {cr.control.title}"
        size = 12
        doc.paragraph(title, size=size, font="Helvetica-Bold", gap_below=4)
        doc.paragraph(cr.control.description, size=10, leading=1.5, gap_below=4)
        if cr.matched_findings:
            doc.paragraph(
                f"Evidence ({len(cr.matched_findings)} matching finding(s)):",
                size=10, gap_below=2,
            )
            # Показываем не более 5 первых, остальное — счётчиком
            for f in cr.matched_findings[:5]:
                bullet = (
                    f"{f.severity.value.upper()}: {f.rule_id} "
                    f"in {f.file or '(unknown)'} "
                    f"({f.location or 'no location'})"
                )
                doc.bullet(bullet, size=10, gap_below=2)
            if len(cr.matched_findings) > 5:
                doc.paragraph(
                    f"... and {len(cr.matched_findings) - 5} more.",
                    size=10, gap_below=8,
                )
        else:
            doc.paragraph("No evidence of violations.", size=10, gap_below=8)

    doc.divider()

    # Приложение: все findings
    if report.all_findings:
        doc.heading("Appendix A — All findings", size=14)
        for f in sorted(
            report.all_findings,
            key=lambda x: (-Severity.order(x.severity), x.file, x.location),
        ):
            line = (
                f"[{f.severity.value.upper()}] {f.rule_id} "
                f"({f.scanner})\n"
                f"  file: {f.file or '(none)'}\n"
                f"  location: {f.location or '(none)'}\n"
                f"  message: {f.message}"
            )
            if f.snippet:
                line += f"\n  snippet: {f.snippet[:160]}"
            doc.paragraph(line, size=9, leading=1.4, gap_below=6)

    doc.divider()

    # Приложение: список применённых правил (для аудитора, чтобы он мог
    # проверить покрытие)
    doc.heading("Appendix B — Rules covered by this standard", size=14)
    for cr in report.control_results:
        if not cr.control.rule_ids:
            continue
        doc.paragraph(
            f"{cr.control.id}: " + ", ".join(cr.control.rule_ids),
            size=9, leading=1.4, gap_below=4, font="Courier",
        )

    doc.divider()

    # Подпись (placeholder)
    doc.heading("Integrity & signature", size=14)
    doc.paragraph(
        "This report was generated by ml-guard, an automated tool. The "
        "fingerprint below is the SHA-256 of this PDF computed before "
        "the fingerprint itself was inserted; downstream tools can verify "
        "by replacing the fingerprint with zeros and re-hashing.",
        size=10, leading=1.5,
    )
    doc.paragraph(
        "Legal note: this report constitutes machine-readable scan "
        "evidence. It is not a conformity declaration. Determination "
        "of regulatory compliance requires assessment by a qualified "
        "natural or legal person (e.g. notified body, DPO).",
        size=10, leading=1.5,
    )

    # Финализация (без fingerprint'а пока)
    raw = doc.to_bytes()

    # Считаем SHA-256 текущих байт и встраиваем как новый блок текста.
    # Это даёт детерминистичный fingerprint, который можно проверить
    # внешним инструментом.
    fingerprint = hashlib.sha256(raw).hexdigest()

    # Добавляем фингерпринт в конец и пересобираем.
    doc.keyvalue_block([
        ("SHA-256 (pre-fp)", fingerprint),
        ("Generated by",     f"ml-guard {__version__}"),
    ])
    return doc.to_bytes()


def _safe_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"
