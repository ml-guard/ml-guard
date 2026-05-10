"""SARIF 2.1.0 форматтер — стандарт для GitHub Code Scanning, GitLab SAST и др.

Спецификация: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub поддерживает подмножество — мы реализуем достаточный минимум.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Dict, List, Any

from ml_guard.findings import Severity, Finding

if TYPE_CHECKING:
    from ml_guard.runner import ScanResult


# Маппинг наших severity → SARIF level
# SARIF знает только 4: none/note/warning/error.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}

# Доп. поле security-severity (GitHub использует его для CVSS-like ранжирования).
_SARIF_SECURITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH:     "8.0",
    Severity.MEDIUM:   "5.0",
    Severity.LOW:      "3.0",
    Severity.INFO:     "0.0",
}


def _build_rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Уникальные правила (по rule_id) для секции tool.driver.rules."""
    rules: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id.replace("-", "_"),
            "shortDescription": {"text": f.rule_id},
            "fullDescription": {"text": f.message},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
            },
            "properties": {
                "security-severity": _SARIF_SECURITY_SCORE.get(f.severity, "0.0"),
                "tags": ["security", "ml"],
            },
        }
    return list(rules.values())


def _build_results(findings: List[Finding]) -> List[Dict[str, Any]]:
    out = []
    for f in findings:
        loc: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
            }
        }
        # Если location выглядит как "line N", достаём номер строки.
        if f.location and f.location.startswith("line "):
            try:
                line_no = int(f.location.split()[1])
                loc["physicalLocation"]["region"] = {"startLine": line_no}
            except (ValueError, IndexError):
                pass

        msg = f.message
        if f.location and "line " not in f.location:
            msg = f"{f.message} ({f.location})"

        out.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": msg},
            "locations": [loc],
            "partialFingerprints": {"primary": f.fingerprint},
            "properties": {
                "scanner": f.scanner,
                "severity": f.severity.value,
            },
        })
    return out


def format_sarif(result: "ScanResult") -> str:
    """Возвращает SARIF JSON как строку."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ml-guard",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/example/ml-guard",
                    "rules": _build_rules(result.findings),
                }
            },
            "results": _build_results(result.findings),
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
