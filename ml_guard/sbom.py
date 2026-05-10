"""SBOM генератор — CycloneDX 1.5 JSON.

CycloneDX (https://cyclonedx.org) — стандарт OWASP для машиночитаемых
software bill of materials. Аудиторы под EU AI Act и Cyber Resilience Act
ожидают именно его (или SPDX, но CycloneDX поддерживает ML-моделей лучше).

Что мы кладём в BOM:

  • metadata: tool=ml-guard, timestamp, описание сканирования
  • components: каждая ML-артефакт (pickle / safetensors / onnx) — это
    `library` или `machine-learning-model` со своим SHA-256, размером,
    обнаруженным форматом
  • vulnerabilities: каждый Finding с severity ≥ MEDIUM становится
    отдельной vulnerability с rating (используем CVSS-like score)

Минимальная схема CycloneDX 1.5 для ML:
  https://cyclonedx.org/docs/1.5/json/
  https://cyclonedx.org/capabilities/mlbom/

Мы сознательно НЕ покрываем 100% спецификации — только то, что нужно для
прохождения аудита и интеграции с downstream-инструментами вроде
Dependency-Track, OWASP DefectDojo, и github.com/CycloneDX/sbom-utility.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ml_guard import __version__
from ml_guard.findings import Finding, Severity

if TYPE_CHECKING:
    from ml_guard.runner import ScanResult


# ---------------------------------------------------------------------------
# Маппинг наших findings на CycloneDX vulnerability rating
# ---------------------------------------------------------------------------

# CycloneDX severity values: critical, high, medium, low, info, none, unknown
_CDX_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
    Severity.INFO:     "info",
}

_CDX_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH:     7.5,
    Severity.MEDIUM:   5.0,
    Severity.LOW:      3.0,
    Severity.INFO:     0.0,
}

# Расширение → CycloneDX component type. У CycloneDX есть отдельный тип
# `machine-learning-model` (с 1.5), и его поддерживают современные парсеры.
_EXT_TO_TYPE = {
    ".pkl":         "machine-learning-model",
    ".pickle":      "machine-learning-model",
    ".pt":          "machine-learning-model",
    ".pth":         "machine-learning-model",
    ".ckpt":        "machine-learning-model",
    ".bin":         "machine-learning-model",
    ".safetensors": "machine-learning-model",
    ".onnx":        "machine-learning-model",
}


# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> Optional[str]:
    """Стримово хэшируем файл; None при ошибке чтения."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for buf in iter(lambda: f.read(chunk), b""):
                h.update(buf)
        return h.hexdigest()
    except OSError:
        return None


def _component_for_file(scan_root: Path, abs_path: Path) -> Optional[Dict[str, Any]]:
    """Строим CycloneDX component для одного файла."""
    if not abs_path.is_file():
        return None
    try:
        size = abs_path.stat().st_size
    except OSError:
        return None
    sha = _sha256_file(abs_path)
    rel = _relative_or_absolute(abs_path, scan_root)
    ext = abs_path.suffix.lower()
    comp: Dict[str, Any] = {
        "bom-ref": f"file:{rel}",
        "type": _EXT_TO_TYPE.get(ext, "file"),
        "name": abs_path.name,
        "version": "0",
        "description": f"ML artifact at {rel}",
        "properties": [
            {"name": "ml-guard:relative_path", "value": rel},
            {"name": "ml-guard:size_bytes",  "value": str(size)},
        ],
    }
    if sha is not None:
        comp["hashes"] = [{"alg": "SHA-256", "content": sha}]
    return comp


def _relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


_PKG_LINE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:==|>=|<=|~=|!=)?\s*([0-9][^;\s#]*)?"
)


def _parse_requirements_files(scan_root: Path) -> List[Dict[str, Any]]:
    """Превращаем найденные requirements.txt в CycloneDX components.

    Это очень упрощённый парсер: достаточно для аудита, но не претендует
    на полное соответствие PEP 508. Для полной поддержки извлечения
    dependency-tree подключим pip-audit/uv в этап CVE checker.
    """
    out: List[Dict[str, Any]] = []
    if not scan_root.is_dir():
        return out

    seen_pkgs: set[tuple[str, str]] = set()  # (name, version)
    candidate_names = {"requirements.txt", "requirements-dev.txt"}

    for fp in scan_root.rglob("*"):
        if not fp.is_file():
            continue
        if fp.name not in candidate_names:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = _PKG_LINE_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            version = m.group(2) or "unknown"
            if (name, version) in seen_pkgs:
                continue
            seen_pkgs.add((name, version))
            out.append({
                "bom-ref": f"pypi:{name}@{version}",
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}" if version != "unknown"
                        else f"pkg:pypi/{name}",
                "properties": [
                    {"name": "ml-guard:source",
                     "value": _relative_or_absolute(fp, scan_root)},
                ],
            })
    return out


def _bom_ref_for_finding(scan_root: Path, finding: Finding) -> str:
    """Привязываем vulnerability к компоненту через bom-ref."""
    return f"file:{finding.file}"


# ---------------------------------------------------------------------------
# Главная функция
# ---------------------------------------------------------------------------

def build_sbom(
    result: "ScanResult",
    scan_root: Path,
    *,
    include_dependencies: bool = True,
    min_severity: Severity = Severity.MEDIUM,
) -> Dict[str, Any]:
    """
    Строит CycloneDX 1.5 dict.

    Параметры:
      result            — ScanResult от Runner
      scan_root         — корень сканирования (для относительных путей)
      include_dependencies — парсить ли requirements.txt
      min_severity      — какие findings включать как vulnerabilities
                          (по умолчанию ≥ MEDIUM, чтобы не зашуметь)
    """
    scan_root = scan_root.resolve()

    # Собираем уникальные файлы из findings (плюс прицельно — top-level
    # ML-артефакты в scan_root, чтобы BOM был полным даже при пустых
    # findings).
    component_paths: Dict[str, Path] = {}

    # Из findings
    for f in result.findings:
        if not f.file:
            continue
        full = (scan_root / f.file).resolve()
        component_paths.setdefault(str(full), full)

    # Прямой обход — добавляем известные ML-расширения, даже если
    # сканеры на них не выдали findings (BOM должен быть полным).
    if scan_root.is_dir():
        for fp in scan_root.rglob("*"):
            if fp.is_file() and fp.suffix.lower() in _EXT_TO_TYPE:
                component_paths.setdefault(str(fp.resolve()), fp)
    elif scan_root.is_file() and scan_root.suffix.lower() in _EXT_TO_TYPE:
        component_paths.setdefault(str(scan_root.resolve()), scan_root)

    components: List[Dict[str, Any]] = []
    for _, p in sorted(component_paths.items()):
        c = _component_for_file(scan_root, p)
        if c is not None:
            components.append(c)

    if include_dependencies:
        components.extend(_parse_requirements_files(scan_root))

    vulnerabilities = _build_vulnerabilities(scan_root, result.findings, min_severity)

    bom: Dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _build_metadata(scan_root, result),
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return bom


def build_sbom_json(
    result: "ScanResult",
    scan_root: Path,
    **kwargs: Any,
) -> str:
    """Удобная обёртка: возвращает уже-сериализованный JSON."""
    return json.dumps(build_sbom(result, scan_root, **kwargs), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Вспомогательные строители
# ---------------------------------------------------------------------------

def _build_metadata(scan_root: Path, result: "ScanResult") -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = ""
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown"

    return {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "bom-ref": f"ml-guard@{__version__}",
                    "name": "ml-guard",
                    "version": __version__,
                    "description": "Security and compliance scanner for ML pipelines",
                }
            ],
        },
        "component": {
            "type": "application",
            "bom-ref": f"scan:{scan_root.name}",
            "name": scan_root.name or "scan",
            "version": "0",
            "description": f"ML Guard scan of {scan_root}",
        },
        "properties": [
            {"name": "ml-guard:scan_root",        "value": str(scan_root)},
            {"name": "ml-guard:files_scanned",    "value": str(result.files_scanned)},
            {"name": "ml-guard:scanners_invoked", "value": str(result.scanners_invoked)},
            {"name": "ml-guard:duration_seconds", "value": f"{result.duration_seconds:.4f}"},
            {"name": "ml-guard:host",             "value": host},
            {"name": "ml-guard:python",           "value": platform.python_version()},
            {"name": "ml-guard:platform",         "value": platform.platform()},
        ],
    }


def _build_vulnerabilities(
    scan_root: Path,
    findings: List[Finding],
    min_severity: Severity,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not f.severity.at_least(min_severity):
            continue
        v: Dict[str, Any] = {
            "bom-ref": f"finding:{f.fingerprint}",
            "id": f.rule_id,
            "source": {"name": f"ml-guard:{f.scanner or 'unknown'}"},
            "ratings": [
                {
                    "source": {"name": "ml-guard"},
                    "score": _CDX_SCORE.get(f.severity, 0.0),
                    "severity": _CDX_SEVERITY.get(f.severity, "unknown"),
                    "method": "other",
                }
            ],
            "description": f.message,
            "affects": [
                {"ref": _bom_ref_for_finding(scan_root, f)},
            ],
            "properties": [
                {"name": "ml-guard:rule_id",  "value": f.rule_id},
                {"name": "ml-guard:scanner",  "value": f.scanner or ""},
                {"name": "ml-guard:location", "value": f.location or ""},
            ],
        }
        if f.snippet:
            v["properties"].append(
                {"name": "ml-guard:snippet", "value": f.snippet[:200]}
            )
        out.append(v)
    return out
