"""SBOM generator — CycloneDX 1.5 JSON.

CycloneDX (https://cyclonedx.org) is the OWASP standard for machine-readable
software bills of materials. Auditors under EU AI Act and Cyber Resilience Act
expect it (or SPDX, but CycloneDX handles ML models better).

What we put in the BOM:

  • metadata: tool=ml-guard, timestamp, scan description
  • components: each ML artifact (pickle / safetensors / onnx) becomes a
    `library` or `machine-learning-model` with SHA-256, size, and
    detected format
  • vulnerabilities: every Finding with severity >= MEDIUM becomes a
    vulnerability with rating (we emit CVSS-like scores)

Minimal CycloneDX 1.5 schema for ML:
  https://cyclonedx.org/docs/1.5/json/
  https://cyclonedx.org/capabilities/mlbom/

We deliberately don't cover 100% of the spec — only what's needed to
pass audit and integrate with downstream tooling like Dependency-Track,
OWASP DefectDojo, and github.com/CycloneDX/sbom-utility.
"""
from __future__ import annotations

import hashlib
import json
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
# Map our findings onto CycloneDX vulnerability ratings
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

# Extension → CycloneDX component type. CycloneDX has a dedicated
# `machine-learning-model` type (since 1.5), supported by modern parsers.
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
# Helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path, chunk: int = 1024 * 1024) -> Optional[str]:
    """Stream-hash the file; None on read error."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for buf in iter(lambda: f.read(chunk), b""):
                h.update(buf)
        return h.hexdigest()
    except OSError:
        return None


def _component_for_file(scan_root: Path, abs_path: Path) -> Optional[Dict[str, Any]]:
    """Build a CycloneDX component for one file."""
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
    """Turn discovered requirements.txt files into CycloneDX components.

    Very simplified parser: good enough for audit, doesn't claim full
    PEP 508 compliance. Full dependency-tree extraction would plug in
    pip-audit/uv at the CVE checker stage.
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
    """Wire a vulnerability to a component via bom-ref."""
    return f"file:{finding.file}"


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def build_sbom(
    result: "ScanResult",
    scan_root: Path,
    *,
    include_dependencies: bool = True,
    min_severity: Severity = Severity.MEDIUM,
) -> Dict[str, Any]:
    """
    Build a CycloneDX 1.5 dict.

    Parameters:
      result              — ScanResult from Runner
      scan_root           — scan root (for relative paths)
      include_dependencies — whether to parse requirements.txt
      min_severity        — which findings to include as vulnerabilities
                            (default >= MEDIUM, to keep noise down)
    """
    scan_root = scan_root.resolve()

    # Gather unique files from findings (plus targeted top-level ML
    # artifacts in scan_root so the BOM is complete even when findings
    # findings).
    component_paths: Dict[str, Path] = {}

    # From findings
    for f in result.findings:
        if not f.file:
            continue
        full = (scan_root / f.file).resolve()
        component_paths.setdefault(str(full), full)

    # Direct traversal — add known ML extensions even when no scanner
    # produced findings (BOM must be complete).
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
    """Convenience wrapper: returns already-serialized JSON."""
    return json.dumps(build_sbom(result, scan_root, **kwargs), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Helper builders
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
