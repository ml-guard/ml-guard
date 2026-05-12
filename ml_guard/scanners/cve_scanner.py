"""CVE scanner — offline dependency check against the local OSV database.

What it does:
  1. Find dependency manifests (requirements.txt, requirements*.txt,
     pyproject.toml, environment.yml, Pipfile.lock).
  2. Parse each into (package_name, version) pairs.
  3. Query `CveDatabase.find_advisories_for(name, version)`.
  4. Turn each matching advisory into a `Finding`.

How the DB is located:
  • Default location is `XDG_DATA_HOME/ml-guard/osv.db` or the path
    supplied via `--cve-db`.
  • If no DB exists we emit one informational finding and return.
    Not an error — the CVE checker is opted into explicitly by running
    `ml-guard cve-update`.

Severity:
  • Advisory MAL-* (malicious package) → CRITICAL regardless of version,
    because it means "this package is intentionally malicious, no version is safe".
  • Advisory has database_specific.severity → use it.
  • Otherwise MEDIUM (conservative fallback: "vulnerability present, severity unspecified").
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ml_guard.cve_db import CveDatabase, default_db_path
from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dependency file parsing
# ---------------------------------------------------------------------------

# requirements.txt: `package==version` or `package>=version`. We only take
# pinned `==` — a vulnerability check needs an exact version. `>=` is a
# range and the CVE check would be far too false-positive (e.g.
# `requests>=2.0` is "theoretically vulnerable" to every ancient CVE).
_REQ_PINNED_RE = re.compile(
    r"^\s*"
    r"(?P<name>[A-Za-z][A-Za-z0-9._\-]*)"
    r"\s*==\s*"
    r"(?P<version>[A-Za-z0-9._\-+!]+)"
    r"(?:\s*[#;].*)?$"
)

# Pipfile.lock — JSON. Pinned versions look like `"==1.2.3"`.
_PIPLOCK_VERSION_RE = re.compile(r"==([\w.\-+!]+)")


def _parse_requirements_txt(text: str) -> Iterable[Tuple[str, str]]:
    """Extract (name, version) from a requirements.txt-style file.

    Ignored:
      • comments (#...)
      • -r includes
      • pip options (--hash, --index-url, etc.)
      • non-pinned specifiers (>=, <=, ~=, *)
      • editable installs (-e ...)
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_PINNED_RE.match(line)
        if m:
            yield m.group("name"), m.group("version")


def _parse_pyproject_toml(text: str) -> Iterable[Tuple[str, str]]:
    """Simple parser for dependencies in pyproject.toml.

    We avoid tomllib to keep working on Python <3.11 (stdlib), and avoid
    tomli (non-stdlib). A regex picks up lines like:

        "package==1.2.3"
        'package == 1.2.3'

    inside dependencies = [...]. Good enough for a security scanner:
    we don't build a dependency tree, we just find pinned versions.
    """
    # Take the content of every dependencies section — recursively parsing
    # TOML is overkill, line-wise regex does the job.
    dep_lines: List[str] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if (
            stripped.startswith("dependencies")
            or stripped.startswith("optional-dependencies")
            or stripped.startswith("dev-dependencies")
        ):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]") or (stripped.startswith("[") and "=" not in stripped):
                in_deps = False
                continue
            dep_lines.append(stripped)

    for line in dep_lines:
        # find "name==version" inside quotes
        m = re.search(
            r"['\"]([A-Za-z][A-Za-z0-9._\-]*)\s*==\s*([A-Za-z0-9._\-+!]+)['\"]",
            line,
        )
        if m:
            yield m.group(1), m.group(2)


def _parse_pipfile_lock(text: str) -> Iterable[Tuple[str, str]]:
    """Pipfile.lock — pipenv JSON format. Extract names and pinned versions."""
    import json as _json
    try:
        data = _json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return
    for section in ("default", "develop"):
        pkgs = data.get(section, {})
        if not isinstance(pkgs, dict):
            continue
        for name, body in pkgs.items():
            if not isinstance(body, dict):
                continue
            v = body.get("version")
            if isinstance(v, str):
                m = _PIPLOCK_VERSION_RE.search(v)
                if m:
                    yield name, m.group(1)


def _parse_environment_yml(text: str) -> Iterable[Tuple[str, str]]:
    """conda environment.yml. Pinned: `package=version`."""
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies"):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("- "):
                # `- package=1.2.3` or `- package=1.2.3=build`
                spec = stripped[2:].strip()
                # Keep only entries that look like PyPI packages
                if "==" in spec:  # e.g. `- pip:` sub-sections
                    name, _, ver = spec.partition("==")
                    yield name.strip(), ver.strip()
                elif "=" in spec:
                    parts = spec.split("=")
                    if len(parts) >= 2 and parts[1]:
                        yield parts[0].strip(), parts[1].strip()
            elif stripped and not stripped.startswith(("- ", " ")):
                in_deps = False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

# Manifests we know how to parse (basename → parser).
_PARSERS = {
    "requirements.txt":     _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "Pipfile.lock":         _parse_pipfile_lock,
    "pyproject.toml":       _parse_pyproject_toml,
    "environment.yml":      _parse_environment_yml,
    "environment.yaml":     _parse_environment_yml,
}

# Also matches any `requirements*.txt`
_REQUIREMENTS_GLOB_RE = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


@register
class CveScanner(Scanner):
    name = "cve"
    description = "Cross-checks pinned dependencies against the local OSV database"

    # Parameters. CLI/Runner can override the DB path via the
    # ML_GUARD_CVE_DB environment variable. An explicit --cve-db CLI flag
    # propagates through the same env var.
    _env_db_var = "ML_GUARD_CVE_DB"

    # Size cap: requirements.txt is normally <1 MB; anything larger is skipped.
    MAX_FILE_BYTES = 4 * 1024 * 1024

    def __init__(self, db_path: Optional[Path] = None) -> None:
        super().__init__()
        self._explicit_db_path = db_path
        self._db: Optional[CveDatabase] = None
        self._db_missing_warned = False

    # ------------------------------------------------------------------

    def _resolve_db_path(self) -> Path:
        """Resolve to the **preferred** DB path. _get_db() may fall back
        to the bundled mini-DB if this file doesn't exist.
        """
        if self._explicit_db_path is not None:
            return self._explicit_db_path
        import os
        env = os.environ.get(self._env_db_var)
        if env:
            return Path(env)
        return default_db_path()

    @staticmethod
    def _bundled_db_path() -> Optional[Path]:
        """Return the path to the bundled mini OSV DB shipped in the wheel,
        or None if it's not present (e.g. in editable installs without the
        data file built yet).
        """
        try:
            import ml_guard
            bundled = Path(ml_guard.__file__).parent / "data" / "osv-mini.sqlite"
            return bundled if bundled.is_file() else None
        except Exception:  # noqa: BLE001
            return None

    def _get_db(self) -> Optional[CveDatabase]:
        if self._db is not None:
            return self._db
        # 1. Preferred user DB (from --db, env, or default location).
        path = self._resolve_db_path()
        if path.is_file():
            self._db = CveDatabase(path)
            return self._db
        # 2. Fallback to the bundled mini DB shipped with the wheel.
        bundled = self._bundled_db_path()
        if bundled is not None:
            self._db = CveDatabase(bundled)
            return self._db
        return None

    # ------------------------------------------------------------------

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.name in _PARSERS:
            return True
        if _REQUIREMENTS_GLOB_RE.match(path.name):
            return True
        return False

    def scan(self, path: Path) -> List[Finding]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size > self.MAX_FILE_BYTES:
            return [Finding(
                rule_id="cve-file-too-large",
                severity=Severity.LOW,
                message=f"Dependency file too large to scan ({size} bytes); skipped",
                file=str(path), scanner=self.name,
            )]

        db = self._get_db()
        if db is None:
            if self._db_missing_warned:
                return []
            self._db_missing_warned = True
            return [Finding(
                rule_id="cve-db-missing",
                severity=Severity.INFO,
                message=(
                    f"OSV database not found at {self._resolve_db_path()}. "
                    f"Run `ml-guard cve-update <path-to-osv.zip>` to enable "
                    f"CVE checks."
                ),
                file=str(path),
                scanner=self.name,
            )]

        # Parse the file
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        parser = _PARSERS.get(path.name)
        if parser is None and _REQUIREMENTS_GLOB_RE.match(path.name):
            parser = _parse_requirements_txt
        if parser is None:
            return []

        deps = list(parser(text))
        if not deps:
            return []

        findings: List[Finding] = []
        # Two-level dedup:
        #   1. (name, version, advisory_id) — guard against accidental
        #      duplicates of the same advisory.
        #   2. (name, version, cve_alias)   — guard against different
        #      sources (GHSA + PYSEC) reporting the same CVE-2023-XXXX
        #      as two distinct advisory documents. Keep the first, collapse
        #      the rest.
        seen_advisory: set = set()
        seen_cve: set = set()

        for name, version in deps:
            advisories = db.find_advisories_for(name, version)
            # Sort so GHSA wins ties — GHSA usually carries severity and
            # summary, while PYSEC is more often blank.
            advisories.sort(key=lambda a: (
                0 if a.id.startswith("GHSA-") else
                1 if a.id.startswith("PYSEC-") else
                2,
                a.id,
            ))
            for adv in advisories:
                key = (name, version, adv.id)
                if key in seen_advisory:
                    continue
                seen_advisory.add(key)

                # CVE-level dedup
                cve_aliases = [a for a in adv.aliases if a.startswith("CVE-")]
                cve_dup = False
                for cve in cve_aliases:
                    if (name, version, cve) in seen_cve:
                        cve_dup = True
                        break
                if cve_dup:
                    continue
                for cve in cve_aliases:
                    seen_cve.add((name, version, cve))

                findings.append(self._make_finding(name, version, adv))

        return findings

    # ------------------------------------------------------------------

    def _make_finding(self, pkg_name: str, version: str, adv) -> Finding:
        if adv.is_malicious:
            severity = Severity.CRITICAL
            rule_id = "cve-malicious-package"
            msg = (
                f"Malicious package detected: {pkg_name}=={version} "
                f"(advisory {adv.id}). Remove this dependency immediately."
            )
        else:
            severity = self._severity_from_advisory(adv)
            rule_id = "cve-known-vulnerability"
            cve_aliases = [a for a in adv.aliases if a.startswith("CVE-")]
            cve_str = f" ({', '.join(cve_aliases)})" if cve_aliases else ""
            short = adv.summary or "no summary"
            msg = (
                f"{pkg_name}=={version} has known vulnerability {adv.id}{cve_str}: "
                f"{short[:200]}"
            )

        snippet = f"{adv.id} -> {pkg_name}=={version}"
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message=msg,
            file="",
            scanner=self.name,
            location=f"package {pkg_name}=={version}",
            snippet=snippet,
        )

    @staticmethod
    def _severity_from_advisory(adv) -> Severity:
        sev_str = (adv.severity or "").lower()
        return {
            "critical": Severity.CRITICAL,
            "high":     Severity.HIGH,
            "medium":   Severity.MEDIUM,
            "low":      Severity.LOW,
        }.get(sev_str, Severity.MEDIUM)
