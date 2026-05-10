"""CVE scanner — оффлайн-проверка зависимостей по локальной OSV-базе.

Что мы делаем:
  1. Находим файлы зависимостей (requirements.txt, requirements*.txt,
     pyproject.toml, environment.yml, Pipfile.lock).
  2. Парсим из них пары (package_name, version).
  3. Запрашиваем `CveDatabase.find_advisories_for(name, version)`.
  4. Каждую найденную уязвимость превращаем в `Finding`.

Как сюда попадает БД:
  • По умолчанию ищем БД в `XDG_DATA_HOME/ml-guard/osv.db` или указанном
    через `--cve-db` пути.
  • Если БД нет — выдаём один informational finding и возвращаем пустой
    список. Это не error, потому что CVE-checker пользователь активирует
    осознанно командой `ml-guard cve-update`.

Severity:
  • Если advisory MAL-* (malicious package) → CRITICAL независимо от версии,
    потому что это означает «пакет специально опасный, никакая версия не безопасна».
  • Если advisory имеет database_specific.severity → используем его.
  • Иначе MEDIUM (консервативный fallback: «уязвимость есть, серьёзность не указана»).
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
# Парсинг файлов зависимостей
# ---------------------------------------------------------------------------

# requirements.txt: `package==version` или `package>=version`. Берём только
# pinned `==`, потому что для уязвимости нужна точная версия. `>=` — это
# range, для которого CVE-проверка слишком фолз-позитивна (например,
# `requests>=2.0` "теоретически уязвим" к каждой древней CVE).
_REQ_PINNED_RE = re.compile(
    r"^\s*"
    r"(?P<name>[A-Za-z][A-Za-z0-9._\-]*)"
    r"\s*==\s*"
    r"(?P<version>[A-Za-z0-9._\-+!]+)"
    r"(?:\s*[#;].*)?$"
)

# Pipfile.lock — JSON. Pinned версии в формате `"==1.2.3"`.
_PIPLOCK_VERSION_RE = re.compile(r"==([\w.\-+!]+)")


def _parse_requirements_txt(text: str) -> Iterable[Tuple[str, str]]:
    """Извлекает (name, version) из requirements.txt-style файла.

    Игнорирует:
      • комментарии (#...)
      • -r includes
      • опции pip (--hash, --index-url и т.п.)
      • не-pinned (>=, <=, ~=, *)
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
    """Простой парсер dependencies в pyproject.toml.

    Не используем tomllib чтобы не зависеть от 3.11+ (стдлиб) и от tomli
    (не-стдлиб). Регуляркой ловим строки вида:

        "package==1.2.3"
        'package == 1.2.3'

    в массиве dependencies = [...]. Для security-сканера этого достаточно:
    мы не строим dependency tree, мы просто ищем pinned версии.
    """
    # Берём содержимое всех секций dependencies — лень парсить TOML
    # рекурсивно, regex по строкам справляется.
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
        # ищем "name==version" внутри кавычек
        m = re.search(
            r"['\"]([A-Za-z][A-Za-z0-9._\-]*)\s*==\s*([A-Za-z0-9._\-+!]+)['\"]",
            line,
        )
        if m:
            yield m.group(1), m.group(2)


def _parse_pipfile_lock(text: str) -> Iterable[Tuple[str, str]]:
    """Pipfile.lock — JSON формата pipenv. Извлекаем имена и pinned версии."""
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
                # `- package=1.2.3` или `- package=1.2.3=build`
                spec = stripped[2:].strip()
                # Оставляем только то что выглядит как pypi-пакет
                if "==" in spec:  # например `- pip:` секции
                    name, _, ver = spec.partition("==")
                    yield name.strip(), ver.strip()
                elif "=" in spec:
                    parts = spec.split("=")
                    if len(parts) >= 2 and parts[1]:
                        yield parts[0].strip(), parts[1].strip()
            elif stripped and not stripped.startswith(("- ", " ")):
                in_deps = False


# ---------------------------------------------------------------------------
# Сканер
# ---------------------------------------------------------------------------

# Файлы, которые мы умеем парсить. (basename → parser).
_PARSERS = {
    "requirements.txt":     _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "Pipfile.lock":         _parse_pipfile_lock,
    "pyproject.toml":       _parse_pyproject_toml,
    "environment.yml":      _parse_environment_yml,
    "environment.yaml":     _parse_environment_yml,
}

# Также любой `requirements*.txt`
_REQUIREMENTS_GLOB_RE = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


@register
class CveScanner(Scanner):
    name = "cve"
    description = "Cross-checks pinned dependencies against the local OSV database"

    # Параметры. CLI/Runner может задать кастомный путь к БД через
    # переменную окружения ML_GUARD_CVE_DB. Опция CLI поверх — добавляется
    # позже; пока — env-var подход.
    _env_db_var = "ML_GUARD_CVE_DB"

    # Лимит размера: requirements.txt обычно меньше 1 МБ; больше — пропускаем.
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

        # Парсим файл
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
        # Дедуп. Два уровня:
        #   1. (name, version, advisory_id) — защита от случайных дублей одного и
        #      того же advisory.
        #   2. (name, version, cve_alias)   — защита от того что разные базы
        #      (GHSA + PYSEC) репортят одну и ту же CVE-2023-XXXX как два
        #      разных advisory-документа. Оставляем первый, остальные —
        #      сворачиваем.
        seen_advisory: set = set()
        seen_cve: set = set()

        for name, version in deps:
            advisories = db.find_advisories_for(name, version)
            # Сортируем чтобы при равных CVE первым шёл GHSA — у него
            # обычно есть severity и summary, у PYSEC чаще пусто.
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

                # CVE-дедуп
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
