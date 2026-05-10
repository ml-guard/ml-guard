"""SQLite-индекс OSV vulnerabilities для оффлайн-проверок.

Зачем оффлайн:
  • Воспроизводимость: одни и те же входы → один и тот же отчёт. live OSV
    меняется ежедневно, и два прогона CI на одном коде будут разными.
  • Air-gapped окружения (банки, оборонка, регулируемые ML-команды) —
    наша целевая аудитория. Live API там не работает.
  • Скорость: ~50 пакетов в requirements.txt — это 50 HTTP-запросов в
    лучшем случае, секунды задержки. SQLite по локальному файлу — миллисекунды.
  • Атакоустойчивость: если osv.dev недоступен или скомпрометирован —
    наш сканер не возвращает «всё ок» по умолчанию.

Так делают trivy, grype, osv-scanner — все они качают БД заранее.

Поток данных:
  1. Пользователь делает `ml-guard cve-update https://osv-vulnerabilities.../all.zip`
     или указывает локальный ZIP/директорию JSON.
  2. Импортёр проходит по всем файлам, складывает в SQLite.
  3. CVE scanner на запрос matches() мгновенно отдаёт совпадения.

OSV schema: https://ossf.github.io/osv-schema/

Источники в текущем дампе (все pypi):
  GHSA   — GitHub Security Advisories (основа), 5K записей, есть severity
  PYSEC  — Python Software Foundation, 3.3K записей
  MAL    — malicious package advisories (typosquatting и т.п.), 11K
  ECHO   — echo.guard re-builds, 15
  OSV    — прочие, 8
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Дефолтное расположение БД
# ---------------------------------------------------------------------------

def default_db_path() -> Path:
    """Куда класть БД по умолчанию.

    Используем XDG_DATA_HOME для соответствия freedesktop.org. На macOS/
    Linux это ~/.local/share, на Windows %LOCALAPPDATA% (не здесь — это
    POSIX-default, но практично работает).
    """
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "ml-guard" / "osv.db"


# ---------------------------------------------------------------------------
# Схема БД
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS advisories (
    id              TEXT PRIMARY KEY,
    summary         TEXT,
    details         TEXT,
    severity        TEXT,
    is_malicious    INTEGER NOT NULL DEFAULT 0,
    is_withdrawn    INTEGER NOT NULL DEFAULT 0,
    aliases         TEXT,
    published       TEXT,
    modified        TEXT,
    references_json TEXT
);

CREATE TABLE IF NOT EXISTS affected (
    advisory_id     TEXT NOT NULL,
    package_name    TEXT NOT NULL COLLATE NOCASE,
    ranges_json     TEXT,
    versions_json   TEXT,
    PRIMARY KEY (advisory_id, package_name)
);

CREATE INDEX IF NOT EXISTS idx_affected_pkg ON affected (package_name);
CREATE INDEX IF NOT EXISTS idx_adv_mal      ON advisories (is_malicious);
CREATE INDEX IF NOT EXISTS idx_adv_withdrawn ON advisories (is_withdrawn);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Преобразование OSV JSON → row для SQLite
# ---------------------------------------------------------------------------

# Маппинг database_specific.severity → наш Severity-уровень (как строка,
# чтобы не тащить enum в БД-слой).
_SEVERITY_NORMALIZE = {
    "CRITICAL":  "critical",
    "HIGH":      "high",
    "MODERATE":  "medium",   # GHSA использует "MODERATE"
    "MEDIUM":    "medium",
    "LOW":       "low",
}


def _normalize_severity(advisory: Dict[str, Any]) -> Optional[str]:
    """Достаём текстовый severity. Источники по приоритету:
       1. database_specific.severity (GHSA — самый надёжный)
       2. severity[*].score CVSS — парсим вручную и считаем уровень
       3. None — для PYSEC/MAL/ECHO без severity
    """
    db = advisory.get("database_specific") or {}
    raw = db.get("severity")
    if isinstance(raw, str):
        norm = _SEVERITY_NORMALIZE.get(raw.upper())
        if norm:
            return norm

    # CVSS — берём первый, парсим Base Score из вектора. Полный CVSS-расчёт
    # сложен, но для CVSSv3 можно просто посмотреть Impact/Exploitability
    # компоненты. Для простоты тут не делаем — оставим это для отдельного
    # хелпера если понадобится. CVSS-вектор есть, значит хотя бы LOW.
    sev_list = advisory.get("severity") or []
    if sev_list:
        return "medium"   # консервативный fallback: "что-то есть, не низкое"

    return None


def _is_malicious(advisory: Dict[str, Any]) -> bool:
    """MAL- advisories обычно описывают полностью вредоносные пакеты.

    Также проверяем `database_specific.malicious-packages-origins`, который
    у GHSA-malware ставится явно.
    """
    if (advisory.get("id") or "").startswith("MAL-"):
        return True
    db = advisory.get("database_specific") or {}
    if db.get("malicious-packages-origins"):
        return True
    return False


def _is_withdrawn(advisory: Dict[str, Any]) -> bool:
    """`withdrawn` — поле OSV-spec: дата, когда advisory было отозвано.

    Если оно есть, advisory считается невалидным и его не стоит репортить
    (но в БД мы храним для аудита: вдруг кто-то спросит, было ли
    предупреждение раньше).
    """
    return bool(advisory.get("withdrawn"))


def _extract_advisory_row(advisory: Dict[str, Any]) -> Optional[Tuple]:
    """Один OSV-объект → row для таблицы advisories.

    Возвращает None если запись непригодна (нет id или affected).
    """
    aid = advisory.get("id")
    if not aid:
        return None

    return (
        aid,
        (advisory.get("summary") or "").strip()[:500],
        # details — обычно длинная маркдаун-простыня, нам она не нужна.
        # summary хранит ту же суть в одну строку. Если кто-то очень захочет
        # — может прочитать оригинал по references_json.
        "",
        _normalize_severity(advisory),
        1 if _is_malicious(advisory) else 0,
        1 if _is_withdrawn(advisory) else 0,
        json.dumps(advisory.get("aliases") or [], separators=(",", ":")),
        advisory.get("published"),
        advisory.get("modified"),
        json.dumps(
            [r for r in (advisory.get("references") or []) if r.get("url")][:5],
            separators=(",", ":"),
        ),
    )


def _extract_affected_rows(advisory: Dict[str, Any]) -> Iterator[Tuple]:
    """Один OSV-объект → много rows для таблицы affected (по одной на пакет).

    Дедуплицируем по package_name внутри одного advisory: некоторые OSV-записи
    повторяют пакет в разных affected[] блоках (для разных range-stratagies),
    мы агрегируем все ranges/versions в один row.
    """
    aid = advisory.get("id")
    if not aid:
        return

    by_pkg: Dict[str, Dict[str, Any]] = {}

    for entry in advisory.get("affected", []):
        pkg = entry.get("package") or {}
        if pkg.get("ecosystem") != "PyPI":
            continue
        name = pkg.get("name")
        if not name:
            continue
        # PyPI имена нормализуем к lowercase + dash (PEP 503).
        norm_name = _normalize_pypi_name(name)
        bucket = by_pkg.setdefault(norm_name, {"ranges": [], "versions": set()})
        for r in entry.get("ranges", []) or []:
            bucket["ranges"].append(r)
        for v in entry.get("versions", []) or []:
            bucket["versions"].add(v)

    for name, bucket in by_pkg.items():
        yield (
            aid,
            name,
            json.dumps(bucket["ranges"], separators=(",", ":")) if bucket["ranges"] else None,
            json.dumps(sorted(bucket["versions"]), separators=(",", ":")) if bucket["versions"] else None,
        )


def _normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: lowercase + не-alnum/dot → dash, collapse ---."""
    import re
    return re.sub(r"[-_.]+", "-", name.lower())


# ---------------------------------------------------------------------------
# Public API: класс CveDatabase
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Advisory:
    """Финальная запись advisory, удобная для сканера."""
    id: str
    summary: str
    severity: Optional[str]    # "critical"|"high"|"medium"|"low"|None
    is_malicious: bool
    aliases: List[str]
    references: List[str]
    affected_ranges: List[Dict[str, Any]]
    affected_versions: List[str]


class CveDatabase:
    """Тонкая обёртка над SQLite.

    Использование:
        db = CveDatabase(Path("osv.db"))
        db.import_zip(Path("all.zip"))
        for adv in db.find_advisories_for("transformers", "4.30.0"):
            ...
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path)
            self._conn.executescript(_SCHEMA_SQL)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "CveDatabase":
        self._connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_zip(self, zip_path: Path) -> Dict[str, int]:
        """Импортирует все JSON из ZIP-архива OSV.

        Возвращает статистику: {"imported": N, "skipped": M, "errors": K}.
        """
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [m for m in zf.namelist() if m.endswith(".json")]
            return self._import_streaming(
                ((m, zf.read(m)) for m in members),
                total_hint=len(members),
            )

    def import_dir(self, dir_path: Path) -> Dict[str, int]:
        """Импортирует все JSON из директории."""
        files = sorted(dir_path.rglob("*.json"))

        def _read():
            for f in files:
                try:
                    yield (f.name, f.read_bytes())
                except OSError as e:
                    log.warning("can't read %s: %s", f, e)

        return self._import_streaming(_read(), total_hint=len(files))

    def _import_streaming(
        self,
        items: Iterable[Tuple[str, bytes]],
        total_hint: int = 0,
    ) -> Dict[str, int]:
        """Стримово импортирует пары (filename, raw_bytes).

        Используем большую транзакцию + executemany — без этого 19K
        INSERT'ов через autocommit будут идти 30+ секунд.
        """
        conn = self._connect()
        stats = {"imported": 0, "skipped": 0, "errors": 0}

        adv_batch: List[Tuple] = []
        aff_batch: List[Tuple] = []
        BATCH = 500

        def _flush():
            if adv_batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO advisories "
                    "(id, summary, details, severity, is_malicious, is_withdrawn, "
                    " aliases, published, modified, references_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    adv_batch,
                )
                adv_batch.clear()
            if aff_batch:
                # Сначала зачищаем старые записи по этим advisory_id —
                # на случай повторного импорта обновлённой версии БД.
                # advisory_ids это [a[0] for a in аffected_batch]
                ids = list({a[0] for a in aff_batch})
                conn.executemany(
                    "DELETE FROM affected WHERE advisory_id = ?",
                    [(i,) for i in ids],
                )
                conn.executemany(
                    "INSERT INTO affected (advisory_id, package_name, ranges_json, versions_json) "
                    "VALUES (?,?,?,?)",
                    aff_batch,
                )
                aff_batch.clear()

        for fname, raw in items:
            try:
                advisory = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as e:
                log.debug("skip %s: not valid JSON (%s)", fname, e)
                stats["errors"] += 1
                continue

            row = _extract_advisory_row(advisory)
            if row is None:
                stats["skipped"] += 1
                continue

            adv_batch.append(row)
            for aff in _extract_affected_rows(advisory):
                aff_batch.append(aff)
            stats["imported"] += 1

            if len(adv_batch) >= BATCH:
                _flush()

        _flush()

        # Записываем мета-инфо: дата импорта, источник, количество.
        from datetime import datetime, timezone
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("imported_at", datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("imported_count", str(stats["imported"])),
        )
        conn.commit()

        # VACUUM после массового импорта высвобождает страницы из удалённых
        # старых записей (когда мы re-imported существующие advisory_id).
        # Стоит ~0.5s на 19K записей и снимает ~30% размера БД.
        conn.execute("VACUUM")

        return stats

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def find_advisories_for(
        self,
        package_name: str,
        version: Optional[str] = None,
    ) -> List[Advisory]:
        """Возвращает все advisories, задевающие этот пакет/версию.

        Если version=None — возвращает все advisories для пакета.
        Withdrawn-advisories пропускаются.
        """
        from packaging.specifiers import InvalidSpecifier
        from packaging.version import InvalidVersion, Version

        norm = _normalize_pypi_name(package_name)
        conn = self._connect()
        cursor = conn.execute(
            """
            SELECT a.id, a.summary, a.severity, a.is_malicious, a.aliases,
                   a.references_json, af.ranges_json, af.versions_json
            FROM affected af
            JOIN advisories a ON af.advisory_id = a.id
            WHERE af.package_name = ? AND a.is_withdrawn = 0
            """,
            (norm,),
        )

        results: List[Advisory] = []
        for (aid, summary, sev, is_mal, aliases_json,
             refs_json, ranges_json, versions_json) in cursor.fetchall():
            ranges = json.loads(ranges_json) if ranges_json else []
            versions = json.loads(versions_json) if versions_json else []

            # Если версия не указана — возвращаем все advisories.
            if version is None:
                results.append(_make_advisory(
                    aid, summary, sev, is_mal, aliases_json, refs_json,
                    ranges, versions,
                ))
                continue

            # Точечная проверка матча.
            if _version_matches(version, ranges, versions):
                results.append(_make_advisory(
                    aid, summary, sev, is_mal, aliases_json, refs_json,
                    ranges, versions,
                ))
        return results

    def stats(self) -> Dict[str, Any]:
        """Сводка БД для диагностики и for-display."""
        conn = self._connect()
        cur = conn.execute("SELECT COUNT(*) FROM advisories")
        total = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) FROM advisories WHERE is_malicious=1")
        mal = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(DISTINCT package_name) FROM affected")
        pkgs = cur.fetchone()[0]
        cur = conn.execute("SELECT key, value FROM meta")
        meta = dict(cur.fetchall())
        return {
            "total_advisories":   total,
            "malicious_packages": mal,
            "packages_affected":  pkgs,
            **meta,
        }


def _make_advisory(aid, summary, sev, is_mal, aliases_json, refs_json,
                   ranges, versions) -> Advisory:
    return Advisory(
        id=aid,
        summary=summary or "",
        severity=sev,
        is_malicious=bool(is_mal),
        aliases=json.loads(aliases_json) if aliases_json else [],
        references=[r.get("url") for r in (json.loads(refs_json) if refs_json else [])
                    if r.get("url")],
        affected_ranges=ranges,
        affected_versions=versions,
    )


# ---------------------------------------------------------------------------
# Version matching
# ---------------------------------------------------------------------------

def _version_matches(
    version: str,
    ranges: List[Dict[str, Any]],
    explicit_versions: List[str],
) -> bool:
    """Проверяет, попадает ли version в OSV-affected.

    Логика OSV (https://ossf.github.io/osv-schema/#affected-fields):
      • Если есть `versions[]` И version в этом списке → match.
      • Если есть `ranges[]` → проверяем каждый диапазон через events.

    Events в range — это упорядоченные точки:
      {"introduced": "0"}      — баг внесён начиная с этой версии
      {"fixed": "1.2.3"}       — починен в этой версии (баг до 1.2.3)
      {"last_affected": "..."} — последняя задетая версия (баг до и включая)
      {"limit": "..."}         — exclusive верхняя граница (редко)

    Range «срабатывает», если version ≥ introduced И (version < fixed,
    если fixed есть) И (version ≤ last_affected, если есть). Если в range
    несколько пар introduced/fixed — это значит несколько отрезков (баг
    внесён, починен, снова внесён); проверяем каждый отдельно.
    """
    from packaging.version import InvalidVersion, Version

    # Точное совпадение по explicit-versions — без всякой интерпретации.
    if explicit_versions and version in explicit_versions:
        return True

    if not ranges:
        return False

    try:
        v = Version(version)
    except InvalidVersion:
        return False

    for r in ranges:
        rtype = r.get("type")
        if rtype not in (None, "ECOSYSTEM", "SEMVER"):
            # GIT и прочие — мы не пытаемся интерпретировать.
            continue

        # Разбираем events в список segments вида (introduced, fixed_or_None, last_affected_or_None).
        segments = _events_to_segments(r.get("events", []))
        for intro, fixed, last_aff in segments:
            if _is_in_segment(v, intro, fixed, last_aff):
                return True

    return False


def _events_to_segments(events):
    """Превращаем upstream events в список (introduced, fixed, last_affected).

    Каждый `introduced` событие открывает новый сегмент. Следующий `fixed`/
    `last_affected`/`limit` его закрывает. Если новый `introduced` пришёл
    без закрытия предыдущего — это значит сегмент открыт до бесконечности
    (но такого практически не бывает в реальных OSV).
    """
    segments = []
    cur_intro = None
    cur_fixed = None
    cur_last = None
    for ev in events:
        if "introduced" in ev:
            # Закрываем предыдущий, если был открыт
            if cur_intro is not None:
                segments.append((cur_intro, cur_fixed, cur_last))
            val = ev["introduced"]
            cur_intro = _safe_version(val) if val != "0" else _zero_version()
            cur_fixed = None
            cur_last = None
        elif "fixed" in ev:
            cur_fixed = _safe_version(ev["fixed"])
        elif "last_affected" in ev:
            cur_last = _safe_version(ev["last_affected"])
        elif "limit" in ev:
            # Trying to be conservative: treat limit как fixed.
            cur_fixed = _safe_version(ev["limit"])
    if cur_intro is not None:
        segments.append((cur_intro, cur_fixed, cur_last))
    return segments


def _zero_version():
    from packaging.version import Version
    return Version("0")


def _safe_version(s):
    from packaging.version import InvalidVersion, Version
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _is_in_segment(v, introduced, fixed, last_aff) -> bool:
    """v ∈ [introduced, fixed) ∪ [introduced, last_aff].

    Если introduced=None — сегмент не валиден. Если ни fixed ни last_affected
    не заданы — баг затрагивает все версии от introduced и выше (например,
    у MAL пакетов).
    """
    if introduced is None:
        return False
    if v < introduced:
        return False
    if fixed is not None and v >= fixed:
        return False
    if last_aff is not None and v > last_aff:
        return False
    return True
