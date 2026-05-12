"""SQLite-backed OSV vulnerability index for offline checks.

Why offline:
  • Reproducibility: same inputs → same report. Live OSV changes daily,
    so two CI runs on the same code would diverge.
  • Air-gapped environments (banks, defense, regulated ML teams) are our
    target audience. Live APIs don't work there.
  • Speed: ~50 packages in requirements.txt = 50 HTTP requests at best,
    seconds of latency. SQLite over a local file = milliseconds.
  • Resilience to attack: if osv.dev is offline or compromised, our
    scanner doesn't default to "all clear".

This is how trivy, grype, osv-scanner all work — pre-downloaded DB.

Data flow:
  1. User runs `ml-guard cve-update https://osv-vulnerabilities.../all.zip`
     or points at a local ZIP / JSON directory.
  2. The importer iterates every file and writes rows to SQLite.
  3. The CVE scanner answers matches() queries instantly from the index.

OSV schema: https://ossf.github.io/osv-schema/

Sources in the current dump (all PyPI):
  GHSA   — GitHub Security Advisories (the bulk), ~5K entries, with severity
  PYSEC  — Python Software Foundation, ~3.3K entries
  MAL    — malicious package advisories (typosquatting etc.), ~11K
  ECHO   — echo.guard re-builds, 15
  OSV    — others, ~8
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
# Default DB location
# ---------------------------------------------------------------------------

def default_db_path() -> Path:
    """Where the DB lives by default.

    Follows XDG_DATA_HOME per freedesktop.org. On macOS/Linux that's
    ~/.local/share. On Windows the POSIX default still works in practice,
    though %LOCALAPPDATA% would be more idiomatic.
    """
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "ml-guard" / "osv.db"


# ---------------------------------------------------------------------------
# DB schema
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
# OSV JSON → SQLite row conversion
# ---------------------------------------------------------------------------

# Map database_specific.severity → our severity level (as string, to
# avoid pulling the enum into the DB layer).
_SEVERITY_NORMALIZE = {
    "CRITICAL":  "critical",
    "HIGH":      "high",
    "MODERATE":  "medium",   # GHSA uses the spelling "MODERATE"
    "MEDIUM":    "medium",
    "LOW":       "low",
}


def _normalize_severity(advisory: Dict[str, Any]) -> Optional[str]:
    """Extract the severity text. Sources, in priority order:
       1. database_specific.severity (GHSA — most reliable)
       2. severity[*].score CVSS — hand-parsed
       3. None — PYSEC/MAL/ECHO records without explicit severity
    """
    db = advisory.get("database_specific") or {}
    raw = db.get("severity")
    if isinstance(raw, str):
        norm = _SEVERITY_NORMALIZE.get(raw.upper())
        if norm:
            return norm

    # CVSS — take the first entry and parse Base Score. Full CVSS scoring
    # is involved; for CVSSv3 you can just inspect the Impact/Exploitability
    # components. Skipped here for simplicity. The mere presence of a
    # CVSS vector implies at least LOW.
    sev_list = advisory.get("severity") or []
    if sev_list:
        return "medium"   # conservative fallback: "something is here, not nothing"

    return None


def _is_malicious(advisory: Dict[str, Any]) -> bool:
    """MAL-* advisories describe outright malicious packages.

    We also check `database_specific.malicious-packages-origins`, which is
    set explicitly on GHSA-malware records.
    """
    if (advisory.get("id") or "").startswith("MAL-"):
        return True
    db = advisory.get("database_specific") or {}
    if db.get("malicious-packages-origins"):
        return True
    return False


def _is_withdrawn(advisory: Dict[str, Any]) -> bool:
    """`withdrawn` is an OSV-spec field: the date the advisory was withdrawn.

    If set, the advisory is considered invalid and shouldn't be reported.
    We still store it in the DB for audit purposes ("was there ever a
    warning?").
    """
    return bool(advisory.get("withdrawn"))


def _extract_advisory_row(advisory: Dict[str, Any]) -> Optional[Tuple]:
    """One OSV record → a row for the advisories table.

    Returns None if the record is unusable (missing id or affected).
    """
    aid = advisory.get("id")
    if not aid:
        return None

    return (
        aid,
        (advisory.get("summary") or "").strip()[:500],
        # `details` is usually a long markdown wall — we don't need it.
        # `summary` carries the same gist in one line. Anyone who wants more
        # can follow references_json.
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
    """One OSV record → many rows for the affected table (one per package).

    Dedup by package_name within a single advisory: some OSV records list
    the same package in multiple affected[] blocks (different range
    strategies). We aggregate ranges/versions into a single row.
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
        # PyPI names: normalize to lowercase + dash (PEP 503).
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
    """PEP 503 normalization: lowercase + non-alnum/dot → dash, collapse ---."""
    import re
    return re.sub(r"[-_.]+", "-", name.lower())


# ---------------------------------------------------------------------------
# Public API: CveDatabase class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Advisory:
    """Final advisory record, ready for the scanner."""
    id: str
    summary: str
    severity: Optional[str]    # "critical"|"high"|"medium"|"low"|None
    is_malicious: bool
    aliases: List[str]
    references: List[str]
    affected_ranges: List[Dict[str, Any]]
    affected_versions: List[str]


class CveDatabase:
    """Thin wrapper around SQLite.

    Usage:
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
        """Import all JSON from an OSV ZIP archive.

        Returns stats: {"imported": N, "skipped": M, "errors": K}.
        """
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [m for m in zf.namelist() if m.endswith(".json")]
            return self._import_streaming(
                ((m, zf.read(m)) for m in members),
                total_hint=len(members),
            )

    def import_dir(self, dir_path: Path) -> Dict[str, int]:
        """Import all JSON files from a directory."""
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
        """Stream-import (filename, raw_bytes) pairs.

        We use one big transaction + executemany — without this, 19K
        INSERTs via autocommit would take 30+ seconds.
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
                # Clear existing rows for these advisory_ids first —
                # supports re-importing an updated dump cleanly.
                # advisory_ids is [a[0] for a in affected_batch]
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

        # Store meta: import date, source, count.
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

        # VACUUM after bulk import reclaims pages from deleted old rows
        # (e.g. when we re-imported existing advisory_ids). Costs ~0.5s on
        # 19K records and saves ~30% of DB size.
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
        """Return all advisories affecting this package/version.

        version=None returns every advisory for the package.
        Withdrawn advisories are skipped.
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

            # No version given — return all advisories.
            if version is None:
                results.append(_make_advisory(
                    aid, summary, sev, is_mal, aliases_json, refs_json,
                    ranges, versions,
                ))
                continue

            # Range-match check.
            if _version_matches(version, ranges, versions):
                results.append(_make_advisory(
                    aid, summary, sev, is_mal, aliases_json, refs_json,
                    ranges, versions,
                ))
        return results

    def stats(self) -> Dict[str, Any]:
        """DB summary for diagnostics and display."""
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
    """Decide whether `version` lies inside any OSV-affected range.

    OSV logic (https://ossf.github.io/osv-schema/#affected-fields):
      • If `versions[]` is present AND version is in that list → match.
      • If `ranges[]` is present → check each range via its events.

    Range events are ordered points:
      {"introduced": "0"}      — bug introduced starting at this version
      {"fixed": "1.2.3"}       — fixed in this version (bug exists below)
      {"last_affected": "..."} — last affected version (bug exists up to & including)
      {"limit": "..."}         — exclusive upper bound (rare)

    A range "fires" when version >= introduced AND (version < fixed, if
    fixed exists) AND (version <= last_affected, if present). If a range
    has multiple introduced/fixed pairs, that's multiple segments (bug
    introduced, fixed, introduced again); we check each separately.
    """
    from packaging.version import InvalidVersion, Version

    # Exact match against explicit versions[] — no interpretation needed.
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
            # GIT and friends — we don't try to interpret them.
            continue

        # Parse events into segments: (introduced, fixed_or_None, last_affected_or_None).
        segments = _events_to_segments(r.get("events", []))
        for intro, fixed, last_aff in segments:
            if _is_in_segment(v, intro, fixed, last_aff):
                return True

    return False


def _events_to_segments(events):
    """Turn upstream events into segments: (introduced, fixed, last_affected).

    Each `introduced` event opens a new segment. The next `fixed`/
    `last_affected`/`limit` closes it. If a new `introduced` arrives
    without closing the previous segment, the old one extends to infinity
    (practically never seen in real OSV data).
    """
    segments = []
    cur_intro = None
    cur_fixed = None
    cur_last = None
    for ev in events:
        if "introduced" in ev:
            # Close the previous segment if one was open
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
            # Trying to be conservative: treat limit as fixed.
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

    introduced=None means the segment isn't valid. With neither fixed nor
    last_affected set, the bug affects all versions from introduced onward
    (typical for MAL packages).
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
