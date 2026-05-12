#!/usr/bin/env python3
"""Build the bundled mini OSV database shipped with ml-guard wheels.

This script is run by maintainers (and the release workflow), not by end users.
End users get a full, fresh DB via `ml-guard cve-update <path-to-osv.zip>`;
the bundled DB exists so that `pip install mlsupplychain && ml-guard scan` Just
Works on the most common ML stack out of the box.

Inputs:
    - --source PATH          OSV dump (ZIP from osv-vulnerabilities.storage...
                              or a directory of *.json files).
    - --packages-file PATH   Newline-separated list of PyPI package names to
                              keep. Defaults to scripts/popular-ml-packages.txt.
    - --output PATH          Where to write the SQLite DB.
                              Defaults to ml_guard/data/osv-mini.sqlite.

Output:
    A SQLite DB containing only advisories whose `affected[].package.name`
    matches one of the listed packages, plus a small `meta` row indicating
    when it was built. Typical size: 1–3 MB.

Why a curated subset:
    The full OSV PyPI dump is ~20 MB compressed and would dominate wheel
    size. End users running `cve-update` with the full dump shadow this
    file (we always merge: the runtime DB is at $XDG_DATA_HOME/ml-guard/,
    bundled is read-only fallback).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterator, Set, Tuple


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True,
                   help="OSV ZIP archive or directory of JSON files")
    p.add_argument("--packages-file", type=Path,
                   default=Path(__file__).parent / "popular-ml-packages.txt")
    p.add_argument("--output", type=Path,
                   default=Path(__file__).parent.parent
                   / "ml_guard" / "data" / "osv-mini.sqlite")
    p.add_argument("--max-records", type=int, default=10000,
                   help="Hard cap on number of advisories to keep (size guard)")
    return p.parse_args()


def load_package_names(path: Path) -> Set[str]:
    names: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # PyPI names are case-insensitive; we lowercase everywhere.
        names.add(line.lower().replace("_", "-"))
    return names


def iter_zip_entries(zip_path: Path) -> Iterator[Tuple[str, bytes]]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                yield name, zf.read(name)
            except (KeyError, zipfile.BadZipFile):
                continue


def iter_dir_files(dir_path: Path) -> Iterator[Tuple[str, bytes]]:
    for fp in sorted(dir_path.rglob("*.json")):
        try:
            yield fp.name, fp.read_bytes()
        except OSError:
            continue


def normalize_pypi_name(name: str) -> str:
    """PyPI normalization: lowercase, '_' → '-'. Underscores and dashes
    are equivalent (PEP 503)."""
    return name.lower().replace("_", "-")


def filter_advisories(entries: Iterator[Tuple[str, bytes]],
                      keep_packages: Set[str],
                      max_records: int) -> Iterator[bytes]:
    """Yield raw bytes of OSV records whose affected packages overlap
    with `keep_packages` (PyPI ecosystem only)."""
    yielded = 0
    for _, raw in entries:
        if yielded >= max_records:
            break
        try:
            doc = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if doc.get("withdrawn"):
            continue

        for a in doc.get("affected", []):
            if not isinstance(a, dict):
                continue
            pkg = a.get("package") or {}
            if pkg.get("ecosystem") != "PyPI":
                continue
            name = pkg.get("name") or ""
            if normalize_pypi_name(name) in keep_packages:
                yield raw
                yielded += 1
                break


def main() -> int:
    args = parse_args()

    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ml_guard.cve_db import CveDatabase

    if not args.source.exists():
        print(f"ERROR: source not found: {args.source}", file=sys.stderr)
        return 1

    keep = load_package_names(args.packages_file)
    print(f"Loaded {len(keep)} package names from {args.packages_file}")

    if args.source.is_dir():
        entries = iter_dir_files(args.source)
    else:
        entries = iter_zip_entries(args.source)

    # Write filtered JSON into a temp directory, then build the DB
    # via the standard importer.
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        kept = 0
        for raw in filter_advisories(entries, keep, args.max_records):
            (td_path / f"{kept:06d}.json").write_bytes(raw)
            kept += 1
        print(f"Filtered: {kept} advisories matching popular packages")

        if kept == 0:
            print("ERROR: no advisories matched. Check --packages-file.",
                  file=sys.stderr)
            return 1

        # Import the filtered set via the standard CveDatabase
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            args.output.unlink()

        started = time.monotonic()
        with CveDatabase(args.output) as db:
            stats = db.import_dir(td_path)

    elapsed = time.monotonic() - started
    size_kb = args.output.stat().st_size / 1024

    # Shrink bundled-DB: drop references_json (unused during matching,
    # takes ~80% of space) and VACUUM.
    print(f"Pre-shrink size: {size_kb:.0f} KB; shrinking ...")
    import sqlite3 as _sql
    conn = _sql.connect(args.output)
    cur = conn.cursor()
    cur.execute("UPDATE advisories SET references_json = '[]'")
    cur.execute("UPDATE advisories SET details = ''")
    conn.commit()
    cur.execute("VACUUM")
    conn.commit()
    conn.close()

    final_kb = args.output.stat().st_size / 1024
    print(f"Wrote {args.output} ({final_kb:.0f} KB) in {elapsed:.1f}s")
    print(f"Stats: {stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
