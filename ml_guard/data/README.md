# Bundled OSV mini-database

This directory contains `osv-mini.sqlite` — a curated subset of the
[OSV vulnerability database](https://osv.dev) covering ~150 popular
ML/Python packages (transformers, torch, numpy, requests, ...).

It exists so that `pip install mlsupplychain` gives you immediate CVE coverage
of typical ML stacks without needing to run `ml-guard cve-update` first.

## When this DB is used

ML Guard searches for the database in this order:

1. `--db` CLI option, or `$ML_GUARD_CVE_DB` env var
2. `$XDG_DATA_HOME/ml-guard/osv.db` (this is what `cve-update` writes)
3. **This bundled file** (read-only fallback)

If you've run `cve-update` once, the user-installed DB shadows the bundled
one. The bundled DB is meant strictly as a "works-out-of-the-box" default.

## Limitations

- **Coverage**: only the ~150 packages listed in
  `scripts/popular-ml-packages.txt`. Anything else: the bundled DB returns
  no findings (silently — not an error).
- **Freshness**: the DB snapshot is taken at release time. CVEs published
  after the wheel was built won't be in it. **For production CI, run
  `ml-guard cve-update <path-to-osv.zip>` weekly** to stay current.
- **Size**: ~4 MB raw, ~500 KB compressed in the wheel.

## Rebuilding (for maintainers)

```bash
wget https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
python scripts/build_mini_osv.py --source all.zip
```
