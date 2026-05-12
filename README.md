# ML Guard

[![PyPI](https://img.shields.io/pypi/v/mlsupplychain?logo=pypi&logoColor=white)](https://pypi.org/project/mlsupplychain/)
[![Python](https://img.shields.io/pypi/pyversions/mlsupplychain?logo=python&logoColor=white)](https://pypi.org/project/mlsupplychain/)
[![Downloads](https://img.shields.io/pypi/dm/mlsupplychain?logo=pypi&logoColor=white)](https://pypi.org/project/mlsupplychain/)
[![License](https://img.shields.io/github/license/ml-guard/ml-guard)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/ml-guard/ml-guard/ci.yml?branch=main&logo=github)](https://github.com/ml-guard/ml-guard/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-ML%20Guard%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/ml-guard-security-scan)

> Security & compliance scanner for ML pipelines — `docker scan` for the ML world.

ML Guard scans the artifacts your team ships — model weights, configs,
dependency manifests, notebooks — and flags problems before they reach
production: malicious pickle code, embedded executables in safetensors,
ONNX models with custom plugins, leaked API keys, vulnerable PyPI
dependencies, malicious packages.

It runs offline. It produces SARIF for native GitHub Code Scanning,
CycloneDX SBOMs for audit, and PDF compliance reports for **EU AI Act,
NIST AI RMF, ISO 27001, and SOC 2**.

## Status

`v0.1.0` — first public release. All five scanners and the compliance
reporter are production-ready; 152 tests cover the codepaths.

| Scanner       | Status     | What it catches                                         |
| ------------- | ---------- | ------------------------------------------------------- |
| `pickle`      | ✓ shipped  | RCE globals, suspicious modules, PyTorch ZIP, proto≥4   |
| `safetensors` | ✓ shipped  | trailing payloads, malformed offsets, embedded URIs     |
| `onnx`        | ✓ shipped  | custom domain ops, suspicious external_data, shells    |
| `secrets`     | ✓ shipped  | AWS/GitHub/OpenAI keys, JWTs, PEM keys, generic entropy |
| `cve`         | ✓ shipped  | OSV cross-check of `requirements.txt` (offline DB)      |

## Install

```bash
# Pure-Python, works everywhere; ~640 KB wheel including bundled OSV DB.
pip install mlsupplychain
```

The wheel ships with a curated mini OSV database covering ~150 popular
ML packages, so `pip install mlsupplychain && ml-guard scan` finds real
vulnerabilities **out of the box** — no setup. For full CVE coverage
across all PyPI:

```bash
wget https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
ml-guard cve-update all.zip
```

> **Note on naming**: the package on PyPI is `mlsupplychain` (because
> `mlguard` was already taken by an unrelated project). The CLI command
> is still `ml-guard` for everyday use. Think of it like
> `pip install scikit-learn` giving you `import sklearn`.

## Quick start

```bash
ml-guard scan ./my-project
```

```
ML Guard — scan report
========================================
Files scanned: 5    Time: 0.04s
Summary:       6 critical, 12 high, 21 medium, 3 low

✗ CRITICAL  model.pkl  [offset 0x2a1]
            Dangerous global imported: os.system (known RCE primitive)
✗ CRITICAL  requirements.txt  [package ascii2text==1.0]
            Malicious package detected (advisory MAL-2022-7421).
✗ CRITICAL  requirements.txt  [package transformers==4.30.0]
            CVE-2023-6730: Deserialization of Untrusted Data vulnerability
! HIGH      .env  [line 1]
            GitHub Personal Access Token detected
            snippet: ghp_…6789 (len=40)
...
```

Exit code is 1 if any finding meets `--fail-on` (default: `critical`).

## CI integration

```yaml
- uses: ml-guard/scan-action@v1
  with:
    path: ./models
    fail-on: critical
    format: sarif
    output: ml-guard.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ml-guard.sarif
```

The SARIF report appears in **Security → Code scanning** in your repo.

## Compliance reports

ML Guard produces machine-readable evidence for four standards:

| Standard      | ID            | What we cover                                          |
| ------------- | ------------- | ------------------------------------------------------ |
| EU AI Act     | `eu-ai-act`   | Articles 9, 10, 11, 12, 13, 15 — risk management,     |
|               |               | record-keeping, technical documentation, cybersecurity |
| NIST AI RMF   | `nist-ai-rmf` | MEASURE 2.7, 2.10; MANAGE 4.1                          |
| ISO/IEC 27001 | `iso-27001`   | Annex A: 5.23, 5.34, 8.4, 8.7, 8.8, 8.25, 8.28        |
| SOC 2         | `soc2`        | Common Criteria: CC6.1, 6.6, 6.7, 6.8, 7.1, 7.2       |

Generate a PDF for an audit:

```bash
ml-guard compliance ./models --standard iso-27001 --output report.pdf
```

The PDF includes verdict, control-by-control evidence with file/line
references, full findings appendix, and an integrity SHA-256.

**Important caveat for auditors:** these reports are *machine-readable
technical evidence*, not conformity declarations. Determination of
regulatory compliance requires assessment by a qualified person
(notified body, DPO, CPA firm).

## SBOM

```bash
ml-guard sbom ./models -o ml-bom.json
```

Produces a CycloneDX 1.5 JSON with every artifact (SHA-256 hashed),
dependency manifest entries, and findings encoded as `vulnerabilities`
with proper `bom-ref` links. Drops directly into Dependency-Track,
DefectDojo, sbom-utility, and the like.

## Configuration

Drop a `.ml-guard.yml` in your project root:

```yaml
fail_on: high                 # CI-only override (default: critical)
include:
  - 'models/*.pkl'
  - 'configs/*.yaml'
exclude:
  - 'tests/fixtures/**'
scanners:
  - pickle
  - secrets
rules:
  pickle-unusual-module:
    severity: low             # downgrade
  secret-stripe-test:
    disabled: true            # silence entirely
```

CLI flags always override config; config provides defaults.

## Output formats

| Format  | Flag             | Use case                                       |
| ------- | ---------------- | ---------------------------------------------- |
| `text`  | `--format text`  | humans (default, colorized)                    |
| `json`  | `--format json`  | scripts, custom dashboards                     |
| `sarif` | `--format sarif` | GitHub Code Scanning, GitLab SAST, IDE plugins |

## Why pickle is the #1 priority

`pickle.load()` and `torch.load()` execute arbitrary Python code by design.
A 200-byte `.pkl` file can drop a reverse shell when a data scientist
opens it. ML Guard parses the pickle bytecode statically — **never
executing it** — and flags every callable resolved before deserialization
happens. See `docs/pickle-threat-model.md` for full attack surface.

## Architecture

```
ml_guard/
├── findings.py              # Finding/Severity dataclasses
├── runner.py                # walks paths, dispatches scanners
├── cli.py                   # click entrypoint
├── config.py                # .ml-guard.yml loader
├── compliance.py            # EU AI Act / NIST AI RMF / ISO 27001 / SOC 2
├── sbom.py                  # CycloneDX 1.5 generator
├── cve_db.py                # SQLite OSV index
├── _pdf.py                  # in-tree PDF 1.4 writer (no reportlab dep)
├── _protobuf.py             # in-tree protobuf reader (no onnx dep)
├── data/
│   └── osv-mini.sqlite      # bundled mini OSV DB (~530 KB compressed)
├── scanners/
│   ├── pickle_scanner.py
│   ├── safetensors_scanner.py
│   ├── onnx_scanner.py
│   ├── secret_scanner.py
│   └── cve_scanner.py
└── output/
    ├── text.py
    ├── json_fmt.py
    └── sarif.py
rust_engine/                  # optional native acceleration via PyO3
```

The Rust engine is **opt-in** via `pip install mlsupplychain[native]`. Without
it, every scanner runs on pure Python with the same correctness
guarantees — just slower on multi-gigabyte artifacts.

## Documentation

- [`docs/rules.md`](docs/rules.md) — full catalog of rules, severities,
  and override examples.
- [`docs/pickle-threat-model.md`](docs/pickle-threat-model.md) — what we
  cover and what we don't, with attack patterns explained.
- [`docs/cve-database.md`](docs/cve-database.md) — OSV update workflow.
- [`docs/performance.md`](docs/performance.md) — real benchmark numbers.
- [`docs/releasing.md`](docs/releasing.md) — for maintainers.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security policy:
[`SECURITY.md`](SECURITY.md).

## License

Apache 2.0. See [`LICENSE`](LICENSE).
