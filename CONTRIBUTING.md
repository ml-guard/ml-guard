# Contributing to ML Guard

Thanks for your interest! ML Guard is a security tool, so the contribution
process is more careful than average — but we welcome PRs.

## Quick start

```bash
git clone https://github.com/ml-guard/ml-guard
cd ml-guard
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# Run all tests
pytest

# Or, without pytest, use the bundled stdlib runner:
python3 run_tests.py

# Lint and types
ruff check ml_guard tests
mypy ml_guard
```

## Adding a new scanner

Each scanner is a class registered via the `@register` decorator. Pattern:

```python
# ml_guard/scanners/myformat_scanner.py
from pathlib import Path
from typing import List

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register


@register
class MyFormatScanner(Scanner):
    name = "myformat"
    description = "Detects ... in .myformat files"

    def can_scan(self, path: Path) -> bool:
        return path.is_file() and path.suffix.lower() == ".myformat"

    def scan(self, path: Path) -> List[Finding]:
        # ... your detection logic ...
        return [Finding(
            rule_id="myformat-bad-thing",
            severity=Severity.HIGH,
            message="Found bad thing",
            file="",          # filled in by Runner
            scanner=self.name,
            location="offset 0x..",
        )]
```

Then:

1. Add `import ml_guard.scanners.myformat_scanner` in `ml_guard/cli.py`
   (next to the others) so that the registry sees it on CLI startup.
2. Add an entry to `docs/rules.md` describing each `rule_id`.
3. Write tests in `tests/test_myformat_scanner.py`.

## Adding a rule to existing scanner

1. Pick a stable `rule_id`. Convention: `<scanner>-<short-name>` in kebab-case.
   Once shipped, the ID is part of public API — never rename.
2. Write the detection in the existing scanner module.
3. Add the rule to `docs/rules.md`.
4. Write at least one test for the rule (positive case + a regression
   for the most likely false-positive).

## Code style

- Python 3.9+. We do not use `match`/`PEP 695` features.
- Type hints on all public APIs. Internal helpers can be untyped.
- 100-char lines, but readability beats the limit (some long error
  messages are fine).
- No `print()` for end-user output — use `click.echo()` or a logger.
- No new third-party dependencies in `[project] dependencies` without
  discussion. We're a security tool: every dep is a supply-chain CVE
  surface.

## Testing

Everything must have tests. The bar is a bit higher than typical:

- A new scanner must reach **>90% line coverage** of its module.
- A new rule must have at least 2 tests (positive case + one
  false-positive guard).
- Existing tests must keep passing on Python 3.9–3.13 across Linux/macOS.

For tests that need a real OSV dump (those go in
`tests/test_cve_real.py` once we move them), gate them with
`@pytest.mark.integration` so they're skipped when the dump isn't
present.

## Security policy for contributions

- Never add code that runs scanned files. All analysis is static.
- Never add code that uploads scanner output to a third party. The tool
  must work air-gapped.
- Pickle/ONNX/any-binary parsers must have explicit DoS guards (size
  cap, depth limit, opcode count cap). See existing scanners for the
  pattern.
- New regex-based detection must include both: (a) at least one
  positive test, (b) at least one false-positive case demonstrating
  it doesn't fire on common benign patterns.

## Submitting a PR

1. Fork → branch → PR against `main`.
2. Include test changes in the same PR.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. Sign off your commits (`git commit -s`) — we use Developer Certificate
   of Origin (DCO).
5. CI must pass on all matrix entries.

## Releasing (maintainers only)

See `docs/releasing.md`.
