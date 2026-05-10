# Security policy

## Reporting a vulnerability

If you find a security issue in ML Guard itself — the scanner, the parsers,
the PDF/SARIF output, or the CVE database loading — please report it
**privately** before disclosing publicly.

**Email:** security@ml-guard.example  *(replace with your real address
on the project's public site once published)*

**Or:** GitHub Security Advisory →
https://github.com/ml-guard/ml-guard/security/advisories/new

We aim to respond within 3 business days.

## Scope

In scope:

- Crashes or hangs on adversarial input (malformed pickles, ONNX, safetensors,
  YAML configs, OSV JSON).
- False negatives in the security-critical paths: pickle RCE detection,
  malicious-package matching, secret detection.
- Path traversal, arbitrary file read/write through ml-guard CLI.
- SARIF/JSON/PDF outputs that can mislead an auditor (e.g. an
  attacker-controlled finding that looks like an integrity attestation).
- Any code path that might execute scanned content (this should never
  happen — all scanners are static).

Out of scope:

- Bugs in the OSV data itself. Report those upstream at
  https://github.com/google/osv.dev.
- Issues in optional integrations (Rust engine, third-party CI plugins)
  unless ml-guard misuses them.
- Cosmetic issues in PDF output.

## Threat model summary

ML Guard is designed to read **untrusted input** safely:

- All file parsers (pickle, ONNX/protobuf, safetensors) operate purely
  statically. We never call `pickle.loads()`, `torch.load()`, or
  `onnx.load()`.
- Every binary parser has explicit DoS guards: size limit, depth limit,
  opcode count cap. See `docs/pickle-threat-model.md`.
- The tool does not make network calls in the default code path. CVE
  data is loaded from a local SQLite file maintained by the user.
- Regex-based detection has timeout-friendly patterns (no
  catastrophic backtracking on adversarial input).

## What we ship

Source-of-truth artifacts are PyPI wheels signed by GitHub's Trusted
Publisher (PEP 740 / Sigstore). To verify a wheel:

```bash
pip install sigstore
python -m sigstore verify identity \
    --cert-identity 'https://github.com/ml-guard/ml-guard/.github/workflows/release.yml@refs/tags/v0.1.0' \
    --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
    mlsupplychain-0.1.0-*.whl
```

GitHub releases also include SHA-256 hashes of every wheel and the sdist.

## Known limitations

The pickle threat model document (`docs/pickle-threat-model.md`) lists
attack patterns we deliberately do not catch (time bombs, side-effect
constructors in unusual modules). These are not vulnerabilities in
ML Guard — they're acknowledged limitations of static pickle analysis.
We still welcome research that broadens the detection.
