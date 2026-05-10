# ML Guard rules catalog

Every finding ml-guard emits has a stable `rule_id`. This is what you tag in
`.ml-guard.yml` to lower a severity, suppress a rule, or filter SARIF output.

`rule_id` is part of the public API: it never changes between releases. New
rules get new IDs, deprecated rules keep working until the next major version.

## How to suppress / re-tune a rule

```yaml
# .ml-guard.yml
rules:
  pickle-unusual-module:
    severity: low                     # lower it instead of 'medium'
  safetensors-metadata-url:
    disabled: true                    # turn it off entirely
```

CLI:

```bash
ml-guard scan . --fail-on high        # ignore everything below 'high'
ml-guard scan . --scanners pickle     # only run pickle scanner
```

---

## Pickle scanner (`scanner: pickle`)

Static analysis of pickle bytecode. Never executes the file.

| Rule ID                          | Severity | Description                                                              |
| -------------------------------- | -------- | ------------------------------------------------------------------------ |
| `pickle-dangerous-global`        | critical | A known-RCE primitive was imported (`os.system`, `eval`, `subprocess.Popen`, `ctypes.CDLL`, …). |
| `pickle-suspicious-module`       | high     | A module unrelated to ML weights was imported (`socket`, `requests`, `shutil`, …). |
| `pickle-unusual-module`          | medium   | Some non-standard module was imported. Common in mixed pickles; review and either trust or refactor. |
| `pickle-stack-global-opaque`     | medium   | `STACK_GLOBAL` opcode used with non-string operands — possible obfuscation. |
| `pickle-deprecated-opcode`       | low      | Python-2-era `INST` or `OBJ` opcode encountered.                         |
| `pickle-parse-error`             | medium   | Stream is malformed (truncated or claims invalid opcodes).               |
| `pickle-bad-zip`                 | medium   | PyTorch ZIP container is corrupt.                                        |
| `pickle-too-large`               | low      | File exceeded the 2 GiB scan limit; skipped.                             |
| `pickle-inner-too-large`         | low      | Nested pickle inside a PyTorch ZIP exceeded 256 MiB; skipped.            |
| `pickle-too-many-opcodes`        | low      | (Native engine only) Stopped after 5 M opcodes (DoS guard).              |

## Safetensors scanner (`scanner: safetensors`)

Validates the wire format and looks for hidden payloads.

| Rule ID                          | Severity | Description                                                              |
| -------------------------------- | -------- | ------------------------------------------------------------------------ |
| `safetensors-executable-trailing`| critical | Trailing bytes after the last tensor begin with an executable signature (ELF, MZ, Mach-O, shebang, …). |
| `safetensors-malformed-header`   | high     | Header length is wrong, JSON invalid, or declared header_size exceeds file size. |
| `safetensors-out-of-bounds`      | high     | A tensor's `data_offsets[end]` extends past the data section.            |
| `safetensors-inverted-offsets`   | high     | A tensor declares `start > end`.                                         |
| `safetensors-negative-offset`    | high     | Tensor offsets are negative.                                             |
| `safetensors-overlapping-tensors`| high     | Two tensors' byte ranges overlap.                                        |
| `safetensors-size-mismatch`      | high     | `numel * dtype_bytes ≠ end − start` — the tensor description lies about its size. |
| `safetensors-shape-overflow`     | high     | Shape product overflows.                                                 |
| `safetensors-unknown-dtype`      | medium   | Dtype is not in the official list (e.g. `F999`).                         |
| `safetensors-hidden-data`        | medium   | More than 64 bytes of trailing data with no executable signature.        |
| `safetensors-invalid-tensor-entry`| medium  | A tensor entry is missing required fields or has wrong types.            |
| `safetensors-metadata-url`       | low      | A URL appears in `__metadata__`.                                         |
| `safetensors-metadata-ip`        | medium   | A non-loopback IP appears in `__metadata__`.                             |
| `safetensors-metadata-path`      | low      | An absolute filesystem path appears in `__metadata__`.                   |
| `safetensors-too-large`          | low      | File exceeded the 16 GiB scan limit; skipped.                            |

## ONNX scanner (`scanner: onnx`)

Parses the protobuf wire format directly (does not depend on the `onnx` library).

| Rule ID                            | Severity | Description                                                            |
| ---------------------------------- | -------- | ---------------------------------------------------------------------- |
| `onnx-custom-domain-op`            | high     | An operator from a non-standard, non-vendor domain (e.g. `evil.exfil`) is used. The runtime will load it as a native plugin. |
| `onnx-non-standard-opset-domain`   | high     | The model declares an `opset_import` from a non-standard domain.       |
| `onnx-vendor-domain-op`            | medium   | Operator from a known vendor domain (`com.microsoft`, `org.pytorch`, …). Requires that runtime to load. |
| `onnx-attr-shell-command`          | high     | A string attribute contains shell-like content (`bash -c`, backticks, `$(...)`, etc.). |
| `onnx-attr-path-traversal`         | high     | A string attribute contains `..` path traversal.                       |
| `onnx-attr-absolute-path`          | medium   | A string attribute contains an absolute filesystem path (`/etc/...`, `C:\Windows\...`). |
| `onnx-attr-url`                    | medium   | A string attribute contains a URL.                                     |
| `onnx-external-absolute-path`      | high     | An `external_data` reference points at an absolute path.               |
| `onnx-external-path-traversal`     | high     | An `external_data` reference contains `..`.                            |
| `onnx-external-url`                | high     | An `external_data` reference is a URL — the loader will fetch it.      |
| `onnx-old-opset`                   | medium   | `ai.onnx` opset_import version is below 7.                             |
| `onnx-old-ir-version`              | medium   | `ir_version` is below 3.                                               |
| `onnx-metadata-url`                | low      | A URL appears in `metadata_props`.                                     |
| `onnx-malformed`                   | medium   | The protobuf is truncated or otherwise malformed.                      |
| `onnx-empty`                       | low      | The `.onnx` file is empty.                                             |
| `onnx-too-many-nodes`              | low      | Stopped after 1 M nodes (DoS guard).                                   |
| `onnx-too-large`                   | low      | File exceeded the 16 GiB scan limit; skipped.                          |

## Secret scanner (`scanner: secrets`)

Pattern + entropy based. All matched secrets are redacted in the output
(`ghp_…6789 (len=40)` style — full secret never reaches the report).

| Rule ID                          | Severity | Description                                                              |
| -------------------------------- | -------- | ------------------------------------------------------------------------ |
| `secret-aws-access-key`          | critical | AWS Access Key ID (`AKIA…`/`ASIA…`).                                     |
| `secret-aws-secret-near-key`     | critical | AWS secret access key in the same line as `aws_secret_access_key=`.      |
| `secret-github-pat`              | critical | GitHub classic PAT (`ghp_…`, `gho_…`, etc.).                             |
| `secret-github-fine-grained-pat` | critical | GitHub fine-grained PAT (`github_pat_…`).                                |
| `secret-private-key`             | critical | PEM-encoded private key (`-----BEGIN ... PRIVATE KEY-----`).             |
| `secret-stripe-live`             | critical | Stripe live secret key (`sk_live_…`).                                    |
| `secret-slack-token`             | high     | Slack token (`xoxb-…`/`xoxp-…`).                                         |
| `secret-slack-webhook`           | high     | Slack webhook URL.                                                       |
| `secret-openai-key`              | high     | OpenAI API key (`sk-…` / `sk-proj-…`).                                   |
| `secret-anthropic-key`           | high     | Anthropic API key (`sk-ant-…`).                                          |
| `secret-huggingface-token`       | high     | Hugging Face token (`hf_…`).                                             |
| `secret-google-api-key`          | high     | Google API key (`AIza…`).                                                |
| `secret-stripe-test`             | medium   | Stripe test key (`sk_test_…`). Lower severity since it's restricted.     |
| `secret-jwt`                     | medium   | JSON Web Token.                                                          |
| `secret-high-entropy`            | medium   | A long high-entropy string adjacent to a key like `password`/`secret`/`token`. Catches custom keys not covered by the regex rules. |
| `secrets-file-too-large`         | low      | File exceeded the 32 MiB scan limit; skipped.                            |

### Placeholders we deliberately ignore

- `AKIAIOSFODNN7EXAMPLE` / `ASIAIOSFODNN7EXAMPLE` — AWS doc examples
- UUIDs (`8-4-4-4-12` hex)
- Strings consisting of one repeated character
- Whole-word tokens like `example`, `placeholder`, `your_secret`, `replace_me`, `dummy`, `xxx+`, `foobar`

## CVE scanner (`scanner: cve`)

Cross-checks pinned dependencies in `requirements*.txt`, `Pipfile.lock`,
`pyproject.toml`, and `environment.yml` against the local OSV database.
See [`docs/cve-database.md`](cve-database.md) for setup.

| Rule ID                   | Severity (varies)            | Description                                                 |
| ------------------------- | ---------------------------- | ----------------------------------------------------------- |
| `cve-malicious-package`   | critical                     | Package matches a `MAL-*` advisory (typosquat / supply-chain) |
| `cve-known-vulnerability` | critical/high/medium/low     | Pinned version is in an `affected` range of an OSV record   |
| `cve-db-missing`          | info                         | OSV database not built — run `ml-guard cve-update <zip>`    |
| `cve-file-too-large`      | low                          | Dependency file exceeds 4 MB; skipped                       |

Severity for `cve-known-vulnerability` comes from the advisory's
`database_specific.severity` field when present; falls back to medium
when missing (e.g. PYSEC entries without an explicit rating).

## Output format and severity propagation

| Severity | SARIF level | CycloneDX score |
| -------- | ----------- | --------------- |
| critical | `error`     | 9.5             |
| high     | `error`     | 7.5             |
| medium   | `warning`   | 5.0             |
| low      | `note`      | 3.0             |
| info     | `note`      | 0.0             |

`--fail-on <severity>` makes the CLI exit with code 1 if any finding is at
or above that level. Default: `critical`.

## Compliance mapping

Each rule contributes to one or more controls in the four supported
standards. A control "FAILS" when at least one of its rules produced a
finding in the scan. A control "PASSES" otherwise (no machine-detectable
violations).

The mapping is declarative — see `ml_guard/compliance.py` for the
authoritative version. Below is a summary of which standards reference
which rules:

| Rule ID                          | EU AI Act | NIST AI RMF | ISO 27001 | SOC 2 |
| -------------------------------- | --------- | ----------- | --------- | ----- |
| `pickle-dangerous-global`        | A9, A15.1 | M2.7        | A.8.7, A.8.28 | CC6.6, CC6.8 |
| `pickle-suspicious-module`       | A9        | M2.7        | A.8.7     | CC6.6, CC7.1 |
| `pickle-stack-global-opaque`     | A9        | —           | A.8.7     | CC7.2 |
| `safetensors-executable-trailing`| A9, A15.1 | M2.7        | A.8.7     | CC6.6, CC6.8 |
| `safetensors-out-of-bounds`      | A10       | —           | —         | CC7.2 |
| `safetensors-overlapping-tensors`| A10       | —           | —         | CC7.2 |
| `safetensors-size-mismatch`      | A10       | —           | —         | CC7.2 |
| `safetensors-hidden-data`        | —         | —           | —         | CC7.2 |
| `safetensors-metadata-url`       | A13       | —           | A.5.34    | CC6.7 |
| `safetensors-metadata-ip`        | —         | —           | A.5.34    | CC6.7 |
| `safetensors-metadata-path`      | —         | —           | —         | CC6.7 |
| `onnx-custom-domain-op`          | A9, A15.1 | M2.7        | A.8.7     | CC6.6 |
| `onnx-attr-shell-command`        | A9        | —           | A.8.7     | CC6.6 |
| `onnx-attr-path-traversal`       | —         | —           | —         | CC7.2 |
| `onnx-attr-absolute-path`        | —         | —           | —         | CC7.2 |
| `onnx-attr-url`                  | A13       | —           | A.5.34    | CC6.7 |
| `onnx-external-url`              | A13       | —           | A.5.34    | CC6.7 |
| `onnx-external-absolute-path`    | A13       | —           | A.5.34    | CC6.7 |
| `onnx-external-path-traversal`   | A13       | —           | —         | CC6.7 |
| `onnx-old-opset`                 | —         | —           | —         | CC7.1 |
| `onnx-old-ir-version`            | —         | —           | —         | CC7.1 |
| `secret-aws-access-key`          | A15.2     | M2.10       | A.5.23, A.8.28 | CC6.1 |
| `secret-aws-secret-near-key`     | A15.2     | —           | A.5.23, A.5.34 | CC6.1 |
| `secret-github-pat`              | A15.2     | M2.10       | A.8.4, A.8.28  | CC6.1 |
| `secret-github-fine-grained-pat` | A15.2     | —           | A.8.4     | CC6.1 |
| `secret-private-key`             | A15.2     | M2.10       | A.8.4, A.5.34, A.8.28 | CC6.1 |
| `secret-openai-key`              | A15.2     | M2.10       | A.5.23    | CC6.1 |
| `secret-anthropic-key`           | A15.2     | M2.10       | A.5.23    | CC6.1 |
| `secret-huggingface-token`       | A15.2     | —           | A.5.23    | CC6.1 |
| `secret-google-api-key`          | A15.2     | —           | A.5.23    | CC6.1 |
| `secret-slack-token`             | A15.2     | —           | A.5.23    | CC6.1 |
| `secret-slack-webhook`           | —         | —           | A.5.23    | —     |
| `secret-stripe-live`             | A15.2     | —           | A.5.23    | CC6.1 |
| `secret-stripe-test`             | —         | —           | A.5.23    | —     |
| `secret-jwt`                     | A15.2     | —           | A.8.4     | CC6.1 |
| `secret-high-entropy`            | A15.2     | M2.10       | A.8.4, A.8.28 | CC6.1 |
| `cve-known-vulnerability`        | A9, A15.1 | —           | A.8.8, A.8.28 | CC7.1 |
| `cve-malicious-package`          | A9, A15.1 | —           | A.8.7, A.8.8 | CC6.6, CC6.8, CC7.1 |

Empty cell = the rule does not contribute to that standard's evidence.

To produce a compliance report:

```bash
ml-guard compliance ./project --standard <id> --output report.pdf
```

Where `<id>` is one of: `eu-ai-act`, `nist-ai-rmf`, `iso-27001`, `soc2`.
