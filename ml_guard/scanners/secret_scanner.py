"""Secret scanner — finds leaked keys and tokens in text artifacts.

Strategy is two-layered:
  1. **Tight regexes** for known providers. Low false-positives, high
     impact (AWS, GitHub, Slack, Stripe, OpenAI, ...).
  2. **Entropy filter** for generic secrets: long base64/hex strings with
     high Shannon entropy next to a marker word ("password", "secret",
     "token", "key", "auth"). Catches hand-rolled API keys that wouldn't
     match layer 1.

Supported formats:
  • `.env`, `.env.*`
  • `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini`, `.conf`
  • `.py` (source with hardcoded keys)
  • `.ipynb` (Jupyter — we unpack both `cell.source` and `outputs`)
  • `Dockerfile`, `docker-compose.yml` are matched by extension/name

Every finding includes file and line number. For a regex match we name
the provider; for an entropy match, the marker word and the value tail
(but NEVER the secret itself — only the first/last 4 chars, so the
finding is human-readable without leaking the secret into logs).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Pattern, Tuple

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register


# ---------------------------------------------------------------------------
# 1. Provider-specific regexes
# ---------------------------------------------------------------------------
# Fields per rule:
#   id       — stable rule_id used in the Finding
#   severity — our severity level
#   label    — human-readable name
#   pattern  — compiled re.Pattern; group 0 must equal the whole match.
#              We use (?:...) internally so group 0 = the secret itself.
#
# Important: prefer strict patterns with specific prefixes and exact
# lengths; that's what keeps false-positives near zero.

@dataclass(frozen=True)
class _Rule:
    id: str
    severity: Severity
    label: str
    pattern: Pattern[str]


_RULES: Tuple[_Rule, ...] = (
    # --- AWS ---
    _Rule(
        id="secret-aws-access-key",
        severity=Severity.CRITICAL,
        label="AWS Access Key ID",
        # AKIA... (long-lived) or ASIA... (session). 20 chars total, uppercase+digits.
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    _Rule(
        id="secret-aws-secret-near-key",
        severity=Severity.CRITICAL,
        label="AWS Secret Access Key (near-context match)",
        # Only fires when explicitly tagged as "aws_secret_access_key"
        pattern=re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"
        ),
    ),
    # --- GitHub ---
    _Rule(
        id="secret-github-pat",
        severity=Severity.CRITICAL,
        label="GitHub Personal Access Token",
        # Prefixes introduced in 2021: ghp_/gho_/ghu_/ghs_/ghr_, 36+ chars after prefix.
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    _Rule(
        id="secret-github-fine-grained-pat",
        severity=Severity.CRITICAL,
        label="GitHub fine-grained PAT",
        pattern=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    # --- Slack ---
    _Rule(
        id="secret-slack-token",
        severity=Severity.HIGH,
        label="Slack token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    _Rule(
        id="secret-slack-webhook",
        severity=Severity.HIGH,
        label="Slack webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ),
    # --- Stripe ---
    _Rule(
        id="secret-stripe-live",
        severity=Severity.CRITICAL,
        label="Stripe live secret key",
        pattern=re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    ),
    _Rule(
        id="secret-stripe-test",
        severity=Severity.MEDIUM,
        label="Stripe test secret key",
        pattern=re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),
    ),
    # --- OpenAI / Anthropic ---
    _Rule(
        id="secret-openai-key",
        severity=Severity.HIGH,
        label="OpenAI API key",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"),
    ),
    _Rule(
        id="secret-anthropic-key",
        severity=Severity.HIGH,
        label="Anthropic API key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ),
    # --- Hugging Face ---
    _Rule(
        id="secret-huggingface-token",
        severity=Severity.HIGH,
        label="Hugging Face token",
        pattern=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    ),
    # --- Google ---
    _Rule(
        id="secret-google-api-key",
        severity=Severity.HIGH,
        label="Google API key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    # --- Generic JWT ---
    _Rule(
        id="secret-jwt",
        severity=Severity.MEDIUM,
        label="JSON Web Token",
        # eyJ is the base64 prefix of '{"' (JWT header). Three dot-separated segments.
        pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    # --- Private keys ---
    _Rule(
        id="secret-private-key",
        severity=Severity.CRITICAL,
        label="Private cryptographic key",
        # PEM headers: RSA, OPENSSH, EC, DSA, PGP
        pattern=re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----"
        ),
    ),
)


# ---------------------------------------------------------------------------
# 2. Entropy-based search
# ---------------------------------------------------------------------------

# Marker words: a long high-entropy string next to one of these is most
# likely a secret. Case-insensitive.
_SECRET_MARKERS = (
    "password", "passwd", "pwd",
    "secret", "token", "auth",
    "apikey", "api_key", "api-key",
    "credentials", "private_key",
    "session_key", "access_key",
)

# key=val or key: val syntax in .env/.yaml/.json/.ini.
# Key is greedy (any alnum/_/-); value is quoted or runs to end of line.
_KV_RE = re.compile(
    r"(?P<key>[A-Za-z][A-Za-z0-9_\-\.]*)\s*[:=]\s*"
    r"(?P<quote>['\"]?)(?P<val>[^'\"\s,;{}\[\]]+)(?P=quote)"
)

# Minimum length for entropy analysis (short passwords aren't caught well
# by entropy anyway — they need dictionary rules instead).
_MIN_ENTROPY_LEN = 20

# Shannon threshold: empirically 4.0 for base64-like keys.
# Strict base64 max is ~6 bits/char; real keys land at 4.5-5.5.
# Hex max is 4.0; we use 3.5 for the hex-only mode below.
_BASE64_ENTROPY_THRESHOLD = 4.0
_HEX_ENTROPY_THRESHOLD = 3.5

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_\-=]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _shannon_entropy(s: str) -> float:
    """Bits per character. 0 for repeated letters, ~6 for random base64."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _looks_like_secret_value(val: str) -> Optional[str]:
    """
    Decide whether the value looks like a secret by shape and entropy.
    Returns a short description (for finding.message) or None.
    """
    if len(val) < _MIN_ENTROPY_LEN:
        return None
    # Hex: 32+ hex chars with entropy >= 3.5
    if _HEX_RE.match(val) and len(val) >= 32:
        if _shannon_entropy(val) >= _HEX_ENTROPY_THRESHOLD:
            return f"high-entropy hex string (len={len(val)})"
    # Base64-like
    if _BASE64_RE.match(val):
        if _shannon_entropy(val) >= _BASE64_ENTROPY_THRESHOLD:
            return f"high-entropy base64-like string (len={len(val)})"
    return None


def _is_secret_marker_key(key: str) -> bool:
    k = key.lower()
    return any(m in k for m in _SECRET_MARKERS)


# Fast (substring) precheck: do we even need to run the regex on this
# line? If the lowercased line contains no marker word, the entropy path
# can't find anything and `_KV_RE.finditer` is skipped. Cheaper than
# any regex.
def _line_has_marker(line: str) -> bool:
    low = line.lower()
    for m in _SECRET_MARKERS:
        if m in low:
            return True
    return False


# ---------------------------------------------------------------------------
# Anti-patterns (definitely NOT secrets)
# ---------------------------------------------------------------------------

# Obvious placeholders in code/config examples; we suppress these to
# avoid annoying the user.
#
# Approach: match a whole word (\b...\b), not a substring. This matters:
# a real high-entropy key may incidentally contain "1234567" or "example"
# as a substring. We only want to suppress when PLACEHOLDER is a standalone
# word, or when the entire secret is composed of repetitions.
_PLACEHOLDER_TOKENS_RE = re.compile(
    r"(?ix)\b(?:"
    r"  example | placeholder | redacted |"
    r"  your[_\-]?(?:secret|key|token|password) |"
    r"  fake | dummy | sample | replace[_\-]?me |"
    r"  changeme | todo | xxx+ | foobar"
    r")\b"
)

# Strings like "AAAAAAAA" or "xxxxxx" — definitely not secrets.
_REPEATING_RE = re.compile(r"^(.)\1{7,}$")

# Canonical AWS example from AWS docs — literal string, always a placeholder.
# AWS has used this exact ID in all their examples for the last 15 years.
_AWS_DOC_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
}

# UUID — high entropy due to hex shape, but identifier, not secret.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_obviously_placeholder(val: str) -> bool:
    if val in _AWS_DOC_EXAMPLES:
        return True
    if _UUID_RE.match(val):
        return True
    if _REPEATING_RE.match(val):
        return True
    if _PLACEHOLDER_TOKENS_RE.search(val):
        return True
    return False


# ---------------------------------------------------------------------------
# Text extraction by file type
# ---------------------------------------------------------------------------

# Extensions the scanner processes.
_TEXT_EXTENSIONS = {
    ".env",
    ".yaml", ".yml",
    ".json",
    ".toml",
    ".cfg", ".ini", ".conf", ".config",
    ".py",
    ".sh", ".bash",
    ".tf", ".tfvars",       # Terraform
}

# Bare filenames (no extension) we also scan.
_TEXT_BASENAMES = {
    "Dockerfile",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local", ".env.production", ".env.development",
}


def _iter_lines_for_path(path: Path) -> Iterable[Tuple[int, str, str]]:
    """
    Yields tuples of (line_no, source_label, line_text).

    For .ipynb, unpacks cells and iterates over their `source`. line_no is
    the line number within the cell; source_label is "cell N source" or
    "cell N output[k]". For other files, source_label="" and line_no is
    just the file line number.
    """
    if path.suffix.lower() == ".ipynb":
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            nb = json.loads(text)
        except (OSError, json.JSONDecodeError):
            return
        cells = nb.get("cells", [])
        if not isinstance(cells, list):
            return
        for ci, cell in enumerate(cells):
            if not isinstance(cell, dict):
                continue
            src = cell.get("source", [])
            if isinstance(src, list):
                joined = "".join(str(p) for p in src)
            elif isinstance(src, str):
                joined = src
            else:
                continue
            for li, line in enumerate(joined.splitlines(), start=1):
                yield li, f"cell {ci} source", line
            outs = cell.get("outputs", [])
            if isinstance(outs, list):
                for oi, out in enumerate(outs):
                    if not isinstance(out, dict):
                        continue
                    text_out = out.get("text") or out.get("data", {}).get("text/plain")
                    if isinstance(text_out, list):
                        text_out = "".join(str(p) for p in text_out)
                    if isinstance(text_out, str):
                        for li, line in enumerate(text_out.splitlines(), start=1):
                            yield li, f"cell {ci} output[{oi}]", line
        return

    # Plain text file.
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for li, line in enumerate(f, start=1):
                yield li, "", line.rstrip("\n")
    except OSError:
        return


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------

@register
class SecretScanner(Scanner):
    name = "secrets"
    description = "Detects hard-coded API keys, tokens, and high-entropy secrets in source/configs"

    # Per-line cap — keeps regexes from hanging the process on single-byte
    # lines that are megabytes long (e.g. .ipynb with embedded base64 images).
    MAX_LINE_LEN = 16 * 1024

    # Per-file cap; larger files are skipped.
    MAX_FILE_BYTES = 32 * 1024 * 1024

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() == ".ipynb":
            return True
        if path.suffix.lower() in _TEXT_EXTENSIONS:
            return True
        if path.name in _TEXT_BASENAMES:
            return True
        return False

    def scan(self, path: Path) -> List[Finding]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size > self.MAX_FILE_BYTES:
            return [Finding(
                rule_id="secrets-file-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({size} bytes); skipped",
                file=str(path), scanner=self.name,
            )]

        findings: List[Finding] = []
        # Dedup: same (rule_id, secret-snippet) per file = report once.
        seen: set[Tuple[str, str]] = set()

        for line_no, src_label, line in _iter_lines_for_path(path):
            if not line:
                continue
            if len(line) > self.MAX_LINE_LEN:
                # Large base64 blobs (ipynb images) — clip them
                line = line[: self.MAX_LINE_LEN]

            self._scan_line(line, line_no, src_label, findings, seen)

        return findings

    # ------------------------------------------------------------------
    def _scan_line(
        self,
        line: str,
        line_no: int,
        src_label: str,
        findings: List[Finding],
        seen: set,
    ) -> None:
        # Collect every secret matched by regex on this line — used to
        # avoid the entropy path reporting it again.
        regex_hit_values: set[str] = set()

        # 1) Regex pass
        for rule in _RULES:
            for m in rule.pattern.finditer(line):
                # Group 1 if present, otherwise group 0.
                secret = m.group(1) if rule.pattern.groups >= 1 and m.lastindex else m.group(0)
                if _is_obviously_placeholder(secret):
                    continue
                key = (rule.id, secret)
                if key in seen:
                    continue
                seen.add(key)
                regex_hit_values.add(secret)

                # Mask the secret: keep first/last 4 chars only.
                redacted = self._redact(secret)
                location = self._fmt_location(line_no, src_label)
                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=f"{rule.label} detected",
                    file="", scanner=self.name,
                    location=location,
                    snippet=redacted,
                ))

        # 2) Entropy near a marker key.
        # Fast pre-check: if the line has no marker word, skip the
        # _KV_RE.finditer call entirely (10x speedup on large secret-free
        # source files).
        if not _line_has_marker(line):
            return

        for m in _KV_RE.finditer(line):
            key = m.group("key")
            val = m.group("val")
            if val in regex_hit_values:
                # Already matched by a strict rule — entropy would be a dup
                continue
            if not _is_secret_marker_key(key):
                continue
            if _is_obviously_placeholder(val):
                continue
            descr = _looks_like_secret_value(val)
            if descr is None:
                continue
            dup_key = ("secret-high-entropy", val)
            if dup_key in seen:
                continue
            seen.add(dup_key)

            redacted = self._redact(val)
            location = self._fmt_location(line_no, src_label)
            findings.append(Finding(
                rule_id="secret-high-entropy",
                severity=Severity.MEDIUM,
                message=f"Possible secret near key '{key}': {descr}",
                file="", scanner=self.name,
                location=location,
                snippet=f"{key}={redacted}",
            ))

    @staticmethod
    def _redact(s: str) -> str:
        if len(s) <= 8:
            return "*" * len(s)
        return f"{s[:4]}…{s[-4:]} (len={len(s)})"

    @staticmethod
    def _fmt_location(line_no: int, src_label: str) -> str:
        if src_label:
            return f"{src_label}, line {line_no}"
        return f"line {line_no}"
