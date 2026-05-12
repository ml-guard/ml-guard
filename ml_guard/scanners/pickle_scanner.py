"""Pickle scanner — detects malicious code in pickle files.

The pickle deserialization vulnerability (CWE-502) works like this:
the pickle protocol is a stack machine with opcodes. The REDUCE opcode
calls a callable (taken from the stack) with arguments (also from the
stack). GLOBAL/STACK_GLOBAL load a callable by module + attribute name.

So seeing the pair (GLOBAL "os" "system", REDUCE) is enough — calling
torch.load() on the file will execute `os.system(...)`. No ML required.

This scanner NEVER executes pickle. We only parse opcodes and check
which globals get loaded. Safe by construction.

Strategy:
  1. pickletools.genops() yields a (opcode, arg, position) stream — it's
     part of the stdlib, battle-tested for years, no attack surface itself.
  2. Track the GLOBAL stack: if REDUCE/BUILD/INST invokes a known
     dangerous callable, emit a Finding at the appropriate severity.
  3. Unknown-but-non-ML modules raise severity by themselves.
"""
from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register

# --------------------------------------------------------------------------
# Knowledge base: what we consider dangerous
# --------------------------------------------------------------------------

# These callables, when invoked via REDUCE, give RCE — always critical.
# Tuple format: (module, qualname). Module name in pickle notation.
_RCE_CALLABLES: Set[Tuple[str, str]] = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "spawnl"),
    ("os", "spawnv"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("commands", "getoutput"),       # Python 2, still seen in old pickles
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("__builtin__", "eval"),         # Python 2 name
    ("__builtin__", "exec"),
    ("__builtin__", "compile"),
    ("__builtin__", "__import__"),
    ("importlib", "import_module"),
    ("runpy", "run_path"),
    ("runpy", "_run_code"),
    ("pty", "spawn"),
    ("platform", "popen"),
    ("ctypes", "CDLL"),              # loading a native lib = RCE
    ("ctypes", "WinDLL"),
    ("ctypes", "OleDLL"),
    ("ctypes", "PyDLL"),
}

# Suspicious modules — no direct RCE but hint at exfiltration/networking.
# A tensor file has no business importing these.
_SUSPICIOUS_MODULES: Set[str] = {
    "socket",
    "urllib",
    "urllib2",
    "urllib.request",
    "http",
    "http.client",
    "httplib",
    "requests",
    "ftplib",
    "telnetlib",
    "smtplib",
    "shutil",          # rmtree, copy
    "tempfile",
    "webbrowser",
    "marshal",         # another "serialization via execution"
    "code",            # interactive interpreter
    "codeop",
    "subprocess",      # already in RCE set; we still flag the import itself
    "pickle",          # recursive pickle.loads is alarming
    "pickletools",
    "_pickle",
}

# Modules typical for ML weights — not flagged as suspicious.
# (The modules themselves are safe; only specific callables would be
# dangerous, and we don't expect them as RCE vectors in ML pickles.)
_BENIGN_ML_MODULES: Set[str] = {
    "torch",
    "torch._utils",
    "torch.nn",
    "torch.nn.modules",
    "torch.nn.parameter",
    "torch.storage",
    "torch._tensor",
    "torch.serialization",
    "numpy",
    "numpy.core.multiarray",
    "numpy._core.multiarray",
    "numpy.core.numeric",
    "numpy.dtypes",
    "collections",
    "collections.abc",
    "_codecs",
}

# Opcodes suspicious in themselves (Python 2 legacy)
_DEPRECATED_OPCODES: Set[str] = {"INST", "OBJ"}  # legacy instantiation paths


# --------------------------------------------------------------------------
# Format-detection helpers
# --------------------------------------------------------------------------

_PICKLE_MAGIC_BYTES = (
    b"\x80",      # PROTO opcode (proto >=2)
    b"(",         # MARK
    b"]",         # EMPTY_LIST
    b"}",         # EMPTY_DICT
    b"c",         # GLOBAL (proto 0)
)

_TORCH_ZIP_MEMBERS = ("data.pkl", "archive/data.pkl")  # PyTorch >=1.6 ZIP


def _looks_like_pickle(path: Path) -> bool:
    """Does this file look like pickle? Used when the extension is ambiguous."""
    try:
        with path.open("rb") as f:
            head = f.read(2)
        return len(head) > 0 and head[:1] in _PICKLE_MAGIC_BYTES
    except OSError:
        return False


def _is_torch_zip(path: Path) -> bool:
    """PyTorch 1.6+ saves .pt/.pth/.bin as a ZIP with data.pkl inside."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            return any(n.endswith("data.pkl") for n in names)
    except (zipfile.BadZipFile, OSError):
        return False


# --------------------------------------------------------------------------
# Analyzer core
# --------------------------------------------------------------------------

class _PickleAnalyzer:
    """
    Stream through opcodes and accumulate findings.

    Pickle protocol >=4 quirk (Python 3.8+ default):
      Loading `os.system` is encoded as:
          SHORT_BINUNICODE "os"
          SHORT_BINUNICODE "system"
          STACK_GLOBAL                       <-- module/name pulled from stack
      So an opcode-only scan misses these — we need to emulate a string
      stack and recover (module, qualname) at STACK_GLOBAL time.

    The emulation is intentionally minimal: only strings (UNICODE variants
    and SHORT_BINSTRING) actually matter; structural opcodes (MARK, POP)
    push placeholders. Enough to spot RCE invocations; we don't need to
    reconstruct tensors.
    """

    def __init__(self, source_label: str) -> None:
        self.source_label = source_label
        self._findings: List[Finding] = []
        self._last_global: Optional[Tuple[str, str]] = None
        self._seen_modules: Set[str] = set()
        self._global_count = 0
        # Heavily simplified stack: strings only (for STACK_GLOBAL).
        # Anything else is pushed as None (placeholder).
        self._stack: List[Optional[str]] = []
        # Already-reported (module, qualname) pairs — avoid duplicates.
        self._reported_pairs: Set[Tuple[str, str]] = set()

    # ----- helpers ---------------------------------------------------------
    def _add(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        pos: Optional[int],
        snippet: str = "",
    ) -> None:
        self._findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file="",  # filled in by the scanner caller
                location=f"offset 0x{pos:x}" if pos is not None else "",
                snippet=snippet,
                metadata={"source": self.source_label},
            )
        )

    # ----- per-opcode handlers --------------------------------------------
    def _on_global(self, module: str, qualname: str, pos: Optional[int]) -> None:
        self._last_global = (module, qualname)
        self._seen_modules.add(module)
        self._global_count += 1

        # Dedup: if we already reported this exact pair, skip.
        if (module, qualname) in self._reported_pairs:
            return

        # Obviously-dangerous callable — critical, even without REDUCE
        # (REDUCE may follow; importing an RCE function in pickle is
        # already a strong red flag).
        if (module, qualname) in _RCE_CALLABLES:
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-dangerous-global",
                severity=Severity.CRITICAL,
                message=f"Dangerous global imported: {module}.{qualname} "
                        f"(known RCE primitive)",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )
            return

        # Suspicious module (networking, shutil, etc.) — high
        if module in _SUSPICIOUS_MODULES or any(
            module.startswith(m + ".") for m in _SUSPICIOUS_MODULES
        ):
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-suspicious-module",
                severity=Severity.HIGH,
                message=f"Suspicious module imported: {module}.{qualname} "
                        f"(not expected in ML weights)",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )
            return

        # Non-ML module — medium (heads-up). Compare top-level package name.
        top = module.split(".")[0]
        if top not in {m.split(".")[0] for m in _BENIGN_ML_MODULES}:
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-unusual-module",
                severity=Severity.MEDIUM,
                message=f"Unusual module for ML weights: {module}.{qualname}",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )

    def _on_reduce(self, pos: Optional[int]) -> None:
        # REDUCE = call the last callable with args popped from the stack.
        # If the last GLOBAL was dangerous, we've already emitted a critical
        # finding. No need to double-report here.
        pass

    def _on_deprecated(self, opcode_name: str, pos: Optional[int]) -> None:
        self._add(
            rule_id="pickle-deprecated-opcode",
            severity=Severity.LOW,
            message=f"Deprecated/uncommon opcode {opcode_name} encountered "
                    f"(Python 2 era; review carefully)",
            pos=pos,
        )

    # ----- main loop -------------------------------------------------------
    # Opcodes that push a string onto the stack.
    _STRING_PUSH_OPS = {
        "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
        "SHORT_BINSTRING", "BINSTRING", "STRING",
        "SHORT_BINBYTES", "BINBYTES", "BINBYTES8",  # bytes may also carry a module name
    }
    # Opcodes pushing non-string values — we push None as a placeholder.
    _NONSTRING_PUSH_OPS = {
        "NONE", "NEWTRUE", "NEWFALSE",
        "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT",
        "FLOAT", "BINFLOAT",
        "EMPTY_DICT", "EMPTY_LIST", "EMPTY_SET", "EMPTY_TUPLE",
        "MARK",
    }

    def analyze(self, data: bytes) -> List[Finding]:
        """Run pickletools.genops over the bytes. We execute nothing."""
        try:
            stream = io.BytesIO(data)
            for op, arg, pos in pickletools.genops(stream):
                name = op.name

                # ----- stack emulation (only for tracking strings) ---------
                if name in self._STRING_PUSH_OPS:
                    # arg is a string or bytes; normalize to str
                    s: Optional[str]
                    if isinstance(arg, bytes):
                        try:
                            s = arg.decode("utf-8", errors="replace")
                        except Exception:  # noqa: BLE001
                            s = None
                    elif isinstance(arg, str):
                        s = arg
                    else:
                        s = None
                    self._stack.append(s)

                elif name in self._NONSTRING_PUSH_OPS:
                    self._stack.append(None)

                elif name in ("POP",):
                    if self._stack:
                        self._stack.pop()

                # ----- interesting opcodes -------------------------------
                if name in ("GLOBAL", "INST"):
                    if isinstance(arg, str) and " " in arg:
                        module, _, qualname = arg.partition(" ")
                        self._on_global(module, qualname, pos)
                    if name == "INST":
                        self._on_deprecated(name, pos)

                elif name == "STACK_GLOBAL":
                    # Take the top two stack entries: [module, qualname]
                    if len(self._stack) >= 2:
                        qualname = self._stack[-1]
                        module = self._stack[-2]
                        if module is not None and qualname is not None:
                            self._on_global(module, qualname, pos)
                        else:
                            # Couldn't recover the name — record the STACK_GLOBAL itself
                            self._add(
                                rule_id="pickle-stack-global-opaque",
                                severity=Severity.MEDIUM,
                                message="STACK_GLOBAL with non-string operands "
                                        "(possibly obfuscated)",
                                pos=pos,
                            )
                    else:
                        self._add(
                            rule_id="pickle-stack-global-opaque",
                            severity=Severity.MEDIUM,
                            message="STACK_GLOBAL on empty stack (malformed pickle)",
                            pos=pos,
                        )
                    # Simulate effect: pop 2, push 1 (the callable, tracked as None)
                    if len(self._stack) >= 2:
                        self._stack.pop()
                        self._stack.pop()
                    self._stack.append(None)

                elif name == "REDUCE":
                    self._on_reduce(pos)
                    # effect: pop 2 (callable, args), push 1 result
                    for _ in range(2):
                        if self._stack:
                            self._stack.pop()
                    self._stack.append(None)

                elif name == "OBJ":
                    self._on_deprecated(name, pos)

        except Exception as e:  # noqa: BLE001
            # Malformed pickle OR an attempt to confuse the parser — also a finding.
            self._add(
                rule_id="pickle-parse-error",
                severity=Severity.MEDIUM,
                message=f"Failed to parse pickle stream: {e}",
                pos=None,
            )

        return self._findings


# --------------------------------------------------------------------------
# The scanner itself (registry plugin)
# --------------------------------------------------------------------------

@register
class PickleScanner(Scanner):
    name = "pickle"
    description = "Detects malicious opcodes and dangerous globals in pickle files"

    # Extensions guaranteed (or likely, for torch zip) to contain pickle.
    _EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"}

    # Limits — DoS protection. Very large files are skipped wholesale.
    MAX_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB
    MAX_INNER_PICKLE = 256 * 1024 * 1024  # 256 MiB cap for an inner pickle in a ZIP

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() in self._EXTENSIONS:
            return True
        # No extension — sniff for the magic bytes
        if path.suffix == "" and _looks_like_pickle(path):
            return True
        return False

    def scan(self, path: Path) -> List[Finding]:
        if path.stat().st_size > self.MAX_BYTES:
            return [Finding(
                rule_id="pickle-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({path.stat().st_size} bytes); skipped",
                file=str(path),
                scanner=self.name,
            )]

        # 1) PyTorch ZIP format — data.pkl lives inside
        if zipfile.is_zipfile(path) and _is_torch_zip(path):
            return self._scan_torch_zip(path)

        # 2) Raw pickle
        return self._scan_raw_pickle(path)

    # ------------------------------------------------------------------
    def _scan_raw_pickle(self, path: Path) -> List[Finding]:
        with path.open("rb") as f:
            data = f.read()
        return self._analyze_bytes(data, location_prefix=None)

    def _scan_torch_zip(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(path, "r") as zf:
                pkl_members = [n for n in zf.namelist() if n.endswith("data.pkl")]
                if not pkl_members:
                    return findings
                for member in pkl_members:
                    info = zf.getinfo(member)
                    if info.file_size > self.MAX_INNER_PICKLE:
                        findings.append(Finding(
                            rule_id="pickle-inner-too-large",
                            severity=Severity.LOW,
                            message=f"Inner pickle '{member}' too large; skipped",
                            file=str(path),
                            scanner=self.name,
                        ))
                        continue
                    with zf.open(member) as inner:
                        data = inner.read()
                    inner_findings = self._analyze_bytes(data, location_prefix=member)
                    findings.extend(inner_findings)
        except zipfile.BadZipFile as e:
            findings.append(Finding(
                rule_id="pickle-bad-zip",
                severity=Severity.MEDIUM,
                message=f"Corrupt PyTorch ZIP: {e}",
                file=str(path),
                scanner=self.name,
            ))
        return findings

    # ------------------------------------------------------------------
    def _analyze_bytes(self, data: bytes, location_prefix: Optional[str]) -> List[Finding]:
        """
        Single entry point for analyzing pickle bytes. Uses the native
        engine when available; falls back to the pure-Python _PickleAnalyzer.

        location_prefix: if set (e.g. a ZIP member name), prepended to each
        finding's location field.
        """
        if _HAS_RUST:
            try:
                raw = ml_guard_engine.scan_pickle_bytes(data)  # type: ignore[name-defined]
                findings: List[Finding] = []
                for d in raw:
                    sev = Severity(d["severity"])
                    loc = d.get("location", "")
                    if location_prefix:
                        loc = f"{location_prefix} @ {loc}" if loc else location_prefix
                    findings.append(Finding(
                        rule_id=d["rule_id"],
                        severity=sev,
                        message=d["message"],
                        file="",  # filled in by the scanner caller
                        location=loc,
                        snippet=d.get("snippet", ""),
                    ))
                return findings
            except Exception:  # noqa: BLE001
                # The native path must never break user-visible behavior.
                # Fall through to Python on any failure.
                pass

        analyzer = _PickleAnalyzer(source_label="<bytes>")
        findings = analyzer.analyze(data)
        if location_prefix:
            for f in findings:
                f.location = (
                    f"{location_prefix} @ {f.location}" if f.location else location_prefix
                )
        return findings


# --------------------------------------------------------------------------
# Optional Rust acceleration
# --------------------------------------------------------------------------
# If ml_guard_engine (Rust) is installed, use it on the hot path for large
# files. Pure Python always works; Rust is a bonus.
try:
    import ml_guard_engine  # type: ignore[import-not-found]
    _HAS_RUST = hasattr(ml_guard_engine, "scan_pickle_bytes")
except ImportError:
    _HAS_RUST = False
