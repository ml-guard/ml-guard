"""ONNX scanner — static analysis of ONNX-format models.

ONNX is a serialized protobuf (`onnx.ModelProto`). We deliberately do NOT
import the `onnx` library: that keeps us independent of its parser and
adds zero external dependencies. Instead we read the wire format directly via
`ml_guard._protobuf`.

What we catch:

  1. **Custom-domain operators**. Standard ONNX operators live in domain
     "" (empty) or "ai.onnx*". Anything else (`com.microsoft`, `nvidia.*`,
     arbitrary `evil.exfil`) is a plugin that the runtime can load as
     native code. This is fully legitimate behavior, but for audit it's
     a high-severity flag: operators from unknown domains shouldn't
     reach production without explicit approval.

  2. **External data (`external_data`)**. ONNX allows storing tensors
     separately — in a file, on disk, or (scarier) at an absolute path.
     If the path contains `..`, absolute `/etc/`, or a URL, it's a
     path-traversal / SSRF vector.

  3. **Too-old opset_import**. opset < 7 belongs to early versions with
     known incompatibilities and exploit surface in old parsers.

  4. **Suspicious string attributes**. STRING-typed attributes containing
     OS commands, shells, or absolute paths suggest a payload smuggled
     through the graph (`Eval`-like custom nodes).

  5. **Deeply nested subgraphs / huge node count** — DoS vector; we cap it.

  6. **Corrupt/malformed proto** — emits its own finding (same as pickle).

This scanner is pure Python with no dependencies beyond our own
`_protobuf.py`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from ml_guard import _protobuf as pb
from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register


# ---------------------------------------------------------------------------
# ONNX schema constants (numeric proto field IDs)
# ---------------------------------------------------------------------------
# ModelProto
_MODEL_IR_VERSION = 1
_MODEL_PRODUCER_NAME = 5
_MODEL_GRAPH = 7
_MODEL_OPSET_IMPORT = 8
_MODEL_METADATA_PROPS = 14

# OperatorSetIdProto
_OPSET_DOMAIN = 1
_OPSET_VERSION = 2

# GraphProto
_GRAPH_NODE = 1
_GRAPH_INITIALIZER = 5

# NodeProto
_NODE_OP_TYPE = 4
_NODE_DOMAIN = 7
_NODE_ATTRIBUTE = 5

# AttributeProto
_ATTR_NAME = 1
_ATTR_S = 4              # bytes (STRING type)
_ATTR_TYPE = 20          # enum
_ATTR_STRINGS = 8        # repeated bytes
_ATTR_G = 6              # GraphProto (nested subgraph)
_ATTR_GRAPHS = 11        # repeated GraphProto

# AttributeProto.AttributeType enum
_ATTR_TYPE_STRING = 3
_ATTR_TYPE_GRAPH = 5
_ATTR_TYPE_GRAPHS = 9

# TensorProto
_TENSOR_NAME = 8
_TENSOR_EXTERNAL_DATA = 13
_TENSOR_DATA_LOCATION = 14

# StringStringEntryProto
_KV_KEY = 1
_KV_VALUE = 2

# data_location enum
_DATA_LOCATION_EXTERNAL = 1


# ---------------------------------------------------------------------------
# Known standard ONNX domains
# ---------------------------------------------------------------------------

# Empty domain and official ai.onnx domains hold canonical operators.
_STANDARD_DOMAINS: Set[str] = {
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
}

# Known "semi-trusted" domains from mainstream runtimes.
# Not critical, but worth a medium flag: the user should know the model
# will only run with the matching runtime installed.
_KNOWN_VENDOR_DOMAINS: Set[str] = {
    "com.microsoft",
    "com.microsoft.experimental",
    "com.microsoft.nchwc",
    "com.ms.internal.nhwc",
    "org.pytorch",
    "org.pytorch.aten",
    "ai.onnx.contrib",
}

# Minimum supported ir_version. ONNX 1.0 = 3, ONNX 1.4+ = 4-5+.
# Below 3 = very old models.
_MIN_IR_VERSION = 3
_MIN_OPSET_VERSION = 7   # ai.onnx below 7 is genuinely ancient


# ---------------------------------------------------------------------------
# Sniffers for string attributes
# ---------------------------------------------------------------------------

# OS commands / shells / paths — same idea as secret scanner, but stricter.
_SHELL_PATTERNS = (
    re.compile(rb"(?i)\b(?:bash|sh|cmd|powershell|wget|curl|nc|netcat)\b"),
    re.compile(rb"(?:^|[\s;&|`])(?:rm|chmod|chown|sudo|kill|eval|exec)\s"),
    re.compile(rb"`[^`]+`"),                          # backtick subshell
    re.compile(rb"\$\([^)]+\)"),                      # $(cmd)
)

_ABS_PATH_PATTERN = re.compile(
    rb"(?:^|[\s\"'(])(?:/(?:etc|root|home|var|proc|tmp|dev|sys|boot)/[A-Za-z0-9./_\-]+)"
)
_WIN_PATH_PATTERN = re.compile(
    rb"[A-Za-z]:\\(?:Windows|Users|Program\sFiles)\\"
)
_URL_PATTERN = re.compile(rb"(?:https?|ftp|file)://[A-Za-z0-9.\-/_:?=&%~+#]+")
_PATH_TRAVERSAL = re.compile(rb"\.\./")

# Minimum length for the entropy test / suspicious-string check.
_STR_INTEREST_MIN = 8


# ---------------------------------------------------------------------------
# Limits — DoS protection
# ---------------------------------------------------------------------------

# Maximum nodes in the graph (including subgraphs). Real models rarely
# exceed 100k operators; a million is almost always an attack or a bug.
MAX_GRAPH_NODES = 1_000_000
MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB


# ---------------------------------------------------------------------------
# Parsing with finding aggregation
# ---------------------------------------------------------------------------

@dataclass
class _ScanState:
    findings: List[Finding] = field(default_factory=list)
    nodes_seen: int = 0
    domains_seen: Set[str] = field(default_factory=set)
    custom_op_pairs: Set[tuple] = field(default_factory=set)  # (domain, op_type)
    aborted: bool = False

    def add(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        location: str = "",
        snippet: str = "",
    ) -> None:
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            file="",
            scanner="onnx",
            location=location,
            snippet=snippet,
        ))


def _read_string_field(msg: Dict[int, List], field_no: int) -> Optional[str]:
    raw = msg.get(field_no)
    if not raw:
        return None
    val = raw[0]
    if isinstance(val, bytes):
        return pb.bytes_to_str(val)
    return None


def _read_int_field(msg: Dict[int, List], field_no: int) -> Optional[int]:
    raw = msg.get(field_no)
    if not raw:
        return None
    val = raw[0]
    if isinstance(val, int):
        return val
    return None


def _read_kv_entries(blobs: List[bytes]) -> List[tuple[str, str]]:
    """StringStringEntryProto[] → [(key, value), ...]"""
    out = []
    for b in blobs:
        if not isinstance(b, bytes):
            continue
        sub = pb.try_parse_nested(b)
        if sub is None:
            continue
        k = _read_string_field(sub, _KV_KEY)
        v = _read_string_field(sub, _KV_VALUE)
        if k is not None:
            out.append((k, v or ""))
    return out


# ---------------------------------------------------------------------------
# Node / graph analysis
# ---------------------------------------------------------------------------

def _analyze_attribute(attr_msg: Dict[int, List], state: _ScanState, node_label: str) -> None:
    """Check a single AttributeProto."""
    name = _read_string_field(attr_msg, _ATTR_NAME) or "<anonymous>"
    attr_type = _read_int_field(attr_msg, _ATTR_TYPE)

    # STRING or STRINGS type — worth inspecting the payload
    if attr_type == _ATTR_TYPE_STRING or _ATTR_S in attr_msg:
        for blob in attr_msg.get(_ATTR_S, []):
            if isinstance(blob, bytes):
                _analyze_string_attribute(blob, state, node_label, name)
    if _ATTR_STRINGS in attr_msg:
        for blob in attr_msg.get(_ATTR_STRINGS, []):
            if isinstance(blob, bytes):
                _analyze_string_attribute(blob, state, node_label, name)

    # Subgraph (e.g. inside If/Loop/Scan) — recurse
    for g_blob in attr_msg.get(_ATTR_G, []):
        if isinstance(g_blob, bytes):
            sub = pb.try_parse_nested(g_blob)
            if sub:
                _analyze_graph(sub, state, label_prefix=f"{node_label}.{name}")
    for g_blob in attr_msg.get(_ATTR_GRAPHS, []):
        if isinstance(g_blob, bytes):
            sub = pb.try_parse_nested(g_blob)
            if sub:
                _analyze_graph(sub, state, label_prefix=f"{node_label}.{name}")


def _analyze_string_attribute(
    blob: bytes,
    state: _ScanState,
    node_label: str,
    attr_name: str,
) -> None:
    """Heuristics over a string attribute."""
    if len(blob) < _STR_INTEREST_MIN:
        return

    if _PATH_TRAVERSAL.search(blob):
        state.add(
            rule_id="onnx-attr-path-traversal",
            severity=Severity.HIGH,
            message=f"Path traversal '..' in attribute '{attr_name}' of {node_label}",
            location=f"{node_label}.{attr_name}",
            snippet=pb.bytes_to_str(blob[:80]),
        )
        return

    if _URL_PATTERN.search(blob):
        state.add(
            rule_id="onnx-attr-url",
            severity=Severity.MEDIUM,
            message=f"URL in attribute '{attr_name}' of {node_label}",
            location=f"{node_label}.{attr_name}",
            snippet=pb.bytes_to_str(blob[:80]),
        )
        return

    if _ABS_PATH_PATTERN.search(blob) or _WIN_PATH_PATTERN.search(blob):
        state.add(
            rule_id="onnx-attr-absolute-path",
            severity=Severity.MEDIUM,
            message=f"Absolute filesystem path in attribute '{attr_name}' of {node_label}",
            location=f"{node_label}.{attr_name}",
            snippet=pb.bytes_to_str(blob[:80]),
        )
        return

    for pat in _SHELL_PATTERNS:
        if pat.search(blob):
            state.add(
                rule_id="onnx-attr-shell-command",
                severity=Severity.HIGH,
                message=f"Shell-like content in attribute '{attr_name}' of {node_label}",
                location=f"{node_label}.{attr_name}",
                snippet=pb.bytes_to_str(blob[:80]),
            )
            return


def _analyze_node(node_msg: Dict[int, List], state: _ScanState, label_prefix: str = "") -> None:
    state.nodes_seen += 1
    if state.nodes_seen > MAX_GRAPH_NODES:
        if not state.aborted:
            state.add(
                rule_id="onnx-too-many-nodes",
                severity=Severity.LOW,
                message=f"Stopped after {MAX_GRAPH_NODES} nodes (DoS guard)",
            )
            state.aborted = True
        return

    op_type = _read_string_field(node_msg, _NODE_OP_TYPE) or "<unknown>"
    domain = _read_string_field(node_msg, _NODE_DOMAIN) or ""
    state.domains_seen.add(domain)

    node_label = f"{label_prefix}.{op_type}" if label_prefix else f"node[{state.nodes_seen-1}]:{op_type}"

    # Operators from custom domains
    if domain not in _STANDARD_DOMAINS:
        pair = (domain, op_type)
        if pair not in state.custom_op_pairs:
            state.custom_op_pairs.add(pair)
            if domain in _KNOWN_VENDOR_DOMAINS:
                state.add(
                    rule_id="onnx-vendor-domain-op",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Operator '{op_type}' from vendor domain '{domain}' "
                        f"requires that runtime/extension to be installed"
                    ),
                    location=node_label,
                    snippet=f"{domain}::{op_type}",
                )
            else:
                state.add(
                    rule_id="onnx-custom-domain-op",
                    severity=Severity.HIGH,
                    message=(
                        f"Operator '{op_type}' from non-standard domain "
                        f"'{domain}' (loads as native plugin at runtime)"
                    ),
                    location=node_label,
                    snippet=f"{domain}::{op_type}",
                )

    # Node attributes
    for attr_blob in node_msg.get(_NODE_ATTRIBUTE, []):
        if not isinstance(attr_blob, bytes):
            continue
        attr_msg = pb.try_parse_nested(attr_blob)
        if attr_msg is None:
            continue
        if state.aborted:
            return
        _analyze_attribute(attr_msg, state, node_label)


def _analyze_initializer(tensor_msg: Dict[int, List], state: _ScanState) -> None:
    """Look for external_data referencing odd paths."""
    name = _read_string_field(tensor_msg, _TENSOR_NAME) or "<unnamed>"
    data_location = _read_int_field(tensor_msg, _TENSOR_DATA_LOCATION)

    ext_blobs = tensor_msg.get(_TENSOR_EXTERNAL_DATA, [])
    if not ext_blobs and data_location != _DATA_LOCATION_EXTERNAL:
        return

    entries = _read_kv_entries([b for b in ext_blobs if isinstance(b, bytes)])
    for k, v in entries:
        if k != "location":
            continue
        # location is the path to the data file. In a safe model this is
        # a relative path without `..`. Anything else is high risk.
        if v.startswith("/") or (len(v) > 1 and v[1] == ":"):
            state.add(
                rule_id="onnx-external-absolute-path",
                severity=Severity.HIGH,
                message=f"Tensor '{name}' references absolute external path: {v}",
                location=f"initializer:{name}",
                snippet=v[:120],
            )
        elif ".." in v.split("/"):
            state.add(
                rule_id="onnx-external-path-traversal",
                severity=Severity.HIGH,
                message=f"Tensor '{name}' references external path with '..': {v}",
                location=f"initializer:{name}",
                snippet=v[:120],
            )
        elif _URL_PATTERN.search(v.encode("utf-8", errors="replace")):
            state.add(
                rule_id="onnx-external-url",
                severity=Severity.HIGH,
                message=f"Tensor '{name}' references URL as external data: {v}",
                location=f"initializer:{name}",
                snippet=v[:120],
            )


def _analyze_graph(graph_msg: Dict[int, List], state: _ScanState, label_prefix: str = "") -> None:
    for node_blob in graph_msg.get(_GRAPH_NODE, []):
        if state.aborted:
            return
        if not isinstance(node_blob, bytes):
            continue
        node_msg = pb.try_parse_nested(node_blob)
        if node_msg is None:
            continue
        _analyze_node(node_msg, state, label_prefix=label_prefix)

    for tensor_blob in graph_msg.get(_GRAPH_INITIALIZER, []):
        if not isinstance(tensor_blob, bytes):
            continue
        t_msg = pb.try_parse_nested(tensor_blob)
        if t_msg is None:
            continue
        _analyze_initializer(t_msg, state)


def _analyze_opset_imports(model_msg: Dict[int, List], state: _ScanState) -> None:
    for blob in model_msg.get(_MODEL_OPSET_IMPORT, []):
        if not isinstance(blob, bytes):
            continue
        sub = pb.try_parse_nested(blob)
        if sub is None:
            continue
        domain = _read_string_field(sub, _OPSET_DOMAIN) or ""
        version = _read_int_field(sub, _OPSET_VERSION)
        # ai.onnx default
        if domain in _STANDARD_DOMAINS:
            if version is not None and version < _MIN_OPSET_VERSION:
                state.add(
                    rule_id="onnx-old-opset",
                    severity=Severity.MEDIUM,
                    message=f"Old opset version {version} for domain '{domain or 'ai.onnx'}'",
                    location="opset_import",
                )
        else:
            # Unknown domain in opset_import = all its operators will be
            # treated as custom; the node-level check would catch this too,
            # but we record it separately — it's an explicit declarative signal.
            sev = Severity.MEDIUM if domain in _KNOWN_VENDOR_DOMAINS else Severity.HIGH
            state.add(
                rule_id="onnx-non-standard-opset-domain",
                severity=sev,
                message=f"Non-standard opset domain declared: '{domain}' (version={version})",
                location="opset_import",
                snippet=f"{domain}@{version}",
            )


# ---------------------------------------------------------------------------
# The scanner itself
# ---------------------------------------------------------------------------

@register
class OnnxScanner(Scanner):
    name = "onnx"
    description = "Detects custom ops, suspicious external_data, and shell-like attributes in ONNX models"

    _EXTENSIONS = {".onnx"}

    # ONNX magic: the first proto tag for ModelProto.ir_version (field 1, varint) = 0x08.
    # Not the most reliable signature, so we mostly rely on the file extension.
    _ONNX_FIRST_BYTES = b"\x08"

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        return path.suffix.lower() in self._EXTENSIONS

    def scan(self, path: Path) -> List[Finding]:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return [Finding(
                rule_id="onnx-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({size} bytes); skipped",
                file=str(path), scanner=self.name,
            )]

        with path.open("rb") as f:
            data = f.read()

        return self._scan_bytes(data)

    # ------------------------------------------------------------------
    def _scan_bytes(self, data: bytes) -> List[Finding]:
        if not data:
            return [Finding(
                rule_id="onnx-empty",
                severity=Severity.LOW,
                message="Empty .onnx file",
                file="", scanner=self.name,
            )]

        try:
            model_msg = pb.parse_message(data)
        except pb.ProtobufError as e:
            return [Finding(
                rule_id="onnx-malformed",
                severity=Severity.MEDIUM,
                message=f"Malformed ONNX/protobuf: {e}",
                file="", scanner=self.name,
            )]

        state = _ScanState()

        # ir_version
        ir_v = _read_int_field(model_msg, _MODEL_IR_VERSION)
        if ir_v is not None and ir_v < _MIN_IR_VERSION:
            state.add(
                rule_id="onnx-old-ir-version",
                severity=Severity.MEDIUM,
                message=f"Old ONNX ir_version={ir_v} (current >= {_MIN_IR_VERSION})",
            )

        # opset_imports
        _analyze_opset_imports(model_msg, state)

        # graph
        for graph_blob in model_msg.get(_MODEL_GRAPH, []):
            if not isinstance(graph_blob, bytes):
                continue
            graph_msg = pb.try_parse_nested(graph_blob)
            if graph_msg is None:
                state.add(
                    rule_id="onnx-malformed",
                    severity=Severity.MEDIUM,
                    message="GraphProto unparsable",
                )
                continue
            _analyze_graph(graph_msg, state)

        # metadata_props can carry the same suspicious strings
        meta_entries = _read_kv_entries([
            b for b in model_msg.get(_MODEL_METADATA_PROPS, []) if isinstance(b, bytes)
        ])
        for k, v in meta_entries:
            if not v:
                continue
            v_bytes = v.encode("utf-8", errors="replace")
            if _URL_PATTERN.search(v_bytes):
                state.add(
                    rule_id="onnx-metadata-url",
                    severity=Severity.LOW,
                    message=f"URL in metadata_props['{k}']",
                    location=f"metadata.{k}",
                    snippet=v[:120],
                )

        return state.findings
