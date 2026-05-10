"""ONNX scanner — статический анализ моделей в формате ONNX.

ONNX — это сериализованный protobuf (`onnx.ModelProto`). Мы НЕ используем
библиотеку `onnx` — это даёт независимость от её парсера и нулевые
дополнительные зависимости. Вместо этого читаем wire-format напрямую через
`ml_guard._protobuf`.

Что мы ловим:

  1. **Custom-domain operators**. Стандартные ONNX-операторы живут в домене
     "" (пустой) или "ai.onnx*". Всё прочее (`com.microsoft`, `nvidia.*`,
     произвольное `evil.exfil`) — это плагины, которые runtime может
     загружать как нативный код. Это полностью законное поведение, но
     для аудита — high-severity флаг: операторы из неизвестных доменов
     не должны попадать в production без явного approve.

  2. **Внешние данные (`external_data`)**. ONNX позволяет хранить тензоры
     отдельно — в файле, на диске или (что страшно) по абсолютному пути.
     Если путь содержит `..`, абсолютные `/etc/`, или URL — это вектор
     для path-traversal или SSRF.

  3. **Слишком старый opset_import**. opset < 7 относится к ранним версиям
     с известными несовместимостями и эксплоит-сурфейсом в старых
     парсерах.

  4. **Подозрительные строковые атрибуты**. Атрибуты с типом STRING,
     содержащие команды ОС, шеллы, абсолютные пути — это маркер
     прокинутого payload'а через граф (`Eval`-подобные кастомные узлы).

  5. **Глубоко вложенные подграфы / огромное число узлов** — DoS-вектор;
     ставим лимиты.

  6. **Битый/малформированный proto** — отдельный finding (как и для pickle).

Этот сканер работает на чистом Python без зависимостей, кроме нашего
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
# ONNX schema constants (численные ID полей proto)
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
# Известные стандартные домены ONNX
# ---------------------------------------------------------------------------

# Пустой домен и официальные ai.onnx-домены — это canonical operators.
_STANDARD_DOMAINS: Set[str] = {
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
}

# Известные «полу-доверенные» домены, идущие от мейнстрим runtimes.
# Не critical, но достойны medium-флага: пользователь должен знать, что
# модель будет работать только при наличии соответствующего runtime.
_KNOWN_VENDOR_DOMAINS: Set[str] = {
    "com.microsoft",
    "com.microsoft.experimental",
    "com.microsoft.nchwc",
    "com.ms.internal.nhwc",
    "org.pytorch",
    "org.pytorch.aten",
    "ai.onnx.contrib",
}

# Минимальный поддерживаемый ir_version. ONNX 1.0 = 3, ONNX 1.4+ = 4-5+.
# Ниже 3 = очень старые модели.
_MIN_IR_VERSION = 3
_MIN_OPSET_VERSION = 7   # ai.onnx ниже 7 — реально древние


# ---------------------------------------------------------------------------
# Sniffers для строковых атрибутов
# ---------------------------------------------------------------------------

# Команды ОС / шеллы / пути — то же, что в secret scanner, но строже.
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

# Минимальная длина для энтропийного теста / подозрительной строки.
_STR_INTEREST_MIN = 8


# ---------------------------------------------------------------------------
# Лимиты — DoS защита
# ---------------------------------------------------------------------------

# Максимальное число узлов в графе (включая subgraphs). Реальные модели
# редко имеют > 100k операторов; миллион — почти всегда атака или ошибка.
MAX_GRAPH_NODES = 1_000_000
MAX_FILE_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB


# ---------------------------------------------------------------------------
# Парсинг с агрегацией находок
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
# Анализ нодов / графа
# ---------------------------------------------------------------------------

def _analyze_attribute(attr_msg: Dict[int, List], state: _ScanState, node_label: str) -> None:
    """Проверяем один AttributeProto."""
    name = _read_string_field(attr_msg, _ATTR_NAME) or "<anonymous>"
    attr_type = _read_int_field(attr_msg, _ATTR_TYPE)

    # Тип STRING или массив STRINGS — содержимое стоит проверить
    if attr_type == _ATTR_TYPE_STRING or _ATTR_S in attr_msg:
        for blob in attr_msg.get(_ATTR_S, []):
            if isinstance(blob, bytes):
                _analyze_string_attribute(blob, state, node_label, name)
    if _ATTR_STRINGS in attr_msg:
        for blob in attr_msg.get(_ATTR_STRINGS, []):
            if isinstance(blob, bytes):
                _analyze_string_attribute(blob, state, node_label, name)

    # Subgraph (например, в If/Loop/Scan) — рекурсия
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
    """Эвристики поверх string-атрибута."""
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

    # Операторы из кастомных доменов
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

    # Атрибуты узла
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
    """Ищем external_data со ссылками на странные пути."""
    name = _read_string_field(tensor_msg, _TENSOR_NAME) or "<unnamed>"
    data_location = _read_int_field(tensor_msg, _TENSOR_DATA_LOCATION)

    ext_blobs = tensor_msg.get(_TENSOR_EXTERNAL_DATA, [])
    if not ext_blobs and data_location != _DATA_LOCATION_EXTERNAL:
        return

    entries = _read_kv_entries([b for b in ext_blobs if isinstance(b, bytes)])
    for k, v in entries:
        if k != "location":
            continue
        # location — это путь к файлу-данным. В безопасной модели это
        # относительный путь без `..`. Всё иное — высокий риск.
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
            # Неизвестный домен в opset_import = все его операторы будут
            # считаться custom; узел-уровень тоже это поймает, но фиксируем
            # отдельно — это явный «декларативный» сигнал.
            sev = Severity.MEDIUM if domain in _KNOWN_VENDOR_DOMAINS else Severity.HIGH
            state.add(
                rule_id="onnx-non-standard-opset-domain",
                severity=sev,
                message=f"Non-standard opset domain declared: '{domain}' (version={version})",
                location="opset_import",
                snippet=f"{domain}@{version}",
            )


# ---------------------------------------------------------------------------
# Сам сканер
# ---------------------------------------------------------------------------

@register
class OnnxScanner(Scanner):
    name = "onnx"
    description = "Detects custom ops, suspicious external_data, and shell-like attributes in ONNX models"

    _EXTENSIONS = {".onnx"}

    # ONNX-magic: первый proto-tag для ModelProto.ir_version (field 1, varint) = 0x08.
    # Не самая надёжная сигнатура, поэтому полагаемся в первую очередь на расширение.
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

        # metadata_props — могут содержать те же подозрительные строки
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
