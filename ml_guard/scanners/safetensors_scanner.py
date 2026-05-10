"""Safetensors scanner — статический анализ формата safetensors.

Формат (стабилизирован Hugging Face, https://github.com/huggingface/safetensors):

    [ 8 bytes:  header_size  (u64 little-endian) ]
    [ header_size bytes:  JSON header ]
    [ rest:  raw tensor data ]

JSON-заголовок:
    {
      "tensor_name": {
        "dtype": "F32",
        "shape": [1024, 768],
        "data_offsets": [start, end]      # относительно начала data-секции
      },
      ...
      "__metadata__": { "format": "pt", ... }    # необязательно
    }

Safetensors *по дизайну* безопаснее pickle: нет исполняемого кода. Но мы всё
равно ищем способы протащить вредоносное содержимое:

1. **Trailing data** после конца последнего тензора — там не должно быть ничего;
   наличие исполняемых сигнатур (ELF, MZ, shellcode) — серьёзный red flag.
2. **Лживые offset'ы** — указывают за пределы data-секции или пересекаются
   между тензорами. Загрузчики на C++ исторически имели CVE на этом векторе.
3. **Несуществующие dtype'ы** — попытка "обмануть" парсер.
4. **Подозрительные строки в __metadata__** — URL/IP/пути → возможный
   exfiltration-канал.
5. **Аномально большой заголовок** (> 100 MB) — DoS или эксплойт.
6. **Заголовок не валидный JSON** — повреждён или специально малформирован.

Реализация — полностью на Python, без зависимостей. Структура файла очень простая.
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register


# ---------------------------------------------------------------------------
# Константы и базы знаний
# ---------------------------------------------------------------------------

# Известные dtype safetensors. Источник: huggingface/safetensors README.
_KNOWN_DTYPES = frozenset({
    "BOOL",
    "U8", "I8",
    "F8_E5M2", "F8_E4M3",
    "U16", "I16", "F16", "BF16",
    "U32", "I32", "F32",
    "U64", "I64", "F64",
})

# Размеры элементов в байтах (для валидации numel * size == segment length).
_DTYPE_BYTES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1,
    "U16": 2, "I16": 2, "F16": 2, "BF16": 2,
    "U32": 4, "I32": 4, "F32": 4,
    "U64": 8, "I64": 8, "F64": 8,
}

# Лимит размера заголовка. В реальной жизни даже самый крупный модельный header —
# единицы мегабайт. 100 МБ — заведомо аномалия.
_MAX_HEADER_BYTES = 100 * 1024 * 1024

# Разумная нижняя граница: пустой заголовок {} = 2 байта.
_MIN_HEADER_BYTES = 2

# Сигнатуры исполняемых форматов в trailing-данных
_EXEC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"\x7fELF",        "ELF (Linux executable)"),
    (b"MZ",             "PE/DOS (Windows executable)"),
    (b"\xca\xfe\xba\xbe", "Mach-O (fat binary)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit LE)"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit BE)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit BE)"),
    (b"#!/",            "shebang script"),
    (b"PK\x03\x04",     "ZIP archive (potential nested payload)"),
    (b"\x1f\x8b",       "gzip archive"),
]

# Регексы для поиска "интересных" строк в __metadata__.
# Намеренно консервативные — false positive раздражает больше чем пропуск.
_URL_RE = re.compile(rb"https?://[A-Za-z0-9.\-/_:?=&%~+#]+", re.ASCII)
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", re.ASCII)
_ABS_PATH_RE = re.compile(rb"(?:^|[\s\"'(])(?:/(?:etc|root|home|var|proc|tmp)/[A-Za-z0-9./_\-]+)", re.ASCII)
_WIN_PATH_RE = re.compile(rb"(?:^|[\s\"'(])[A-Za-z]:\\\\[A-Za-z0-9.\\\-_]+", re.ASCII)

# IP-адреса в metadata типа дата-сета — это нормально (например 127.0.0.1 как заглушка).
# Поэтому 127.0.0.1 / 0.0.0.0 / 255.255.255.255 фильтруем.
_IGNORED_IPS = {b"127.0.0.1", b"0.0.0.0", b"255.255.255.255", b"1.1.1.1"}


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

@dataclass
class _Tensor:
    name: str
    dtype: str
    shape: List[int]
    start: int
    end: int


class _SafetensorsParseError(Exception):
    pass


def _parse_header(data: bytes) -> Tuple[int, Dict[str, Any]]:
    """Возвращает (header_bytes_len, parsed_json). Бросает _SafetensorsParseError."""
    if len(data) < 8:
        raise _SafetensorsParseError("file too short for header length")
    (header_len,) = struct.unpack("<Q", data[:8])
    if header_len < _MIN_HEADER_BYTES:
        raise _SafetensorsParseError(f"header too small: {header_len} bytes")
    if header_len > _MAX_HEADER_BYTES:
        raise _SafetensorsParseError(f"header improbably large: {header_len} bytes")
    if 8 + header_len > len(data):
        raise _SafetensorsParseError(
            f"declared header_size={header_len} exceeds file size={len(data)}"
        )
    header_bytes = data[8 : 8 + header_len]
    try:
        parsed = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise _SafetensorsParseError(f"invalid JSON header: {e}") from e
    if not isinstance(parsed, dict):
        raise _SafetensorsParseError("header is not a JSON object")
    return header_len, parsed


def _extract_tensors(parsed: Dict[str, Any]) -> Tuple[List[_Tensor], List[str]]:
    """Извлекает тензоры из JSON-заголовка. Возвращает (tensors, parse_warnings)."""
    tensors: List[_Tensor] = []
    warnings: List[str] = []
    for name, body in parsed.items():
        if name == "__metadata__":
            continue
        if not isinstance(body, dict):
            warnings.append(f"tensor entry '{name}' is not an object")
            continue
        dtype = body.get("dtype")
        shape = body.get("shape")
        offs = body.get("data_offsets")
        if not isinstance(dtype, str):
            warnings.append(f"tensor '{name}' missing/invalid dtype")
            continue
        if not isinstance(shape, list) or not all(isinstance(d, int) and d >= 0 for d in shape):
            warnings.append(f"tensor '{name}' invalid shape: {shape!r}")
            continue
        if (
            not isinstance(offs, list)
            or len(offs) != 2
            or not all(isinstance(o, int) for o in offs)
        ):
            warnings.append(f"tensor '{name}' invalid data_offsets: {offs!r}")
            continue
        start, end = offs
        tensors.append(_Tensor(name=name, dtype=dtype, shape=shape, start=start, end=end))
    return tensors, warnings


def _shape_numel(shape: List[int]) -> int:
    n = 1
    for d in shape:
        n *= d
    return n


# ---------------------------------------------------------------------------
# Сам сканер
# ---------------------------------------------------------------------------

@register
class SafetensorsScanner(Scanner):
    name = "safetensors"
    description = (
        "Detects malformed safetensors headers, lying offsets, "
        "trailing executables, and exfiltration hints in metadata"
    )

    _EXTENSIONS = {".safetensors"}
    MAX_BYTES = 16 * 1024 * 1024 * 1024  # 16 GiB

    # Магия: u64 little-endian header_size, обычно небольшое значение, поэтому
    # старшие байты ≈ 0. Это слабый сигнал; полагаемся на расширение.

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        return path.suffix.lower() in self._EXTENSIONS

    def scan(self, path: Path) -> List[Finding]:
        size = path.stat().st_size
        if size > self.MAX_BYTES:
            return [Finding(
                rule_id="safetensors-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({size} bytes); skipped",
                file=str(path),
                scanner=self.name,
            )]

        with path.open("rb") as f:
            data = f.read()

        return self._scan_bytes(data, file_size=size)

    # ------------------------------------------------------------------
    def _scan_bytes(self, data: bytes, file_size: int) -> List[Finding]:
        findings: List[Finding] = []

        try:
            header_len, parsed = _parse_header(data)
        except _SafetensorsParseError as e:
            return [Finding(
                rule_id="safetensors-malformed-header",
                severity=Severity.HIGH,
                message=f"Malformed safetensors header: {e}",
                file="",
                scanner=self.name,
                location="bytes 0..7",
            )]

        data_section_start = 8 + header_len
        data_section_size = len(data) - data_section_start

        tensors, warnings = _extract_tensors(parsed)
        for w in warnings:
            findings.append(Finding(
                rule_id="safetensors-invalid-tensor-entry",
                severity=Severity.MEDIUM,
                message=w,
                file="",
                scanner=self.name,
            ))

        # Анализ offset'ов
        max_end = 0
        prev_end = 0
        for t in sorted(tensors, key=lambda x: x.start):
            self._check_tensor_bounds(t, data_section_size, findings)
            self._check_tensor_dtype(t, findings)
            self._check_tensor_size_consistency(t, findings)
            if t.start < prev_end:
                findings.append(Finding(
                    rule_id="safetensors-overlapping-tensors",
                    severity=Severity.HIGH,
                    message=(
                        f"Tensor '{t.name}' starts at {t.start} but previous tensor "
                        f"ends at {prev_end} (overlap)"
                    ),
                    file="",
                    scanner=self.name,
                    location=f"tensor '{t.name}'",
                ))
            prev_end = max(prev_end, t.end)
            max_end = max(max_end, t.end)

        # Trailing data после последнего тензора?
        # Допускаем небольшой padding (до 64 байт — спецификация это допускает в реальности).
        ALLOWED_PADDING = 64
        trailing_size = data_section_size - max_end
        if trailing_size > ALLOWED_PADDING:
            trailing_off = data_section_start + max_end
            trailing = data[trailing_off : trailing_off + min(trailing_size, 4096)]
            sig = self._find_executable_signature(trailing)
            if sig is not None:
                findings.append(Finding(
                    rule_id="safetensors-executable-trailing",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Trailing payload after last tensor ({trailing_size} bytes) "
                        f"begins with {sig} signature"
                    ),
                    file="",
                    scanner=self.name,
                    location=f"offset 0x{trailing_off:x}",
                    snippet=trailing[:32].hex(),
                ))
            else:
                findings.append(Finding(
                    rule_id="safetensors-hidden-data",
                    severity=Severity.MEDIUM,
                    message=(
                        f"{trailing_size} bytes of trailing data after last tensor"
                    ),
                    file="",
                    scanner=self.name,
                    location=f"offset 0x{trailing_off:x}",
                    snippet=trailing[:32].hex(),
                ))

        # Анализ __metadata__ на признаки exfiltration
        meta = parsed.get("__metadata__")
        if isinstance(meta, dict):
            self._scan_metadata(meta, findings)

        return findings

    # ------------------------------------------------------------------
    def _check_tensor_bounds(
        self, t: _Tensor, data_section_size: int, findings: List[Finding]
    ) -> None:
        if t.start < 0 or t.end < 0:
            findings.append(Finding(
                rule_id="safetensors-negative-offset",
                severity=Severity.HIGH,
                message=f"Tensor '{t.name}' has negative offset",
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))
            return
        if t.start > t.end:
            findings.append(Finding(
                rule_id="safetensors-inverted-offsets",
                severity=Severity.HIGH,
                message=f"Tensor '{t.name}' has start > end ({t.start} > {t.end})",
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))
            return
        if t.end > data_section_size:
            findings.append(Finding(
                rule_id="safetensors-out-of-bounds",
                severity=Severity.HIGH,
                message=(
                    f"Tensor '{t.name}' extends past data section "
                    f"(end={t.end}, section={data_section_size})"
                ),
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))

    def _check_tensor_dtype(self, t: _Tensor, findings: List[Finding]) -> None:
        if t.dtype not in _KNOWN_DTYPES:
            findings.append(Finding(
                rule_id="safetensors-unknown-dtype",
                severity=Severity.MEDIUM,
                message=f"Tensor '{t.name}' uses unknown dtype '{t.dtype}'",
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))

    def _check_tensor_size_consistency(self, t: _Tensor, findings: List[Finding]) -> None:
        """Размер сегмента = numel * dtype_bytes. Иначе тензор «лжёт»."""
        elem_size = _DTYPE_BYTES.get(t.dtype)
        if elem_size is None:
            return  # уже зарепортили unknown-dtype
        try:
            numel = _shape_numel(t.shape)
        except OverflowError:
            findings.append(Finding(
                rule_id="safetensors-shape-overflow",
                severity=Severity.HIGH,
                message=f"Tensor '{t.name}' shape product overflows",
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))
            return
        expected = numel * elem_size
        actual = t.end - t.start
        # Разрешаем равенство; всё остальное — ложь.
        if actual != expected:
            findings.append(Finding(
                rule_id="safetensors-size-mismatch",
                severity=Severity.HIGH,
                message=(
                    f"Tensor '{t.name}' segment size {actual}B != expected "
                    f"{expected}B (numel={numel}, dtype={t.dtype})"
                ),
                file="", scanner=self.name,
                location=f"tensor '{t.name}'",
            ))

    def _find_executable_signature(self, blob: bytes) -> Optional[str]:
        for sig, name in _EXEC_SIGNATURES:
            if blob.startswith(sig):
                return name
        # Также проверяем первые ~16 байт — иногда payload смещён padding'ом.
        head = blob[:64]
        for sig, name in _EXEC_SIGNATURES:
            idx = head.find(sig)
            if idx != -1 and idx < 16:
                return name
        return None

    def _scan_metadata(self, meta: Dict[str, Any], findings: List[Finding]) -> None:
        """Ищем подозрительные строки в __metadata__: URL, IP, абс.пути."""
        # Сериализуем в bytes один раз
        try:
            meta_bytes = json.dumps(meta, sort_keys=True).encode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return

        urls = _URL_RE.findall(meta_bytes)
        if urls:
            sample = urls[0].decode("utf-8", errors="replace")[:100]
            findings.append(Finding(
                rule_id="safetensors-metadata-url",
                severity=Severity.LOW,
                message=f"URL in __metadata__: {sample}",
                file="", scanner=self.name,
                location="__metadata__",
                snippet=sample,
            ))

        ips = [
            ip for ip in _IPV4_RE.findall(meta_bytes)
            if ip not in _IGNORED_IPS and self._is_valid_ip(ip)
        ]
        if ips:
            sample = ips[0].decode("ascii", errors="replace")
            findings.append(Finding(
                rule_id="safetensors-metadata-ip",
                severity=Severity.MEDIUM,
                message=f"IP address in __metadata__: {sample}",
                file="", scanner=self.name,
                location="__metadata__",
                snippet=sample,
            ))

        if _ABS_PATH_RE.search(meta_bytes) or _WIN_PATH_RE.search(meta_bytes):
            findings.append(Finding(
                rule_id="safetensors-metadata-path",
                severity=Severity.LOW,
                message="Absolute filesystem path in __metadata__",
                file="", scanner=self.name,
                location="__metadata__",
            ))

    @staticmethod
    def _is_valid_ip(b: bytes) -> bool:
        """Дополнительная валидация — отфильтровать строки-числа типа 999.999.999.999."""
        try:
            parts = b.split(b".")
            if len(parts) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
