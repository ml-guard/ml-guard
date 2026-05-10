"""Тесты Safetensors scanner.

Структура файла:
    [u64 LE header_size][header_size bytes JSON][raw tensor data]
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from ml_guard.findings import Severity
from ml_guard.scanners.safetensors_scanner import SafetensorsScanner


def _build(header: dict, body: bytes = b"") -> bytes:
    head = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(head)) + head + body


def _has_rule(findings, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def test_can_scan(tmp_path: Path):
    s = SafetensorsScanner()
    p = tmp_path / "x.safetensors"
    p.write_bytes(b"")
    assert s.can_scan(p)
    other = tmp_path / "x.bin"
    other.write_bytes(b"")
    assert not s.can_scan(other)


def test_clean_file_no_findings(tmp_path: Path):
    """Один тензор F32 [2,3] = 24 байта."""
    p = tmp_path / "ok.safetensors"
    body = b"\x00" * 24
    header = {
        "weight": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]},
        "__metadata__": {"format": "pt"},
    }
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert findings == [], [f.to_dict() for f in findings]


def test_too_short_file(tmp_path: Path):
    p = tmp_path / "tiny.safetensors"
    p.write_bytes(b"\x00\x00")
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-malformed-header")


def test_header_size_exceeds_file(tmp_path: Path):
    p = tmp_path / "lying.safetensors"
    # Заявляем огромный header в маленьком файле
    p.write_bytes(struct.pack("<Q", 999999) + b"{}")
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-malformed-header")


def test_invalid_json(tmp_path: Path):
    p = tmp_path / "badjson.safetensors"
    bad = b"{not valid json"
    p.write_bytes(struct.pack("<Q", len(bad)) + bad)
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-malformed-header")


def test_out_of_bounds_tensor(tmp_path: Path):
    """Тензор объявляет конец за пределами data-секции."""
    p = tmp_path / "oob.safetensors"
    # body = 4 байта, но тензор просит [0, 1000]
    body = b"\x00" * 4
    header = {"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 1000]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-out-of-bounds")


def test_size_mismatch(tmp_path: Path):
    """numel * dtype_bytes != end - start → лживый тензор."""
    p = tmp_path / "mis.safetensors"
    # Тензор F32 shape=[2,3] должен быть 24 байта; даём 16.
    body = b"\x00" * 16
    header = {"w": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 16]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-size-mismatch")


def test_unknown_dtype(tmp_path: Path):
    p = tmp_path / "dtype.safetensors"
    body = b"\x00" * 8
    header = {"w": {"dtype": "F999", "shape": [2], "data_offsets": [0, 8]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-unknown-dtype")


def test_overlapping_tensors(tmp_path: Path):
    p = tmp_path / "overlap.safetensors"
    body = b"\x00" * 32
    header = {
        "a": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        "b": {"dtype": "F32", "shape": [4], "data_offsets": [8, 24]},  # пересекается с a
    }
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-overlapping-tensors")


def test_trailing_executable(tmp_path: Path):
    """ELF в trailing-данных = critical."""
    p = tmp_path / "elf.safetensors"
    legit = b"\x00" * 16
    trailing = b"\x7fELF" + b"\x00" * 100  # ELF header + payload
    body = legit + trailing
    header = {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-executable-trailing")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_trailing_random_data_medium(tmp_path: Path):
    """Произвольные ~256 байт после тензора без exe-сигнатуры → medium."""
    p = tmp_path / "trail.safetensors"
    body = b"\x00" * 16 + b"random_payload_here_" * 20  # ~400 байт
    header = {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-hidden-data")
    assert not _has_rule(findings, "safetensors-executable-trailing")


def test_metadata_url_detected(tmp_path: Path):
    p = tmp_path / "meta.safetensors"
    body = b"\x00" * 4
    header = {
        "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "__metadata__": {"hint": "exfil to http://evil.example.com/x"},
    }
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-metadata-url")


def test_metadata_ip_detected(tmp_path: Path):
    p = tmp_path / "meta_ip.safetensors"
    body = b"\x00" * 4
    header = {
        "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "__metadata__": {"server": "8.8.8.8"},
    }
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert _has_rule(findings, "safetensors-metadata-ip")


def test_metadata_localhost_ignored(tmp_path: Path):
    """127.0.0.1 — типичная заглушка, не должна давать алёрт."""
    p = tmp_path / "meta_local.safetensors"
    body = b"\x00" * 4
    header = {
        "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        "__metadata__": {"server": "127.0.0.1"},
    }
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert not _has_rule(findings, "safetensors-metadata-ip")


def test_padding_below_threshold_ignored(tmp_path: Path):
    """Небольшой padding (<= 64 байта) — это норма, не флагуем."""
    p = tmp_path / "pad.safetensors"
    body = b"\x00" * 16 + b"\x00" * 32  # 32 байта padding
    header = {"w": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]}}
    p.write_bytes(_build(header, body))
    findings = SafetensorsScanner().scan(p)
    assert not _has_rule(findings, "safetensors-hidden-data")
