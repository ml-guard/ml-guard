"""Микро-бенчмарки для сканеров ML Guard.

Запуск:
    PYTHONPATH=. python3 benchmarks/bench.py

Что меряем:
  • per-file throughput для каждого сканера на синтетических артефактах
    разных размеров;
  • full-runner с разным числом workers на смешанной директории;
  • cold/warm: первый запуск vs повторный (там, где есть кэш или JIT-эффекты).

Это НЕ pytest-benchmark и не правило для CI failure: на shared-ranner'е
GitHub Actions цифры пляшут на 2-3x. Цель — детектировать регрессии
выше 10x от запуска к запуску.
"""
from __future__ import annotations

import json
import pickle
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Tuple

# Чтобы запускать как `python3 benchmarks/bench.py` из корня проекта
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_guard.runner import Runner
from ml_guard.scanners.pickle_scanner import PickleScanner
from ml_guard.scanners.safetensors_scanner import SafetensorsScanner
from ml_guard.scanners.onnx_scanner import OnnxScanner
from ml_guard.scanners.secret_scanner import SecretScanner


# ---------------------------------------------------------------------------
# Хелперы для генерации синтетических артефактов
# ---------------------------------------------------------------------------

class _Mal:
    def __reduce__(self):
        import os
        return (os.system, ("echo x",))


def make_pickle_evil(path: Path) -> None:
    path.write_bytes(pickle.dumps(_Mal()))


def make_pickle_clean_large(path: Path, mb: int) -> None:
    """Большой pickle с массивом байтов (типичный сценарий: torch tensor)."""
    payload = {"weights": b"\x00" * (mb * 1024 * 1024)}
    path.write_bytes(pickle.dumps(payload))


def make_safetensors(path: Path, num_tensors: int = 100, tensor_bytes: int = 1024) -> None:
    """Многотензорный safetensors."""
    header = {}
    body = b""
    offset = 0
    for i in range(num_tensors):
        end = offset + tensor_bytes
        header[f"layer{i}"] = {
            "dtype": "F32",
            "shape": [tensor_bytes // 4],
            "data_offsets": [offset, end],
        }
        body += b"\x00" * tensor_bytes
        offset = end
    head = json.dumps(header).encode()
    path.write_bytes(struct.pack("<Q", len(head)) + head + body)


def make_onnx(path: Path, num_nodes: int = 100) -> None:
    """Синтетический ONNX с N стандартных Conv-узлов."""

    def varint(n: int) -> bytes:
        out = bytearray()
        while n > 0x7f:
            out.append((n & 0x7f) | 0x80); n >>= 7
        out.append(n & 0x7f)
        return bytes(out)

    def sf(no: int, s: str) -> bytes:
        p = s.encode()
        return varint((no << 3) | 2) + varint(len(p)) + p

    def vf(no: int, v: int) -> bytes:
        return varint((no << 3) | 0) + varint(v)

    def mf(no: int, b: bytes) -> bytes:
        return varint((no << 3) | 2) + varint(len(b)) + b

    nodes_blob = b""
    for _ in range(num_nodes):
        node = sf(4, "Conv")
        nodes_blob += mf(1, node)
    graph = nodes_blob
    model = vf(1, 8) + sf(5, "bench") + mf(7, graph)
    path.write_bytes(model)


def make_env_with_secrets(path: Path) -> None:
    path.write_text(
        "GH_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n"
        "OPENAI_API_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd\n"
        "DB_HOST=localhost\n"
        "DB_PORT=5432\n"
    )


def make_python_with_string_blob(path: Path, lines: int = 1000) -> None:
    """Большой .py файл — бенчим secret-scanner на длинном источнике."""
    out = []
    for i in range(lines):
        out.append(f"x{i} = 'value_{i:05d}'  # comment {i}")
    out.append("API_KEY = 'sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd'")
    path.write_text("\n".join(out))


# ---------------------------------------------------------------------------
# Раннер бенчмарков
# ---------------------------------------------------------------------------

def time_it(fn: Callable[[], None], runs: int = 5) -> Tuple[float, float]:
    """Возвращает (median_seconds, min_seconds)."""
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    times.sort()
    median = times[len(times) // 2]
    return median, times[0]


def fmt_throughput(seconds: float, bytes_: int) -> str:
    if seconds <= 0:
        return "—"
    mbps = (bytes_ / 1024 / 1024) / seconds
    return f"{mbps:.1f} MB/s"


# ---------------------------------------------------------------------------
# Сами бенчмарки
# ---------------------------------------------------------------------------

def bench_pickle() -> List[Tuple[str, float, float, str]]:
    rows = []
    s = PickleScanner()

    with tempfile.TemporaryDirectory() as td:
        # 1. Маленький вредоносный (~30 bytes)
        p_evil = Path(td) / "evil.pkl"
        make_pickle_evil(p_evil)
        size = p_evil.stat().st_size
        med, _ = time_it(lambda: s.scan(p_evil), runs=20)
        rows.append(("pickle/evil_30B", size, med, fmt_throughput(med, size)))

        # 2. Большой чистый — 4 MB tensor-blob
        p_big = Path(td) / "big.pkl"
        make_pickle_clean_large(p_big, mb=4)
        size = p_big.stat().st_size
        med, _ = time_it(lambda: s.scan(p_big), runs=10)
        rows.append(("pickle/clean_4MB", size, med, fmt_throughput(med, size)))

    return rows


def bench_safetensors() -> List[Tuple[str, float, float, str]]:
    rows = []
    s = SafetensorsScanner()

    with tempfile.TemporaryDirectory() as td:
        p1 = Path(td) / "small.safetensors"
        make_safetensors(p1, num_tensors=10, tensor_bytes=1024)
        size = p1.stat().st_size
        med, _ = time_it(lambda: s.scan(p1), runs=20)
        rows.append(("safetensors/10_tensors", size, med, fmt_throughput(med, size)))

        p2 = Path(td) / "big.safetensors"
        make_safetensors(p2, num_tensors=1000, tensor_bytes=4 * 1024)  # ~4 MB
        size = p2.stat().st_size
        med, _ = time_it(lambda: s.scan(p2), runs=10)
        rows.append(("safetensors/1000_tensors_4MB", size, med, fmt_throughput(med, size)))

    return rows


def bench_onnx() -> List[Tuple[str, float, float, str]]:
    rows = []
    s = OnnxScanner()

    with tempfile.TemporaryDirectory() as td:
        p1 = Path(td) / "small.onnx"
        make_onnx(p1, num_nodes=10)
        size = p1.stat().st_size
        med, _ = time_it(lambda: s.scan(p1), runs=20)
        rows.append(("onnx/10_nodes", size, med, fmt_throughput(med, size)))

        p2 = Path(td) / "big.onnx"
        make_onnx(p2, num_nodes=10_000)
        size = p2.stat().st_size
        med, _ = time_it(lambda: s.scan(p2), runs=10)
        rows.append(("onnx/10000_nodes", size, med, fmt_throughput(med, size)))

    return rows


def bench_secrets() -> List[Tuple[str, float, float, str]]:
    rows = []
    s = SecretScanner()

    with tempfile.TemporaryDirectory() as td:
        p1 = Path(td) / "small.env"
        make_env_with_secrets(p1)
        size = p1.stat().st_size
        med, _ = time_it(lambda: s.scan(p1), runs=20)
        rows.append(("secrets/4_lines", size, med, fmt_throughput(med, size)))

        p2 = Path(td) / "big.py"
        make_python_with_string_blob(p2, lines=10_000)
        size = p2.stat().st_size
        med, _ = time_it(lambda: s.scan(p2), runs=10)
        rows.append(("secrets/10000_py_lines", size, med, fmt_throughput(med, size)))

    return rows


def bench_runner_parallelism() -> List[Tuple[str, float, float, str]]:
    rows = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # 50 разных файлов: 25 pickle + 15 safetensors + 5 onnx + 5 .env
        for i in range(25):
            make_pickle_clean_large(root / f"m{i}.pkl", mb=1)
        for i in range(15):
            make_safetensors(root / f"s{i}.safetensors", num_tensors=50, tensor_bytes=1024)
        for i in range(5):
            make_onnx(root / f"g{i}.onnx", num_nodes=500)
        for i in range(5):
            make_env_with_secrets(root / f"e{i}.env")

        total_bytes = sum(p.stat().st_size for p in root.iterdir())

        for w in (1, 2, 4, 8):
            r = Runner(workers=w)
            med, fastest = time_it(lambda w=w: Runner(workers=w).run(root), runs=3)
            rows.append((
                f"runner/workers={w}",
                total_bytes,
                med,
                fmt_throughput(med, total_bytes),
            ))

    return rows


def main() -> None:
    print(f"ML Guard benchmarks  -  python {sys.version.split()[0]}")
    print("=" * 70)

    sections = [
        ("Pickle scanner",      bench_pickle),
        ("Safetensors scanner", bench_safetensors),
        ("ONNX scanner",        bench_onnx),
        ("Secrets scanner",     bench_secrets),
        ("Runner parallelism",  bench_runner_parallelism),
    ]
    for title, fn in sections:
        print(f"\n--- {title} ---")
        rows = fn()
        for name, size, sec, thr in rows:
            print(f"  {name:<32}  {size:>10} B   {sec*1000:>7.2f} ms   {thr}")

    print()


if __name__ == "__main__":
    main()
