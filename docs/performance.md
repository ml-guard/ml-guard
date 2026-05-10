# Performance notes

This document captures real measurements of ML Guard scanners on a
reference machine (Linux x86_64, Python 3.12). Numbers will differ on
your hardware — what matters is the *shape* of the cost curve.

## Reference benchmarks

```
$ python3 benchmarks/bench.py

--- Pickle scanner ---
  pickle/evil_30B                       44 B      0.03 ms   1.6 MB/s
  pickle/clean_4MB                 4194335 B      3.35 ms   1192 MB/s

--- Safetensors scanner ---
  safetensors/10_tensors             10986 B      0.04 ms   275 MB/s
  safetensors/1000_tensors_4MB     4178352 B      2.91 ms   1370 MB/s

--- ONNX scanner ---
  onnx/10_nodes                         91 B      0.04 ms     2.5 MB/s
  onnx/10000_nodes                   80013 B     18.28 ms     4.2 MB/s

--- Secrets scanner ---
  secrets/4_lines                      145 B      0.05 ms     2.7 MB/s
  secrets/10000_py_lines            377840 B     66.63 ms     5.4 MB/s
```

## What dominates each scanner

### Pickle
**Bytecode walk via `pickletools.genops`.** That iterator is implemented
in C inside CPython, so the Python overhead is small. A 4 MB tensor
pickle is parsed at ~1 GB/s effective throughput (we don't actually
deserialize the tensor data — opcodes are skipped).

The native Rust path exists but adds little for typical files. It only
matters for pickles with many millions of opcodes (rare).

### Safetensors
**Header parse + offset validation.** The bulk of the file is binary
tensor bytes that we never read — we only validate that `data_offsets`
are consistent. Throughput scales with header size, not file size.

### ONNX
**Custom protobuf parser walks the entire ModelProto.** Every node and
attribute is decoded. This is the slowest scanner per byte (~4 MB/s)
because it does ~20 method calls per node in Python. We considered
pulling in `protobuf`/`onnx` libraries — those are 5-10x faster but
introduce a parser-of-the-target-format inside our security tool, which
is a bad pattern. We ate the perf cost.

### Secrets
**Many regexes per line + Shannon entropy.** The slowest case is large
source files with no secrets — we still execute every regex on every
line. The pre-check `_line_has_marker(line)` short-circuits the entropy
path when no marker word is present, giving a ~30% win on clean files.

## Why we don't parallelize by default

We added `--workers N` and a `ThreadPoolExecutor` path in the runner.
Then we measured:

```
--- Runner parallelism (50 mixed files, 25 MB total) ---
  runner/workers=1                21.0 ms
  runner/workers=2                25.5 ms
  runner/workers=4                22.7 ms
  runner/workers=8                37.9 ms
```

**Parallelism didn't help.** Two reasons:

1. **CPU-bound work, not I/O-bound.** Most scanner time is spent in
   regex / protobuf parse / pickle bytecode walk — pure Python under the
   GIL. Threads can't run concurrently.
2. **Per-file work is small.** Even the slow ONNX scanner finishes a
   typical file in single-digit milliseconds. Thread pool overhead
   (queue, lock, dispatch) starts to dominate.

So we made `workers=1` the default. The flag is still there for users
running on slow remote storage (NFS, FUSE mounts, S3 mounts) where
`open()/read()` actually blocks — there, threads do release the GIL
during I/O wait and the parallel runner does help.

If we ever ship the Rust pickle scanner widely, we'll revisit: Rust code
releases the GIL by default, and `workers > 1` would actually help for
pickle-heavy directories.

## When to use ProcessPoolExecutor instead

We don't ship one. Process pools cost ~50 ms per worker startup — that's
already 2× the total runtime of a typical scan. Only worth it for
multi-gigabyte models where one scan takes seconds. If you need that,
parallelize at the *directory* level: run `ml-guard scan` on different
subdirectories in separate shells.

## Finding regressions

Run `benchmarks/bench.py` before and after a change. We don't have
strict thresholds in CI — shared runners are too noisy — but a 10x
slowdown on any line should be investigated.

## Optimizations we deferred

- **Native ONNX parser in Rust.** Would push throughput from 4 MB/s to
  100+ MB/s and matter for big LLM exports. Tracked as a follow-up.
- **Compiled regex sets in `secrets`.** Combine all provider regexes
  into one alternation and dispatch via `match.lastgroup`. Could halve
  the slow-case cost.
- **Memory-mapped reads** for large safetensors / pickles. Reduces
  resident memory but doesn't help throughput on small files.
