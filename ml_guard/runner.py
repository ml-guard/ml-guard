"""Runner — walks the path, dispatches scanners via the registry, aggregates findings."""
from __future__ import annotations

import concurrent.futures
import fnmatch
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Iterable, Set, Sequence
import time

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, ScannerRegistry, default_registry
from ml_guard.config import Config

log = logging.getLogger(__name__)


# Directories we skip by default — none of these hold ML artifacts.
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".tox",
}

# Default per-file size cap. Override via config or --max-file-size.
DEFAULT_MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4 GiB


@dataclass
class ScanResult:
    """Result of a single scan run."""
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scanners_invoked: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    # ---- convenience accessors -----------------------------------------
    def by_severity(self, sev: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def has_at_least(self, threshold: Severity) -> bool:
        return any(f.severity.at_least(threshold) for f in self.findings)

    def summary_counts(self) -> dict:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


class Runner:
    """Runs every applicable scanner against the given path."""

    def __init__(
        self,
        registry: Optional[ScannerRegistry] = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        ignore_dirs: Optional[Set[str]] = None,
        include_patterns: Optional[Sequence[str]] = None,
        exclude_patterns: Optional[Sequence[str]] = None,
        selected_scanners: Optional[Sequence[str]] = None,
        config: Optional[Config] = None,
        workers: Optional[int] = None,
    ) -> None:
        self.registry = registry or default_registry
        self.config = config or Config.empty()
        # Config provides defaults; explicit constructor args override them.
        if self.config.max_file_size_mb is not None and max_file_size == DEFAULT_MAX_FILE_SIZE:
            max_file_size = self.config.max_file_size_mb * 1024 * 1024
        self.max_file_size = max_file_size
        self.ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS

        # Patterns: explicit args are merged with config (union, not replace).
        merged_include = list(include_patterns) if include_patterns else []
        merged_include.extend(self.config.include)
        merged_exclude = list(exclude_patterns) if exclude_patterns else []
        merged_exclude.extend(self.config.exclude)
        self.include_patterns: List[str] = merged_include
        self.exclude_patterns: List[str] = merged_exclude

        # Scanner selection: explicit arg wins, else config, else "run all".
        if selected_scanners:
            self.selected_scanners: Optional[Set[str]] = set(selected_scanners)
        elif self.config.scanners:
            self.selected_scanners = set(self.config.scanners)
        else:
            self.selected_scanners = None

        # Threaded parallelism. Default workers=1: our scanners are CPU-bound
        # (regex, protobuf parsing, pickle bytecode walks), and the GIL makes
        # multi-threading either useless or counterproductive due to
        # ThreadPoolExecutor overhead. We expose the knob anyway for two cases:
        #   • huge files on slow I/O (NFS, S3-mount) where read() actually
        #     blocks — workers=4..8 helps;
        #   • when the native Rust engine is built and releases the GIL.
        # workers=1 also guarantees deterministic finding order.
        if workers is None:
            workers = 1
        if workers < 1:
            workers = 1
        self.workers = workers

    # ------------------------------------------------------------------
    def run(self, root: Path) -> ScanResult:
        root = root.resolve()
        result = ScanResult()
        started = time.monotonic()

        if not root.exists():
            result.errors.append(f"Path does not exist: {root}")
            return result

        files = self._collect_files(root)

        # Thread-safe accumulator. .findings/.errors/.scanners_invoked/
        # .files_scanned are updated from worker threads under one lock.
        result_lock = threading.Lock()

        def worker(path: Path) -> None:
            findings, scanners_invoked, errors = self._scan_one_file(path, root)
            if scanners_invoked == 0:
                return
            with result_lock:
                result.files_scanned += 1
                result.scanners_invoked += scanners_invoked
                result.findings.extend(findings)
                result.errors.extend(errors)

        if self.workers <= 1 or len(files) <= 1:
            for p in files:
                worker(p)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
                # list() materializes results so any exception surfaces here.
                # worker() catches its own errors, but this is a fail-safe.
                list(ex.map(worker, files))

        result.duration_seconds = time.monotonic() - started
        return result

    # ------------------------------------------------------------------
    def _scan_one_file(
        self, path: Path, root: Path
    ) -> tuple[List[Finding], int, List[str]]:
        """Scan one file with every applicable scanner.

        Returns (findings, scanners_invoked, errors). Does NOT mutate self
        or the shared ScanResult — that's the caller's job in worker().
        Keeping per-call state local simplifies thread safety: everything a
        thread accumulates is local until merged under a single lock.
        """
        applicable = list(self.registry.applicable(path))
        if self.selected_scanners is not None:
            applicable = [s for s in applicable if s.name in self.selected_scanners]
        if not applicable:
            return [], 0, []

        local_findings: List[Finding] = []
        local_errors: List[str] = []
        scanners_invoked = 0

        for scanner in applicable:
            scanners_invoked += 1
            try:
                found = scanner.scan(path)
            except Exception as e:  # noqa: BLE001
                msg = f"Scanner {scanner.name} crashed on {path}: {e}"
                log.exception(msg)
                local_errors.append(msg)
                continue
            for f in found:
                if not f.file:
                    try:
                        f.file = str(path.relative_to(root))
                    except ValueError:
                        f.file = str(path)
                if not f.scanner:
                    f.scanner = scanner.name
                kept = self.config.apply_rule_override(f)
                if kept is not None:
                    local_findings.append(kept)

        return local_findings, scanners_invoked, local_errors

    # ------------------------------------------------------------------
    def _collect_files(self, root: Path) -> List[Path]:
        """
        If root is a file, return [root] — filters don't apply because the
        user pointed at an exact path.
        If it's a directory, walk recursively and skip:
          • directories in ignore_dirs,
          • files larger than max_file_size,
          • symlinks (cycle protection),
          • files that don't match include_patterns (when set),
          • files that match exclude_patterns.
        """
        if root.is_file():
            return [root]

        out: List[Path] = []
        for path in self._walk(root):
            try:
                size = path.stat().st_size
            except OSError as e:
                log.debug("Cannot stat %s: %s", path, e)
                continue
            if size > self.max_file_size:
                log.debug("Skipping large file: %s (%d bytes)", path, size)
                continue
            if not self._matches_filters(path, root):
                continue
            out.append(path)
        return out

    def _matches_filters(self, path: Path, root: Path) -> bool:
        """True if the file passes include/exclude against its relative path."""
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()

        # exclude wins over include
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.name, pat):
                return False

        if self.include_patterns:
            for pat in self.include_patterns:
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.name, pat):
                    return True
            return False  # include set but nothing matched

        return True

    def _walk(self, root: Path) -> Iterable[Path]:
        """rglob equivalent with ignore_dirs filtering and symlink skipping."""
        # os.walk is used (not Path.rglob) so we can prune ignored directories
        # in-place via dirnames[:] = ... and avoid descending into them.
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # In-place filter lets os.walk skip the pruned dirs entirely.
            dirnames[:] = [d for d in dirnames if d not in self.ignore_dirs]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.is_symlink():
                    continue
                yield p
