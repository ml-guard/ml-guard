"""Runner — обходит путь, выбирает сканеры через реестр, агрегирует находки."""
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


# Директории, которые мы по умолчанию пропускаем — они не ML-артефакты.
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git", ".hg", ".svn",
    "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".tox",
}

# Лимит размера файла для сканирования по умолчанию (можно переопределить).
DEFAULT_MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4 GiB


@dataclass
class ScanResult:
    """Итог одного запуска сканирования."""
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scanners_invoked: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    # ---- удобные свёртки -----------------------------------------------
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
    """Запускает все сканеры для указанного пути."""

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
        # Конфиг даёт дефолты, явные аргументы их перекрывают.
        if self.config.max_file_size_mb is not None and max_file_size == DEFAULT_MAX_FILE_SIZE:
            max_file_size = self.config.max_file_size_mb * 1024 * 1024
        self.max_file_size = max_file_size
        self.ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS

        # Шаблоны: явные аргументы + из конфига (объединение, не замена)
        merged_include = list(include_patterns) if include_patterns else []
        merged_include.extend(self.config.include)
        merged_exclude = list(exclude_patterns) if exclude_patterns else []
        merged_exclude.extend(self.config.exclude)
        self.include_patterns: List[str] = merged_include
        self.exclude_patterns: List[str] = merged_exclude

        # selected_scanners: если явно задано — приоритет, иначе из конфига
        if selected_scanners:
            self.selected_scanners: Optional[Set[str]] = set(selected_scanners)
        elif self.config.scanners:
            self.selected_scanners = set(self.config.scanners)
        else:
            self.selected_scanners = None

        # Параллелизм через потоки. По дефолту workers=1: наши сканеры —
        # CPU-bound (regex / protobuf parse / pickle bytecode walk), и GIL
        # делает многопоточность бесполезной или даже вредной (overhead
        # ThreadPoolExecutor доминирует). Опция оставлена на случай:
        #   • очень больших файлов на медленном I/O (NFS, S3-mount), где
        #     read() реально блокируется — тогда workers=4..8 помогает;
        #   • когда нативный Rust-движок собран и release'ит GIL.
        # 1 = строго последовательно (детерминированный порядок findings).
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

        # Тред-сейфный аккумулятор. .findings/.errors/.scanners_invoked/.files_scanned
        # обновляются из воркер-потоков под одним lock'ом.
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
                # list() — чтобы все исключения, если случатся, вылетели.
                # Внутри worker() мы их уже ловим, так что futures не должны
                # бросать; но fail-safe.
                list(ex.map(worker, files))

        result.duration_seconds = time.monotonic() - started
        return result

    # ------------------------------------------------------------------
    def _scan_one_file(
        self, path: Path, root: Path
    ) -> tuple[List[Finding], int, List[str]]:
        """Сканирует один файл всеми применимыми сканерами.

        Возвращает (findings, scanners_invoked, errors). НЕ модифицирует
        self или общий ScanResult — это делает caller в worker(). Так мы
        упрощаем тред-сейфность: всё, что считает поток, локально, и
        сливается под одним lock'ом за один раз.
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
        Если root — файл, возвращаем [root] (фильтры не применяются — пользователь
        указал точный путь).
        Если директория — рекурсивно собираем файлы, пропуская:
          • директории из ignore_dirs,
          • файлы крупнее max_file_size,
          • симлинки (защита от циклов),
          • файлы, не совпадающие с include_patterns (если задан),
          • файлы, совпадающие с exclude_patterns.
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
        """True если файл проходит include/exclude по relative-path."""
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()

        # exclude имеет приоритет
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.name, pat):
                return False

        if self.include_patterns:
            for pat in self.include_patterns:
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.name, pat):
                    return True
            return False  # есть include, но не совпало

        return True

    def _walk(self, root: Path) -> Iterable[Path]:
        """rglob с фильтрацией ignore_dirs и пропуском симлинков."""
        # Используем os.walk для контроля над тем, в какие директории спускаться.
        import os
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Фильтруем in-place — это позволяет os.walk пропустить директории.
            dirnames[:] = [d for d in dirnames if d not in self.ignore_dirs]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.is_symlink():
                    continue
                yield p
