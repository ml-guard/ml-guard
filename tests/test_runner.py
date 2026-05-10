"""Тесты Runner — обход директорий, агрегация результатов."""
from __future__ import annotations

import pickle
from pathlib import Path

from ml_guard.findings import Severity
from ml_guard.runner import Runner, ScanResult, DEFAULT_IGNORE_DIRS

# Импорт регистрирует pickle scanner в default_registry.
import ml_guard.scanners.pickle_scanner  # noqa: F401


class _Mal:
    def __reduce__(self):
        import os
        return (os.system, ("echo x",))


def _make_evil_pkl(p: Path) -> None:
    with p.open("wb") as f:
        pickle.dump(_Mal(), f)


def _make_clean_pkl(p: Path) -> None:
    with p.open("wb") as f:
        pickle.dump({"a": 1}, f)


def test_run_empty_dir(tmp_path: Path):
    r = Runner()
    result = r.run(tmp_path)
    assert isinstance(result, ScanResult)
    assert result.files_scanned == 0
    assert result.findings == []


def test_run_single_clean_file(tmp_path: Path):
    p = tmp_path / "a.pkl"
    _make_clean_pkl(p)
    result = Runner().run(p)
    assert result.files_scanned == 1
    assert not result.has_at_least(Severity.CRITICAL)


def test_run_single_evil_file(tmp_path: Path):
    p = tmp_path / "evil.pkl"
    _make_evil_pkl(p)
    result = Runner().run(p)
    assert result.has_at_least(Severity.CRITICAL)
    assert result.files_scanned == 1


def test_run_directory_recursion(tmp_path: Path):
    sub = tmp_path / "models" / "v1"
    sub.mkdir(parents=True)
    _make_clean_pkl(sub / "good.pkl")
    _make_evil_pkl(sub / "bad.pkl")
    result = Runner().run(tmp_path)
    assert result.files_scanned == 2
    assert result.has_at_least(Severity.CRITICAL)


def test_ignore_dirs(tmp_path: Path):
    # .git/ должна игнорироваться
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    _make_evil_pkl(git_dir / "evil.pkl")
    result = Runner().run(tmp_path)
    # Не должны были даже увидеть файл
    assert result.files_scanned == 0
    assert not result.has_at_least(Severity.CRITICAL)


def test_summary_counts(tmp_path: Path):
    _make_evil_pkl(tmp_path / "a.pkl")
    _make_evil_pkl(tmp_path / "b.pkl")
    _make_clean_pkl(tmp_path / "c.pkl")
    result = Runner().run(tmp_path)
    counts = result.summary_counts()
    assert counts["critical"] >= 2


def test_nonexistent_path():
    r = Runner()
    result = r.run(Path("/nonexistent/path/that/should/not/exist"))
    assert result.errors
    assert result.files_scanned == 0
