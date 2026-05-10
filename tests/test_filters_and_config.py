"""Тесты новых возможностей Runner: include/exclude/selected_scanners + интеграция с конфигом."""
from __future__ import annotations

import pickle
from pathlib import Path

from ml_guard.config import Config, RuleOverride
from ml_guard.findings import Severity
from ml_guard.runner import Runner

import ml_guard.scanners.pickle_scanner  # регистрирует pickle scanner  # noqa: F401


class _Mal:
    def __reduce__(self):
        import os
        return (os.system, ("echo x",))


def _evil(p: Path) -> Path:
    with p.open("wb") as f:
        pickle.dump(_Mal(), f)
    return p


def _clean(p: Path) -> Path:
    with p.open("wb") as f:
        pickle.dump({"a": 1}, f)
    return p


# ---------------------------------------------------------------------------
# include / exclude
# ---------------------------------------------------------------------------

def test_exclude_pattern_skips_file(tmp_path: Path):
    (tmp_path / "models").mkdir()
    (tmp_path / "scratch").mkdir()
    _evil(tmp_path / "models" / "ok.pkl")
    _evil(tmp_path / "scratch" / "skipped.pkl")

    r = Runner(exclude_patterns=["scratch/*"])
    res = r.run(tmp_path)
    assert res.files_scanned == 1
    assert all("scratch" not in f.file for f in res.findings)


def test_include_pattern_limits_scope(tmp_path: Path):
    (tmp_path / "a.pkl").write_bytes(pickle.dumps(_Mal()))
    (tmp_path / "b.pkl").write_bytes(pickle.dumps(_Mal()))
    (tmp_path / "c.pkl").write_bytes(pickle.dumps(_Mal()))

    r = Runner(include_patterns=["a.pkl"])
    res = r.run(tmp_path)
    assert res.files_scanned == 1
    assert any("a.pkl" in f.file for f in res.findings)


def test_exclude_takes_priority_over_include(tmp_path: Path):
    """Если файл совпадает и с include и с exclude — исключаем."""
    (tmp_path / "a.pkl").write_bytes(pickle.dumps(_Mal()))
    r = Runner(include_patterns=["*.pkl"], exclude_patterns=["a.pkl"])
    res = r.run(tmp_path)
    assert res.files_scanned == 0


def test_glob_matches_basename_too(tmp_path: Path):
    """`--exclude '*.pkl'` без префикса директории — должно совпадать."""
    sub = tmp_path / "deep" / "nested"
    sub.mkdir(parents=True)
    _evil(sub / "x.pkl")
    r = Runner(exclude_patterns=["*.pkl"])
    res = r.run(tmp_path)
    assert res.files_scanned == 0


# ---------------------------------------------------------------------------
# selected_scanners
# ---------------------------------------------------------------------------

def test_selected_scanners_unknown_name_yields_nothing(tmp_path: Path):
    _evil(tmp_path / "x.pkl")
    r = Runner(selected_scanners=["nonexistent"])
    res = r.run(tmp_path)
    # Файл существует, но ни один сканер не выбран — files_scanned=0
    assert res.files_scanned == 0
    assert res.findings == []


def test_selected_scanners_pickle_works(tmp_path: Path):
    _evil(tmp_path / "x.pkl")
    r = Runner(selected_scanners=["pickle"])
    res = r.run(tmp_path)
    assert res.has_at_least(Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Интеграция с конфигом
# ---------------------------------------------------------------------------

def test_config_provides_default_excludes(tmp_path: Path):
    cfg = Config(exclude=["scratch/*"])
    (tmp_path / "scratch").mkdir()
    _evil(tmp_path / "scratch" / "x.pkl")
    _evil(tmp_path / "y.pkl")
    r = Runner(config=cfg)
    res = r.run(tmp_path)
    assert res.files_scanned == 1


def test_cli_args_merge_with_config(tmp_path: Path):
    """Явные exclude_patterns + config.exclude → объединяются (не перезаписываются)."""
    cfg = Config(exclude=["scratch/*"])
    (tmp_path / "scratch").mkdir()
    (tmp_path / "tmp").mkdir()
    _evil(tmp_path / "scratch" / "a.pkl")
    _evil(tmp_path / "tmp" / "b.pkl")
    _evil(tmp_path / "c.pkl")
    r = Runner(exclude_patterns=["tmp/*"], config=cfg)
    res = r.run(tmp_path)
    assert res.files_scanned == 1  # только c.pkl


def test_config_rule_override_disables(tmp_path: Path):
    """Rule override из конфига должен отбросить finding до агрегации."""
    cfg = Config(rules={
        "pickle-dangerous-global": RuleOverride(disabled=True),
    })
    _evil(tmp_path / "x.pkl")
    r = Runner(config=cfg)
    res = r.run(tmp_path)
    # Само правило отключено — критикалов быть не должно (но другие правила могут сработать)
    assert not any(f.rule_id == "pickle-dangerous-global" for f in res.findings)


def test_config_rule_override_severity(tmp_path: Path):
    """Rule override меняет severity без отбрасывания."""
    cfg = Config(rules={
        "pickle-dangerous-global": RuleOverride(severity=Severity.LOW),
    })
    _evil(tmp_path / "x.pkl")
    r = Runner(config=cfg)
    res = r.run(tmp_path)
    dg = [f for f in res.findings if f.rule_id == "pickle-dangerous-global"]
    assert dg
    assert all(f.severity == Severity.LOW for f in dg)


def test_config_max_file_size_mb(tmp_path: Path):
    """max_file_size_mb из конфига применяется как дефолт."""
    big = tmp_path / "huge.pkl"
    # 1 MiB файла, но при лимите 0 MiB в конфиге он отбрасывается
    big.write_bytes(b"\x80\x04N." * 200_000)
    cfg = Config(max_file_size_mb=0)
    r = Runner(config=cfg)
    res = r.run(tmp_path)
    assert res.files_scanned == 0


def test_config_scanners_whitelist(tmp_path: Path):
    cfg = Config(scanners=["pickle"])
    _evil(tmp_path / "x.pkl")
    r = Runner(config=cfg)
    res = r.run(tmp_path)
    assert res.has_at_least(Severity.CRITICAL)
