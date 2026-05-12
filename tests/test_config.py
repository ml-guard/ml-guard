"""Tests for the .ml-guard.yml config loader."""
from __future__ import annotations

import os
from pathlib import Path

from ml_guard.config import Config, RuleOverride, load_config
from ml_guard.findings import Finding, Severity


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------

def test_load_missing_returns_empty(tmp_path: Path):
    """No config, no env, no autodiscovery — empty Config."""
    cfg = load_config(scan_root=tmp_path)
    assert cfg.fail_on is None
    assert cfg.include == []
    assert cfg.exclude == []
    assert cfg.scanners == []
    assert cfg.rules == {}
    assert cfg.source_path is None


def test_load_explicit_path(tmp_path: Path):
    p = tmp_path / "my-config.yml"
    p.write_text("fail_on: high\nscanners: [pickle]\n")
    cfg = load_config(explicit_path=p)
    assert cfg.fail_on == Severity.HIGH
    assert cfg.scanners == ["pickle"]
    assert cfg.source_path == p


def test_load_explicit_missing_raises(tmp_path: Path):
    """If the user explicitly points to a missing path → error."""
    try:
        load_config(explicit_path=tmp_path / "nope.yml")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_autodiscover_in_scan_root(tmp_path: Path):
    (tmp_path / ".ml-guard.yml").write_text("fail_on: medium\n")
    cfg = load_config(scan_root=tmp_path)
    assert cfg.fail_on == Severity.MEDIUM


def test_autodiscover_walks_up(tmp_path: Path):
    """A config at the monorepo root is picked up from a subdirectory."""
    (tmp_path / ".ml-guard.yaml").write_text("fail_on: low\n")
    sub = tmp_path / "models" / "v2"
    sub.mkdir(parents=True)
    cfg = load_config(scan_root=sub)
    assert cfg.fail_on == Severity.LOW


def test_env_override(tmp_path: Path, monkeypatch=None):
    """$ML_GUARD_CONFIG takes precedence over autodiscovery."""
    p = tmp_path / "env-config.yml"
    p.write_text("fail_on: critical\n")
    other_root = tmp_path / "project"
    other_root.mkdir()
    (other_root / ".ml-guard.yml").write_text("fail_on: low\n")
    old = os.environ.get("ML_GUARD_CONFIG")
    os.environ["ML_GUARD_CONFIG"] = str(p)
    try:
        cfg = load_config(scan_root=other_root)
        assert cfg.fail_on == Severity.CRITICAL
    finally:
        if old is None:
            del os.environ["ML_GUARD_CONFIG"]
        else:
            os.environ["ML_GUARD_CONFIG"] = old


def test_invalid_yaml_returns_empty(tmp_path: Path):
    p = tmp_path / "bad.yml"
    p.write_text("this is: : : not yaml ::: [\n")
    cfg = load_config(explicit_path=p)
    # Should not crash; returns empty Config
    assert cfg.fail_on is None


def test_invalid_severity_in_yaml_ignored(tmp_path: Path):
    p = tmp_path / "c.yml"
    p.write_text("fail_on: super-bad\n")
    cfg = load_config(explicit_path=p)
    assert cfg.fail_on is None


def test_rules_section_parsed(tmp_path: Path):
    p = tmp_path / "c.yml"
    p.write_text(
        "rules:\n"
        "  pickle-unusual-module:\n"
        "    severity: low\n"
        "  pickle-deprecated-opcode:\n"
        "    disabled: true\n"
    )
    cfg = load_config(explicit_path=p)
    assert cfg.rules["pickle-unusual-module"].severity == Severity.LOW
    assert cfg.rules["pickle-deprecated-opcode"].disabled is True


def test_top_level_must_be_mapping(tmp_path: Path):
    p = tmp_path / "c.yml"
    p.write_text("- just\n- a list\n")
    cfg = load_config(explicit_path=p)
    assert cfg.fail_on is None  # ignored


# ---------------------------------------------------------------------------
# apply_rule_override
# ---------------------------------------------------------------------------

def test_override_disables_finding():
    cfg = Config()
    cfg.rules["x-rule"] = RuleOverride(disabled=True)
    f = Finding(rule_id="x-rule", severity=Severity.CRITICAL, message="m", file="f")
    assert cfg.apply_rule_override(f) is None


def test_override_lowers_severity():
    cfg = Config()
    cfg.rules["x-rule"] = RuleOverride(severity=Severity.LOW)
    f = Finding(rule_id="x-rule", severity=Severity.CRITICAL, message="m", file="f")
    out = cfg.apply_rule_override(f)
    assert out is f
    assert f.severity == Severity.LOW


def test_override_unknown_rule_passthrough():
    cfg = Config()
    f = Finding(rule_id="not-overridden", severity=Severity.HIGH, message="m", file="f")
    assert cfg.apply_rule_override(f) is f
    assert f.severity == Severity.HIGH
