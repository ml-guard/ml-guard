"""Load ml-guard configuration from a YAML file.

Convention: ml-guard searches the first existing file from:
  • --config argument
  • $ML_GUARD_CONFIG
  • .ml-guard.yml / .ml-guard.yaml at the scan root
  • pyproject.toml at the scan root ([tool.ml-guard] section)

CLI options always win — the config provides defaults for the command.

Configuration schema (all fields optional):

    # .ml-guard.yml
    fail_on: high              # severity threshold for non-zero exit
    include:
      - 'models/*.pkl'
      - 'configs/*.yaml'
    exclude:
      - 'tests/fixtures/**'
    scanners:
      - pickle
      - secrets
    max_file_size_mb: 4096
    rules:
      pickle-unusual-module:
        severity: low          # downgrade the rule's severity
      pickle-deprecated-opcode:
        disabled: true         # disable the rule entirely
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ml_guard.findings import Severity

log = logging.getLogger(__name__)


# Filenames we look up the config in by convention
_AUTO_CONFIG_NAMES = (".ml-guard.yml", ".ml-guard.yaml")


@dataclass
class RuleOverride:
    """Per-rule behavior override."""
    severity: Optional[Severity] = None    # change severity level
    disabled: bool = False                 # disable entirely


@dataclass
class Config:
    """Decoded configuration. All fields optional, all may be None."""
    fail_on: Optional[Severity] = None
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)
    max_file_size_mb: Optional[int] = None
    rules: Dict[str, RuleOverride] = field(default_factory=dict)
    # Where the config was read from — useful for --verbose
    source_path: Optional[Path] = None

    # ------------------------------------------------------------------
    @classmethod
    def empty(cls) -> "Config":
        return cls()

    def apply_rule_override(self, finding) -> Optional[object]:
        """
        If there's an override for finding.rule_id, apply it.
        Returns None if the rule is disabled (finding should be dropped),
        otherwise returns the (possibly modified) finding.
        """
        ov = self.rules.get(finding.rule_id)
        if ov is None:
            return finding
        if ov.disabled:
            return None
        if ov.severity is not None:
            finding.severity = ov.severity
        return finding


# ----------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------

def load_config(
    explicit_path: Optional[Path] = None,
    scan_root: Optional[Path] = None,
) -> Config:
    """
    Strategy:
      1. If explicit_path is given — read exactly that, error otherwise.
      2. If $ML_GUARD_CONFIG is set — read that.
      3. If scan_root is given — look for .ml-guard.yml/.yaml there.
      4. Otherwise return an empty Config.
    """
    path: Optional[Path] = None

    if explicit_path is not None:
        if not explicit_path.exists():
            raise FileNotFoundError(f"Config file not found: {explicit_path}")
        path = explicit_path
    elif os.environ.get("ML_GUARD_CONFIG"):
        env_path = Path(os.environ["ML_GUARD_CONFIG"])
        if env_path.exists():
            path = env_path
    elif scan_root is not None:
        # Search scan_root and up to 3 parents upward (for monorepos)
        candidates: List[Path] = []
        cur = scan_root if scan_root.is_dir() else scan_root.parent
        for _ in range(4):
            for name in _AUTO_CONFIG_NAMES:
                candidates.append(cur / name)
            cur = cur.parent
            if cur == cur.parent:  # reached the root
                break
        for cand in candidates:
            if cand.is_file():
                path = cand
                break

    if path is None:
        return Config.empty()

    return _parse_yaml(path)


def _parse_yaml(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("Cannot read config %s: %s", path, e)
        return Config.empty()

    try:
        raw: Any = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        log.warning("Invalid YAML in %s: %s", path, e)
        return Config.empty()

    if not isinstance(raw, dict):
        log.warning("Config %s must be a mapping at top level; ignoring", path)
        return Config.empty()

    cfg = Config(source_path=path)

    if "fail_on" in raw:
        try:
            cfg.fail_on = Severity(str(raw["fail_on"]).lower())
        except ValueError:
            log.warning("Invalid fail_on in %s: %r", path, raw["fail_on"])

    for key, target in (("include", cfg.include), ("exclude", cfg.exclude),
                        ("scanners", cfg.scanners)):
        val = raw.get(key)
        if isinstance(val, list):
            target.extend(str(v) for v in val)
        elif val is not None:
            log.warning("Config %s: %s must be a list", path, key)

    if "max_file_size_mb" in raw:
        try:
            cfg.max_file_size_mb = int(raw["max_file_size_mb"])
        except (ValueError, TypeError):
            log.warning("Invalid max_file_size_mb in %s", path)

    rules = raw.get("rules", {})
    if isinstance(rules, dict):
        for rule_id, body in rules.items():
            if not isinstance(body, dict):
                continue
            ov = RuleOverride()
            if "disabled" in body:
                ov.disabled = bool(body["disabled"])
            if "severity" in body:
                try:
                    ov.severity = Severity(str(body["severity"]).lower())
                except ValueError:
                    log.warning("Invalid severity for rule %s", rule_id)
            cfg.rules[str(rule_id)] = ov

    return cfg
