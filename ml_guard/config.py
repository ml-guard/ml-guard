"""Загрузка конфигурации ML Guard из YAML-файла.

Конвенция: ml-guard ищет первый существующий файл из:
  • аргумент --config
  • $ML_GUARD_CONFIG
  • .ml-guard.yml / .ml-guard.yaml в корне сканирования
  • pyproject.toml в корне сканирования (секция [tool.ml-guard])

Опции CLI всегда побеждают конфиг — конфиг задаёт дефолты для команды.

Схема конфигурации (все поля необязательны):

    # .ml-guard.yml
    fail_on: high              # severity для exit-кода
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
        severity: low          # понизить серьёзность правила
      pickle-deprecated-opcode:
        disabled: true         # отключить правило
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


# Имена файлов, в которых мы ищем конфиг автоматически
_AUTO_CONFIG_NAMES = (".ml-guard.yml", ".ml-guard.yaml")


@dataclass
class RuleOverride:
    """Переопределение поведения одного правила."""
    severity: Optional[Severity] = None    # сменить уровень
    disabled: bool = False                 # выключить полностью


@dataclass
class Config:
    """Декодированная конфигурация. Все поля необязательны и могут быть None."""
    fail_on: Optional[Severity] = None
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    scanners: List[str] = field(default_factory=list)
    max_file_size_mb: Optional[int] = None
    rules: Dict[str, RuleOverride] = field(default_factory=dict)
    # Откуда конфиг был прочитан — полезно в --verbose
    source_path: Optional[Path] = None

    # ------------------------------------------------------------------
    @classmethod
    def empty(cls) -> "Config":
        return cls()

    def apply_rule_override(self, finding) -> Optional[object]:
        """
        Если для finding.rule_id есть override, применяет его.
        Возвращает None если правило отключено (finding нужно отбросить),
        иначе возвращает finding (возможно изменённый).
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
# Загрузка
# ----------------------------------------------------------------------

def load_config(
    explicit_path: Optional[Path] = None,
    scan_root: Optional[Path] = None,
) -> Config:
    """
    Стратегия:
      1. Если задан explicit_path — читаем строго его, иначе ошибка.
      2. Если задан $ML_GUARD_CONFIG — читаем его.
      3. Если задан scan_root — ищем .ml-guard.yml/.yaml там.
      4. Иначе возвращаем пустой Config.
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
        # Ищем в scan_root и до 3 родителей вверх (на случай монорепо)
        candidates: List[Path] = []
        cur = scan_root if scan_root.is_dir() else scan_root.parent
        for _ in range(4):
            for name in _AUTO_CONFIG_NAMES:
                candidates.append(cur / name)
            cur = cur.parent
            if cur == cur.parent:  # достигли /
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
