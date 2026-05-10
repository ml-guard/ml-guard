"""Модель находок (findings) — то, что возвращают все сканеры."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any
import hashlib


class Severity(str, Enum):
    """Уровни серьёзности. Порядок важен — используется для сравнения через order()."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def order(cls, value: "Severity") -> int:
        """Числовой ранг для сравнения. Чем выше, тем серьёзнее."""
        return {
            cls.INFO: 0,
            cls.LOW: 1,
            cls.MEDIUM: 2,
            cls.HIGH: 3,
            cls.CRITICAL: 4,
        }[value]

    def at_least(self, threshold: "Severity") -> bool:
        """Это серьёзность >= порога?"""
        return Severity.order(self) >= Severity.order(threshold)


@dataclass
class Finding:
    """
    Одна находка от сканера. Структура спроектирована так, чтобы
    легко конвертироваться в SARIF, CycloneDX и JSON.
    """
    rule_id: str                     # стабильный ID правила, например "pickle-dangerous-opcode"
    severity: Severity
    message: str                     # человекочитаемое описание
    file: str                        # путь к файлу, относительно корня сканирования
    location: str = ""               # "offset 0x2a1", "line 12", "tensor 'weight'"
    snippet: str = ""                # до ~100 байт улик (hex или текст)
    scanner: str = ""                # какой сканер нашёл (pickle, safetensors, secrets, ...)
    metadata: Dict[str, Any] = field(default_factory=dict)  # доп. данные для SBOM/SARIF

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в JSON-совместимый dict."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @property
    def fingerprint(self) -> str:
        """
        Стабильный идентификатор — нужен для SARIF baseline и подавления повторов.
        Не включает snippet, чтобы небольшие изменения файла не ломали fingerprint.
        """
        key = f"{self.rule_id}|{self.file}|{self.location}|{self.message}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
