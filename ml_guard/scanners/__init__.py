"""Базовая абстракция Scanner и его реестр.

Каждый сканер заявляет, какие файлы он умеет обрабатывать,
и возвращает список Finding. Реестр выбирает подходящие сканеры
для каждого файла на основе can_scan().
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Iterable, Type
import logging

from ml_guard.findings import Finding

log = logging.getLogger(__name__)


class Scanner(ABC):
    """Базовый интерфейс сканера."""

    name: str = "base"               # уникальное имя сканера, попадает в Finding.scanner
    description: str = ""

    @abstractmethod
    def can_scan(self, path: Path) -> bool:
        """Применим ли этот сканер к данному файлу/директории?"""
        raise NotImplementedError

    @abstractmethod
    def scan(self, path: Path) -> List[Finding]:
        """Запустить сканирование. Должен ловить свои исключения и
        возвращать их как Finding с severity=INFO/LOW (см. _wrap_error)."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    def _stamp(self, finding: Finding, path: Path, root: Path) -> Finding:
        """Заполнить служебные поля (file, scanner) перед отдачей наружу."""
        try:
            finding.file = str(path.relative_to(root))
        except ValueError:
            finding.file = str(path)
        finding.scanner = self.name
        return finding


class ScannerRegistry:
    """Реестр зарегистрированных сканеров.

    Сканеры регистрируются глобально через @register декоратор или
    явный вызов .register(). Раннер берёт реестр и для каждого файла
    выбирает все .can_scan(path) == True сканеры.
    """

    def __init__(self) -> None:
        self._scanners: List[Scanner] = []

    def register(self, scanner: Scanner) -> Scanner:
        log.debug("Registering scanner: %s", scanner.name)
        self._scanners.append(scanner)
        return scanner

    def unregister_all(self) -> None:
        """Полезно в тестах."""
        self._scanners.clear()

    def applicable(self, path: Path) -> Iterable[Scanner]:
        for s in self._scanners:
            try:
                if s.can_scan(path):
                    yield s
            except Exception as e:  # noqa: BLE001
                log.warning("Scanner %s.can_scan failed on %s: %s", s.name, path, e)

    def all(self) -> List[Scanner]:
        return list(self._scanners)


# Глобальный реестр по умолчанию. CLI его использует.
default_registry = ScannerRegistry()


def register(scanner_cls: Type[Scanner]) -> Type[Scanner]:
    """Декоратор для класса сканера: создаёт экземпляр и регистрирует."""
    default_registry.register(scanner_cls())
    return scanner_cls
