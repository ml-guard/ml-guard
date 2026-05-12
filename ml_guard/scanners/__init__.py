"""Scanner base interface and its registry.

Each scanner declares which files it can handle and returns a list of
Findings. The registry picks the applicable scanners for a given file
via can_scan().
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Iterable, Type
import logging

from ml_guard.findings import Finding

log = logging.getLogger(__name__)


class Scanner(ABC):
    """Base interface for scanners."""

    name: str = "base"               # unique scanner name, lands in Finding.scanner
    description: str = ""

    @abstractmethod
    def can_scan(self, path: Path) -> bool:
        """Does this scanner apply to this file / directory?"""
        raise NotImplementedError

    @abstractmethod
    def scan(self, path: Path) -> List[Finding]:
        """Run the scan. Must catch its own exceptions and return them
        as Finding(severity=INFO/LOW) (see _wrap_error)."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    def _stamp(self, finding: Finding, path: Path, root: Path) -> Finding:
        """Fill bookkeeping fields (file, scanner) before yielding outward."""
        try:
            finding.file = str(path.relative_to(root))
        except ValueError:
            finding.file = str(path)
        finding.scanner = self.name
        return finding


class ScannerRegistry:
    """Registry of registered scanners.

    Scanners register globally via the @register decorator or an explicit
    .register() call. The runner takes the registry and, for each file,
    picks every scanner where .can_scan(path) == True.
    """

    def __init__(self) -> None:
        self._scanners: List[Scanner] = []

    def register(self, scanner: Scanner) -> Scanner:
        log.debug("Registering scanner: %s", scanner.name)
        self._scanners.append(scanner)
        return scanner

    def unregister_all(self) -> None:
        """Handy in tests."""
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


# Default global registry. The CLI uses this.
default_registry = ScannerRegistry()


def register(scanner_cls: Type[Scanner]) -> Type[Scanner]:
    """Class decorator: instantiate the scanner and register it."""
    default_registry.register(scanner_cls())
    return scanner_cls
