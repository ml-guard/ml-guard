"""Finding data model — what every scanner returns."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any
import hashlib


class Severity(str, Enum):
    """Severity levels. Ordering matters — used by `order()` for comparison."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def order(cls, value: "Severity") -> int:
        """Numeric rank for comparison. Higher = more severe."""
        return {
            cls.INFO: 0,
            cls.LOW: 1,
            cls.MEDIUM: 2,
            cls.HIGH: 3,
            cls.CRITICAL: 4,
        }[value]

    def at_least(self, threshold: "Severity") -> bool:
        """True if this severity is >= the given threshold."""
        return Severity.order(self) >= Severity.order(threshold)


@dataclass
class Finding:
    """
    A single finding emitted by a scanner. Shape is designed for
    straightforward conversion to SARIF, CycloneDX, and JSON output.
    """
    rule_id: str                     # stable rule identifier, e.g. "pickle-dangerous-opcode"
    severity: Severity
    message: str                     # human-readable description
    file: str                        # path relative to the scan root
    location: str = ""               # "offset 0x2a1", "line 12", "tensor 'weight'"
    snippet: str = ""                # up to ~100 bytes of evidence (hex or text)
    scanner: str = ""                # which scanner produced this finding
    metadata: Dict[str, Any] = field(default_factory=dict)  # extra payload for SBOM/SARIF

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @property
    def fingerprint(self) -> str:
        """
        Stable identifier used for SARIF baselines and duplicate suppression.
        Excludes `snippet` so trivial file edits don't break the fingerprint.
        """
        key = f"{self.rule_id}|{self.file}|{self.location}|{self.message}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
