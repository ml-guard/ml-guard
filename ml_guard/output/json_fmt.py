"""JSON formatter for machine consumption."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ml_guard.runner import ScanResult


def format_json(result: "ScanResult") -> str:
    """Serialize ScanResult to stable JSON."""
    payload = {
        "tool": "ml-guard",
        "version": "0.1.0",
        "files_scanned": result.files_scanned,
        "scanners_invoked": result.scanners_invoked,
        "duration_seconds": round(result.duration_seconds, 4),
        "summary": result.summary_counts(),
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
