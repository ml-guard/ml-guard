"""Text formatter — human-readable console output."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ml_guard.findings import Severity

if TYPE_CHECKING:
    from ml_guard.runner import ScanResult


_SEVERITY_ICONS = {
    Severity.CRITICAL: "✗",
    Severity.HIGH:     "!",
    Severity.MEDIUM:   "•",
    Severity.LOW:      "·",
    Severity.INFO:     "i",
}

# ANSI colors. Minimal fallback — if the terminal doesn't support
# them, the output will be ugly but still readable.
_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH:     "\033[31m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[36m",
    Severity.INFO:     "\033[37m",
}
_RESET = "\033[0m"


def format_text(result: "ScanResult", use_color: bool = True) -> str:
    """Return a string with the colored/plain human-readable report."""
    lines = []
    lines.append("ML Guard — scan report")
    lines.append("=" * 40)
    counts = result.summary_counts()
    lines.append(
        f"Files scanned: {result.files_scanned}    "
        f"Time: {result.duration_seconds:.2f}s"
    )
    summary_bits = []
    for sev in Severity:
        n = counts.get(sev.value, 0)
        if n:
            summary_bits.append(f"{n} {sev.value}")
    if summary_bits:
        lines.append("Summary:       " + ", ".join(summary_bits))
    else:
        lines.append("Summary:       no findings — all clear")
    lines.append("")

    # Sort by severity, then by file
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (-Severity.order(f.severity), f.file, f.location),
    )
    for f in sorted_findings:
        icon = _SEVERITY_ICONS.get(f.severity, "?")
        color = _SEVERITY_COLORS.get(f.severity, "") if use_color else ""
        reset = _RESET if use_color else ""
        sev_label = f.severity.value.upper().ljust(8)
        loc = f"  [{f.location}]" if f.location else ""
        lines.append(f"{color}{icon} {sev_label}{reset} {f.file}{loc}")
        lines.append(f"           {f.message}")
        if f.snippet:
            lines.append(f"           snippet: {f.snippet[:120]}")
        lines.append(f"           rule: {f.rule_id}  scanner: {f.scanner}")
        lines.append("")

    if result.errors:
        lines.append("Errors during scanning:")
        for e in result.errors:
            lines.append(f"  ! {e}")

    return "\n".join(lines)
