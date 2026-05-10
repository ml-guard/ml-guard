"""Форматтеры вывода для ScanResult."""
from ml_guard.output.text import format_text
from ml_guard.output.json_fmt import format_json
from ml_guard.output.sarif import format_sarif

FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}

__all__ = ["FORMATTERS", "format_text", "format_json", "format_sarif"]
