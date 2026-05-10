"""Secret scanner — поиск утечек ключей и токенов в текстовых артефактах.

Стратегия — двухслойная:
  1. **Точные регексы** для известных провайдеров. Низкие false-positive,
     высокий impact (AWS, GitHub, Slack, Stripe, OpenAI, ...).
  2. **Энтропийный фильтр** для generic-секретов: ищем длинные base64/hex
     строки с высокой энтропией Шеннона рядом с словом-маркером ("password",
     "secret", "token", "key", "auth"). Это ловит самописные API-ключи,
     которые не подпадают под p.1.

Поддерживаемые форматы:
  • `.env`, `.env.*`
  • `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini`, `.conf`
  • `.py` (исходники с захардкоженными ключами)
  • `.ipynb` (Jupyter — распаковываем `cell.source` и `outputs`)
  • `Dockerfile`, `docker-compose.yml` обрабатываются по расширению/имени

Все findings содержат файл и номер строки. Для финдинга через регекс мы
выводим тип провайдера; для энтропийного — слово-маркер и хвост строки
(но НЕ сам секрет целиком — только первые/последние 4 символа, чтобы
финдинг был разбираемым человеком, но не «пересолил» лог).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Pattern, Tuple

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register


# ---------------------------------------------------------------------------
# 1. Регексы известных провайдеров
# ---------------------------------------------------------------------------
# Поля каждого правила:
#   id       — стабильный rule_id для finding'а
#   severity — наш уровень
#   label    — человекочитаемое название
#   pattern  — скомпилированный re.Pattern, должен иметь группу 0 = весь матч.
#              Используем (?:...) внутри, чтобы группа 0 = весь секрет.
#
# Важно: предпочитаем строгие паттерны со специфичными префиксами и точными
# длинами; так false-positive почти нулевой.

@dataclass(frozen=True)
class _Rule:
    id: str
    severity: Severity
    label: str
    pattern: Pattern[str]


_RULES: Tuple[_Rule, ...] = (
    # --- AWS ---
    _Rule(
        id="secret-aws-access-key",
        severity=Severity.CRITICAL,
        label="AWS Access Key ID",
        # AKIA... (long-lived) или ASIA... (session). 20 chars total, uppercase+digits.
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    _Rule(
        id="secret-aws-secret-near-key",
        severity=Severity.CRITICAL,
        label="AWS Secret Access Key (near-context match)",
        # Срабатывает только когда явно подписано как "aws_secret_access_key"
        pattern=re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"
        ),
    ),
    # --- GitHub ---
    _Rule(
        id="secret-github-pat",
        severity=Severity.CRITICAL,
        label="GitHub Personal Access Token",
        # Префиксы введены в 2021: ghp_/gho_/ghu_/ghs_/ghr_, длина 36+ после префикса.
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    _Rule(
        id="secret-github-fine-grained-pat",
        severity=Severity.CRITICAL,
        label="GitHub fine-grained PAT",
        pattern=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    # --- Slack ---
    _Rule(
        id="secret-slack-token",
        severity=Severity.HIGH,
        label="Slack token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    _Rule(
        id="secret-slack-webhook",
        severity=Severity.HIGH,
        label="Slack webhook URL",
        pattern=re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ),
    # --- Stripe ---
    _Rule(
        id="secret-stripe-live",
        severity=Severity.CRITICAL,
        label="Stripe live secret key",
        pattern=re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    ),
    _Rule(
        id="secret-stripe-test",
        severity=Severity.MEDIUM,
        label="Stripe test secret key",
        pattern=re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),
    ),
    # --- OpenAI / Anthropic ---
    _Rule(
        id="secret-openai-key",
        severity=Severity.HIGH,
        label="OpenAI API key",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"),
    ),
    _Rule(
        id="secret-anthropic-key",
        severity=Severity.HIGH,
        label="Anthropic API key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    ),
    # --- Hugging Face ---
    _Rule(
        id="secret-huggingface-token",
        severity=Severity.HIGH,
        label="Hugging Face token",
        pattern=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    ),
    # --- Google ---
    _Rule(
        id="secret-google-api-key",
        severity=Severity.HIGH,
        label="Google API key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    # --- Generic JWT ---
    _Rule(
        id="secret-jwt",
        severity=Severity.MEDIUM,
        label="JSON Web Token",
        # eyJ — base64-prefix '{"' (JWT header). Три сегмента через точку.
        pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    # --- Private keys ---
    _Rule(
        id="secret-private-key",
        severity=Severity.CRITICAL,
        label="Private cryptographic key",
        # PEM headers: RSA, OPENSSH, EC, DSA, PGP
        pattern=re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----"
        ),
    ),
)


# ---------------------------------------------------------------------------
# 2. Энтропийный поиск
# ---------------------------------------------------------------------------

# Маркеры, рядом с которыми длинная высокоэнтропийная строка скорее всего
# секрет. Регистронезависимо.
_SECRET_MARKERS = (
    "password", "passwd", "pwd",
    "secret", "token", "auth",
    "apikey", "api_key", "api-key",
    "credentials", "private_key",
    "session_key", "access_key",
)

# key=val или key: val синтаксис в .env/.yaml/.json/.ini.
# Ключ ловим достаточно жадно (любой alnum/_/-), значение — кавычки или до конца строки.
_KV_RE = re.compile(
    r"(?P<key>[A-Za-z][A-Za-z0-9_\-\.]*)\s*[:=]\s*"
    r"(?P<quote>['\"]?)(?P<val>[^'\"\s,;{}\[\]]+)(?P=quote)"
)

# Минимальная длина строки для энтропийного анализа (короткие пароли всё равно
# плохо ловятся энтропией — для них нужны словарные правила).
_MIN_ENTROPY_LEN = 20

# Порог Шеннона: эмпирически 4.0 для base64-like ключей.
# Для строгого base64 теоретический максимум ~6 бит/символ; реальные ключи 4.5–5.5.
# Для hex — максимум 4.0; ставим порог 3.5 для hex-режима ниже.
_BASE64_ENTROPY_THRESHOLD = 4.0
_HEX_ENTROPY_THRESHOLD = 3.5

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_\-=]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _shannon_entropy(s: str) -> float:
    """Бит на символ. 0 для одинаковых букв, ~6 для случайного base64."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _looks_like_secret_value(val: str) -> Optional[str]:
    """
    Проверяет, выглядит ли значение как секрет по форме и энтропии.
    Возвращает кратное описание (для finding.message) или None.
    """
    if len(val) < _MIN_ENTROPY_LEN:
        return None
    # Hex: 32+ символа hex с энтропией ≥ 3.5
    if _HEX_RE.match(val) and len(val) >= 32:
        if _shannon_entropy(val) >= _HEX_ENTROPY_THRESHOLD:
            return f"high-entropy hex string (len={len(val)})"
    # Base64-like
    if _BASE64_RE.match(val):
        if _shannon_entropy(val) >= _BASE64_ENTROPY_THRESHOLD:
            return f"high-entropy base64-like string (len={len(val)})"
    return None


def _is_secret_marker_key(key: str) -> bool:
    k = key.lower()
    return any(m in k for m in _SECRET_MARKERS)


# Очень быстрая (substring) проверка: нужно ли вообще запускать regex над
# строкой. Если в lowercase-варианте строки нет ни одного маркер-слова,
# энтропийный путь точно ничего не найдёт, и `_KV_RE.finditer` можно
# пропустить. Дешевле любой regex.
def _line_has_marker(line: str) -> bool:
    low = line.lower()
    for m in _SECRET_MARKERS:
        if m in low:
            return True
    return False


# ---------------------------------------------------------------------------
# Антипаттерны (заведомо НЕ секреты)
# ---------------------------------------------------------------------------

# Очевидные плейсхолдеры в примерах кода/конфигов; их не репортим, чтобы
# не раздражать пользователя.
#
# Подход: совпадение — целое слово (\b...\b), а не подстрока. Это важно:
# реальный high-entropy ключ может случайно содержать "1234567" или "example"
# как подстроку. Сигнал: PLACEHOLDER явно стоит как самостоятельное слово
# или весь секрет составлен из повторений.
_PLACEHOLDER_TOKENS_RE = re.compile(
    r"(?ix)\b(?:"
    r"  example | placeholder | redacted |"
    r"  your[_\-]?(?:secret|key|token|password) |"
    r"  fake | dummy | sample | replace[_\-]?me |"
    r"  changeme | todo | xxx+ | foobar"
    r")\b"
)

# Строки вроде "AAAAAAAA" или "xxxxxx" — заведомо не секреты.
_REPEATING_RE = re.compile(r"^(.)\1{7,}$")

# Канонический пример AWS из доков AWS — буквальная строка, всегда плейсхолдер.
# AWS использует именно этот ID во всех своих примерах последние 15 лет.
_AWS_DOC_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
}

# UUID — высокая энтропия по форме hex, но это идентификатор, не секрет.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _is_obviously_placeholder(val: str) -> bool:
    if val in _AWS_DOC_EXAMPLES:
        return True
    if _UUID_RE.match(val):
        return True
    if _REPEATING_RE.match(val):
        return True
    if _PLACEHOLDER_TOKENS_RE.search(val):
        return True
    return False


# ---------------------------------------------------------------------------
# Извлечение текста по типу файла
# ---------------------------------------------------------------------------

# Расширения, которые сканер берёт в работу.
_TEXT_EXTENSIONS = {
    ".env",
    ".yaml", ".yml",
    ".json",
    ".toml",
    ".cfg", ".ini", ".conf", ".config",
    ".py",
    ".sh", ".bash",
    ".tf", ".tfvars",       # Terraform
}

# Имена файлов без расширения, которые мы тоже сканируем.
_TEXT_BASENAMES = {
    "Dockerfile",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.local", ".env.production", ".env.development",
}


def _iter_lines_for_path(path: Path) -> Iterable[Tuple[int, str, str]]:
    """
    Возвращает кортежи (line_no, source_label, line_text).

    Для .ipynb распаковывает ячейки и проходит по их `source`. line_no — номер
    внутри cell'а; source_label — "cell N source" или "cell N output[k]".
    Для остальных файлов source_label="" и line_no обычный.
    """
    if path.suffix.lower() == ".ipynb":
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            nb = json.loads(text)
        except (OSError, json.JSONDecodeError):
            return
        cells = nb.get("cells", [])
        if not isinstance(cells, list):
            return
        for ci, cell in enumerate(cells):
            if not isinstance(cell, dict):
                continue
            src = cell.get("source", [])
            if isinstance(src, list):
                joined = "".join(str(p) for p in src)
            elif isinstance(src, str):
                joined = src
            else:
                continue
            for li, line in enumerate(joined.splitlines(), start=1):
                yield li, f"cell {ci} source", line
            outs = cell.get("outputs", [])
            if isinstance(outs, list):
                for oi, out in enumerate(outs):
                    if not isinstance(out, dict):
                        continue
                    text_out = out.get("text") or out.get("data", {}).get("text/plain")
                    if isinstance(text_out, list):
                        text_out = "".join(str(p) for p in text_out)
                    if isinstance(text_out, str):
                        for li, line in enumerate(text_out.splitlines(), start=1):
                            yield li, f"cell {ci} output[{oi}]", line
        return

    # Обычный текстовый файл.
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for li, line in enumerate(f, start=1):
                yield li, "", line.rstrip("\n")
    except OSError:
        return


# ---------------------------------------------------------------------------
# Сканер
# ---------------------------------------------------------------------------

@register
class SecretScanner(Scanner):
    name = "secrets"
    description = "Detects hard-coded API keys, tokens, and high-entropy secrets in source/configs"

    # Лимит на строку — чтобы регексы не подвешивали процесс на однобайтовых
    # строках длиной в мегабайты (ipynb с base64-картинкой и т.п.).
    MAX_LINE_LEN = 16 * 1024

    # Лимит на файл, выше — пропускаем.
    MAX_FILE_BYTES = 32 * 1024 * 1024

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() == ".ipynb":
            return True
        if path.suffix.lower() in _TEXT_EXTENSIONS:
            return True
        if path.name in _TEXT_BASENAMES:
            return True
        return False

    def scan(self, path: Path) -> List[Finding]:
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size > self.MAX_FILE_BYTES:
            return [Finding(
                rule_id="secrets-file-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({size} bytes); skipped",
                file=str(path), scanner=self.name,
            )]

        findings: List[Finding] = []
        # Дедуп: одинаковая (rule_id, секрет-сниппет) на файл — один раз.
        seen: set[Tuple[str, str]] = set()

        for line_no, src_label, line in _iter_lines_for_path(path):
            if not line:
                continue
            if len(line) > self.MAX_LINE_LEN:
                # Большие base64-блобы (картинки в ipynb) — режем
                line = line[: self.MAX_LINE_LEN]

            self._scan_line(line, line_no, src_label, findings, seen)

        return findings

    # ------------------------------------------------------------------
    def _scan_line(
        self,
        line: str,
        line_no: int,
        src_label: str,
        findings: List[Finding],
        seen: set,
    ) -> None:
        # Сюда складываем все секреты, найденные регексами на этой строке —
        # потом не будем дублировать их через энтропию.
        regex_hit_values: set[str] = set()

        # 1) Регексы
        for rule in _RULES:
            for m in rule.pattern.finditer(line):
                # Group 1, если есть; иначе вся группа 0.
                secret = m.group(1) if rule.pattern.groups >= 1 and m.lastindex else m.group(0)
                if _is_obviously_placeholder(secret):
                    continue
                key = (rule.id, secret)
                if key in seen:
                    continue
                seen.add(key)
                regex_hit_values.add(secret)

                # Маскируем секрет: первые/последние 4 символа.
                redacted = self._redact(secret)
                location = self._fmt_location(line_no, src_label)
                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=f"{rule.label} detected",
                    file="", scanner=self.name,
                    location=location,
                    snippet=redacted,
                ))

        # 2) Энтропия рядом с маркер-ключом
        # Быстрый pre-check: если в строке нет ни одного маркер-слова, не
        # тратим время на запуск _KV_RE.finditer (это в 10x ускоряет
        # сканирование больших исходников без секретов).
        if not _line_has_marker(line):
            return

        for m in _KV_RE.finditer(line):
            key = m.group("key")
            val = m.group("val")
            if val in regex_hit_values:
                # Уже нашли точным правилом — энтропия будет дублем
                continue
            if not _is_secret_marker_key(key):
                continue
            if _is_obviously_placeholder(val):
                continue
            descr = _looks_like_secret_value(val)
            if descr is None:
                continue
            dup_key = ("secret-high-entropy", val)
            if dup_key in seen:
                continue
            seen.add(dup_key)

            redacted = self._redact(val)
            location = self._fmt_location(line_no, src_label)
            findings.append(Finding(
                rule_id="secret-high-entropy",
                severity=Severity.MEDIUM,
                message=f"Possible secret near key '{key}': {descr}",
                file="", scanner=self.name,
                location=location,
                snippet=f"{key}={redacted}",
            ))

    @staticmethod
    def _redact(s: str) -> str:
        if len(s) <= 8:
            return "*" * len(s)
        return f"{s[:4]}…{s[-4:]} (len={len(s)})"

    @staticmethod
    def _fmt_location(line_no: int, src_label: str) -> str:
        if src_label:
            return f"{src_label}, line {line_no}"
        return f"line {line_no}"
