"""Pickle scanner — обнаружение вредоносного кода в pickle-файлах.

Атака на pickle (CWE-502, "Insecure Deserialization") работает так:
протокол pickle — это стек-машина с опкодами. Опкод REDUCE
вызывает callable (взятый из стека) с аргументами (тоже со стека).
GLOBAL/STACK_GLOBAL загружают callable по имени модуля и атрибута.

Поэтому достаточно увидеть пару (GLOBAL "os" "system", REDUCE) —
и при torch.load() выполнится `os.system(...)`. Никакого ML.

Наш сканер НЕ ВЫПОЛНЯЕТ pickle. Мы только парсим опкоды и
проверяем, какие глобалы загружаются. Это безопасно по построению.

Стратегия:
  1. pickletools.genops() даёт поток (opcode, arg, position) — это часть
     stdlib, вылизана годами, не имеет surface для атак.
  2. Отслеживаем стек GLOBAL'ов: если REDUCE/BUILD/INST вызывает
     известно-опасный callable — Finding с severity по таблице.
  3. Не-известно-опасные модули, не относящиеся к ML, повышают severity.
"""
from __future__ import annotations

import io
import pickletools
import struct
import zipfile
from pathlib import Path
from typing import List, Optional, Set, Tuple

from ml_guard.findings import Finding, Severity
from ml_guard.scanners import Scanner, register

# --------------------------------------------------------------------------
# Базы знаний: что мы считаем опасным
# --------------------------------------------------------------------------

# Эти callable'ы при вызове через REDUCE дают RCE — сразу critical.
# Формат: (module, qualname). Имя модуля — в pickle-нотации.
_RCE_CALLABLES: Set[Tuple[str, str]] = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "spawnl"),
    ("os", "spawnv"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("commands", "getoutput"),       # Python 2, всё ещё встречается
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("__builtin__", "eval"),         # Python 2 имя
    ("__builtin__", "exec"),
    ("__builtin__", "compile"),
    ("__builtin__", "__import__"),
    ("importlib", "import_module"),
    ("runpy", "run_path"),
    ("runpy", "_run_code"),
    ("pty", "spawn"),
    ("platform", "popen"),
    ("ctypes", "CDLL"),              # загрузка нативной библиотеки — RCE
    ("ctypes", "WinDLL"),
    ("ctypes", "OleDLL"),
    ("ctypes", "PyDLL"),
}

# Подозрительные модули — даже без RCE намекают на эксфильтрацию/networking.
# Тензору они не нужны.
_SUSPICIOUS_MODULES: Set[str] = {
    "socket",
    "urllib",
    "urllib2",
    "urllib.request",
    "http",
    "http.client",
    "httplib",
    "requests",
    "ftplib",
    "telnetlib",
    "smtplib",
    "shutil",          # rmtree, copy
    "tempfile",
    "webbrowser",
    "marshal",         # ещё одна сериализация-через-исполнение
    "code",            # interactive interpreter
    "codeop",
    "subprocess",      # уже в RCE, но сами импорты тоже отметим
    "pickle",          # рекурсивный pickle.loads — тревога
    "pickletools",
    "_pickle",
}

# Модули, типичные для ML-весов — их мы не считаем подозрительными.
# (Сами они безопасны, опасны только конкретные callable из них —
# но в ML-pickle мы их вообще не ожидаем как RCE-вектор.)
_BENIGN_ML_MODULES: Set[str] = {
    "torch",
    "torch._utils",
    "torch.nn",
    "torch.nn.modules",
    "torch.nn.parameter",
    "torch.storage",
    "torch._tensor",
    "torch.serialization",
    "numpy",
    "numpy.core.multiarray",
    "numpy._core.multiarray",
    "numpy.core.numeric",
    "numpy.dtypes",
    "collections",
    "collections.abc",
    "_codecs",
}

# Опкоды, которые сами по себе подозрительны (Python 2 наследие)
_DEPRECATED_OPCODES: Set[str] = {"INST", "OBJ"}  # старые способы инстанцирования


# --------------------------------------------------------------------------
# Утилиты определения формата
# --------------------------------------------------------------------------

_PICKLE_MAGIC_BYTES = (
    b"\x80",      # PROTO opcode (proto >=2)
    b"(",         # MARK
    b"]",         # EMPTY_LIST
    b"}",         # EMPTY_DICT
    b"c",         # GLOBAL (proto 0)
)

_TORCH_ZIP_MEMBERS = ("data.pkl", "archive/data.pkl")  # PyTorch >=1.6 ZIP


def _looks_like_pickle(path: Path) -> bool:
    """Проверка: это похоже на pickle? Используется когда нет нужного расширения."""
    try:
        with path.open("rb") as f:
            head = f.read(2)
        return len(head) > 0 and head[:1] in _PICKLE_MAGIC_BYTES
    except OSError:
        return False


def _is_torch_zip(path: Path) -> bool:
    """PyTorch 1.6+ сохраняет .pt/.pth/.bin как ZIP с data.pkl внутри."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            return any(n.endswith("data.pkl") for n in names)
    except (zipfile.BadZipFile, OSError):
        return False


# --------------------------------------------------------------------------
# Ядро анализатора
# --------------------------------------------------------------------------

class _PickleAnalyzer:
    """
    Стримово проходим по опкодам и накапливаем findings.

    Особенности pickle protocol >=4 (Python 3.8+ default):
      Загрузка `os.system` кодируется так:
          SHORT_BINUNICODE "os"
          SHORT_BINUNICODE "system"
          STACK_GLOBAL                       <-- module/name берутся со стека
      Поэтому одного просмотра опкодов недостаточно — нужно эмулировать
      стек строк, чтобы при STACK_GLOBAL восстановить пару (module, qualname).

    Эмуляция максимально упрощена: на стеке нас интересуют только строки
    (UNICODE-варианты и SHORT_BINSTRING), а структурные опкоды (MARK, POP)
    мы трактируем как «положили заглушку». Этого достаточно для
    поиска RCE-вызовов; нам не нужно реконструировать тензоры.
    """

    def __init__(self, source_label: str) -> None:
        self.source_label = source_label
        self._findings: List[Finding] = []
        self._last_global: Optional[Tuple[str, str]] = None
        self._seen_modules: Set[str] = set()
        self._global_count = 0
        # Очень упрощённый стек: только строки (для STACK_GLOBAL).
        # Не-строки кладём как None (placeholder).
        self._stack: List[Optional[str]] = []
        # Уже зарепортированные пары (module, qualname) — чтобы не дублировать
        self._reported_pairs: Set[Tuple[str, str]] = set()

    # ----- helpers ---------------------------------------------------------
    def _add(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        pos: Optional[int],
        snippet: str = "",
    ) -> None:
        self._findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file="",  # заполнит сканер
                location=f"offset 0x{pos:x}" if pos is not None else "",
                snippet=snippet,
                metadata={"source": self.source_label},
            )
        )

    # ----- per-opcode handlers --------------------------------------------
    def _on_global(self, module: str, qualname: str, pos: Optional[int]) -> None:
        self._last_global = (module, qualname)
        self._seen_modules.add(module)
        self._global_count += 1

        # Дедуп: если та же пара уже репортилась — выходим.
        if (module, qualname) in self._reported_pairs:
            return

        # Очевидно опасный callable — critical, даже без REDUCE
        # (REDUCE может последовать дальше; даже сам импорт RCE-функции
        # в pickle — серьёзный red flag).
        if (module, qualname) in _RCE_CALLABLES:
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-dangerous-global",
                severity=Severity.CRITICAL,
                message=f"Dangerous global imported: {module}.{qualname} "
                        f"(known RCE primitive)",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )
            return

        # Подозрительный модуль (networking, shutil, etc.) — high
        if module in _SUSPICIOUS_MODULES or any(
            module.startswith(m + ".") for m in _SUSPICIOUS_MODULES
        ):
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-suspicious-module",
                severity=Severity.HIGH,
                message=f"Suspicious module imported: {module}.{qualname} "
                        f"(not expected in ML weights)",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )
            return

        # Не-ML модуль — medium (heads-up)
        # Берём топ-уровень модуля для проверки.
        top = module.split(".")[0]
        if top not in {m.split(".")[0] for m in _BENIGN_ML_MODULES}:
            self._reported_pairs.add((module, qualname))
            self._add(
                rule_id="pickle-unusual-module",
                severity=Severity.MEDIUM,
                message=f"Unusual module for ML weights: {module}.{qualname}",
                pos=pos,
                snippet=f"{module}.{qualname}",
            )

    def _on_reduce(self, pos: Optional[int]) -> None:
        # REDUCE = вызов последнего callable с аргументами со стека.
        # Если последний global был опасным, это уже зафиксировано как critical.
        # Здесь ничего не добавляем, чтобы не дублировать.
        pass

    def _on_deprecated(self, opcode_name: str, pos: Optional[int]) -> None:
        self._add(
            rule_id="pickle-deprecated-opcode",
            severity=Severity.LOW,
            message=f"Deprecated/uncommon opcode {opcode_name} encountered "
                    f"(Python 2 era; review carefully)",
            pos=pos,
        )

    # ----- main loop -------------------------------------------------------
    # Опкоды, которые кладут строку на стек.
    _STRING_PUSH_OPS = {
        "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
        "SHORT_BINSTRING", "BINSTRING", "STRING",
        "SHORT_BINBYTES", "BINBYTES", "BINBYTES8",  # bytes тоже могут нести имя модуля
    }
    # Опкоды, которые кладут не-строковое значение — мы кладём None как placeholder.
    _NONSTRING_PUSH_OPS = {
        "NONE", "NEWTRUE", "NEWFALSE",
        "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT",
        "FLOAT", "BINFLOAT",
        "EMPTY_DICT", "EMPTY_LIST", "EMPTY_SET", "EMPTY_TUPLE",
        "MARK",
    }

    def analyze(self, data: bytes) -> List[Finding]:
        """Прогоняем pickletools.genops по байтам. Не выполняем ничего."""
        try:
            stream = io.BytesIO(data)
            for op, arg, pos in pickletools.genops(stream):
                name = op.name

                # ----- эмуляция стека (только для отслеживания строк) -----
                if name in self._STRING_PUSH_OPS:
                    # arg — строка или bytes; нормализуем к str
                    s: Optional[str]
                    if isinstance(arg, bytes):
                        try:
                            s = arg.decode("utf-8", errors="replace")
                        except Exception:  # noqa: BLE001
                            s = None
                    elif isinstance(arg, str):
                        s = arg
                    else:
                        s = None
                    self._stack.append(s)

                elif name in self._NONSTRING_PUSH_OPS:
                    self._stack.append(None)

                elif name in ("POP",):
                    if self._stack:
                        self._stack.pop()

                # ----- интересные опкоды ---------------------------------
                if name in ("GLOBAL", "INST"):
                    if isinstance(arg, str) and " " in arg:
                        module, _, qualname = arg.partition(" ")
                        self._on_global(module, qualname, pos)
                    if name == "INST":
                        self._on_deprecated(name, pos)

                elif name == "STACK_GLOBAL":
                    # Берём две верхушки стека: [module, qualname]
                    if len(self._stack) >= 2:
                        qualname = self._stack[-1]
                        module = self._stack[-2]
                        if module is not None and qualname is not None:
                            self._on_global(module, qualname, pos)
                        else:
                            # Не смогли восстановить — фиксируем сам факт STACK_GLOBAL
                            self._add(
                                rule_id="pickle-stack-global-opaque",
                                severity=Severity.MEDIUM,
                                message="STACK_GLOBAL with non-string operands "
                                        "(possibly obfuscated)",
                                pos=pos,
                            )
                    else:
                        self._add(
                            rule_id="pickle-stack-global-opaque",
                            severity=Severity.MEDIUM,
                            message="STACK_GLOBAL on empty stack (malformed pickle)",
                            pos=pos,
                        )
                    # Симулируем effect: pop 2, push 1 (callable, который мы трекаем как None)
                    if len(self._stack) >= 2:
                        self._stack.pop()
                        self._stack.pop()
                    self._stack.append(None)

                elif name == "REDUCE":
                    self._on_reduce(pos)
                    # effect: pop 2 (callable, args), push 1 result
                    for _ in range(2):
                        if self._stack:
                            self._stack.pop()
                    self._stack.append(None)

                elif name == "OBJ":
                    self._on_deprecated(name, pos)

        except Exception as e:  # noqa: BLE001
            # Битый pickle ИЛИ попытка обмануть парсер — тоже находка.
            self._add(
                rule_id="pickle-parse-error",
                severity=Severity.MEDIUM,
                message=f"Failed to parse pickle stream: {e}",
                pos=None,
            )

        return self._findings


# --------------------------------------------------------------------------
# Сам сканер (плагин для реестра)
# --------------------------------------------------------------------------

@register
class PickleScanner(Scanner):
    name = "pickle"
    description = "Detects malicious opcodes and dangerous globals in pickle files"

    # Расширения, которые точно содержат pickle (или могут — для torch zip).
    _EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"}

    # Лимиты — DoS-защита. Слишком большой файл — читаем не всё.
    MAX_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB
    MAX_INNER_PICKLE = 256 * 1024 * 1024  # 256 MiB на inner-pickle в ZIP

    def can_scan(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() in self._EXTENSIONS:
            return True
        # Без расширения — пробуем по магии
        if path.suffix == "" and _looks_like_pickle(path):
            return True
        return False

    def scan(self, path: Path) -> List[Finding]:
        if path.stat().st_size > self.MAX_BYTES:
            return [Finding(
                rule_id="pickle-too-large",
                severity=Severity.LOW,
                message=f"File too large to scan ({path.stat().st_size} bytes); skipped",
                file=str(path),
                scanner=self.name,
            )]

        # 1) PyTorch ZIP-формат — внутри data.pkl
        if zipfile.is_zipfile(path) and _is_torch_zip(path):
            return self._scan_torch_zip(path)

        # 2) Сырой pickle
        return self._scan_raw_pickle(path)

    # ------------------------------------------------------------------
    def _scan_raw_pickle(self, path: Path) -> List[Finding]:
        with path.open("rb") as f:
            data = f.read()
        return self._analyze_bytes(data, location_prefix=None)

    def _scan_torch_zip(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(path, "r") as zf:
                pkl_members = [n for n in zf.namelist() if n.endswith("data.pkl")]
                if not pkl_members:
                    return findings
                for member in pkl_members:
                    info = zf.getinfo(member)
                    if info.file_size > self.MAX_INNER_PICKLE:
                        findings.append(Finding(
                            rule_id="pickle-inner-too-large",
                            severity=Severity.LOW,
                            message=f"Inner pickle '{member}' too large; skipped",
                            file=str(path),
                            scanner=self.name,
                        ))
                        continue
                    with zf.open(member) as inner:
                        data = inner.read()
                    inner_findings = self._analyze_bytes(data, location_prefix=member)
                    findings.extend(inner_findings)
        except zipfile.BadZipFile as e:
            findings.append(Finding(
                rule_id="pickle-bad-zip",
                severity=Severity.MEDIUM,
                message=f"Corrupt PyTorch ZIP: {e}",
                file=str(path),
                scanner=self.name,
            ))
        return findings

    # ------------------------------------------------------------------
    def _analyze_bytes(self, data: bytes, location_prefix: Optional[str]) -> List[Finding]:
        """
        Единая точка анализа байтов pickle. Если доступен нативный движок —
        используем его; иначе — pure-Python `_PickleAnalyzer`.

        location_prefix: если задан (например, имя ZIP-члена), добавляется
        к каждому location.
        """
        if _HAS_RUST:
            try:
                raw = ml_guard_engine.scan_pickle_bytes(data)  # type: ignore[name-defined]
                findings: List[Finding] = []
                for d in raw:
                    sev = Severity(d["severity"])
                    loc = d.get("location", "")
                    if location_prefix:
                        loc = f"{location_prefix} @ {loc}" if loc else location_prefix
                    findings.append(Finding(
                        rule_id=d["rule_id"],
                        severity=sev,
                        message=d["message"],
                        file="",  # заполнит сканер
                        location=loc,
                        snippet=d.get("snippet", ""),
                    ))
                return findings
            except Exception:  # noqa: BLE001
                # Нативный путь не должен блокировать пользователя.
                # Падаем обратно на Python.
                pass

        analyzer = _PickleAnalyzer(source_label="<bytes>")
        findings = analyzer.analyze(data)
        if location_prefix:
            for f in findings:
                f.location = (
                    f"{location_prefix} @ {f.location}" if f.location else location_prefix
                )
        return findings


# --------------------------------------------------------------------------
# Опциональное Rust-ускорение
# --------------------------------------------------------------------------
# Если собран ml_guard_engine (Rust), мы можем использовать его для горячего
# пути на больших файлах. Чистый Python всегда работает; Rust — бонус.
try:
    import ml_guard_engine  # type: ignore[import-not-found]
    _HAS_RUST = hasattr(ml_guard_engine, "scan_pickle_bytes")
except ImportError:
    _HAS_RUST = False
