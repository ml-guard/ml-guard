"""Минимальный PDF 1.4 writer для compliance-отчётов.

Зачем своё, а не reportlab/fpdf:
  • Compliance-отчёт хочется уметь генерировать в air-gapped окружении.
  • Внешние PDF-библиотеки тащат сотни KB и имеют свою CVE-историю —
    плохая идея для security-инструмента.
  • Нам нужен ТОЛЬКО плоский текст: заголовки, абзацы, таблица findings.
    Это ~200 строк PDF-генератора.

Поддерживаемая структура PDF:
  1. Header: %PDF-1.4
  2. Объекты:
     • Catalog (root)
     • Pages — родитель страниц
     • Page[1..N] — страницы со ссылкой на ресурсы и контент
     • Font — встроенный Helvetica (Type1, base14 — не требует встраивания файла)
     • Contents[1..N] — потоки рисования (FlateDecode)
  3. xref-таблица с offset'ами объектов
  4. trailer + startxref + %%EOF

Шрифт: используем PDF base-14 (Helvetica/Helvetica-Bold). Они доступны в
любом PDF-viewer'е без встраивания. Это ограничивает символы Latin-1 —
для compliance-отчёта на английском этого достаточно. Юникод — TODO.

Формат символов в content stream:
  BT      = begin text
  /F1 12 Tf = font 1 (Helvetica), size 12
  72 720 Td = move cursor to x=72, y=720 (PDF origin = bottom-left)
  (Hello) Tj = show text "Hello"
  ET      = end text

Координатная сетка: точки PDF (1pt = 1/72"), letter = 612x792.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import List, Sequence


# Letter в точках PDF (8.5"x11")
PAGE_WIDTH = 612
PAGE_HEIGHT = 792

# Поля
MARGIN_LEFT = 54
MARGIN_RIGHT = 54
MARGIN_TOP = 60
MARGIN_BOTTOM = 60

# Шрифты base-14
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"

# Шрифт-метрики Helvetica (приблизительные, для line-wrap).
# Используем half-em-width = 0.5 * size в среднем; для прецизионности
# можно подключить таблицу AFM, но для compliance-PDF это излишне.
def _approx_text_width(text: str, font: str, size: float) -> float:
    """Приближённая ширина строки в точках."""
    avg_em = 0.55 if "Bold" in font else 0.50
    if "Courier" in font:
        avg_em = 0.60     # моноширинный
    return len(text) * avg_em * size


# ---------------------------------------------------------------------------
# Высокоуровневое API: PdfDocument
# ---------------------------------------------------------------------------

@dataclass
class _TextRun:
    """Одна команда отрисовки текста в content stream."""
    x: float
    y: float
    text: str
    font: str
    size: float
    color: tuple = (0.0, 0.0, 0.0)   # RGB 0..1


@dataclass
class _Page:
    runs: List[_TextRun] = field(default_factory=list)


class PdfDocument:
    """Сборщик многостраничного PDF.

    API:
        doc = PdfDocument(title="...", author="ML Guard")
        doc.heading("Compliance Report", size=24)
        doc.paragraph("This document attests that...")
        doc.table([[...], [...]])
        doc.save("report.pdf")

    Внутри ведём курсор `_y` сверху вниз по текущей странице. Когда место
    кончается — автоматически добавляем новую страницу.
    """

    def __init__(self, title: str = "", author: str = "ml-guard") -> None:
        self.title = title
        self.author = author
        self._pages: List[_Page] = []
        self._cur: _Page = self._new_page()
        self._y: float = PAGE_HEIGHT - MARGIN_TOP

    # -------------------- управление страницами --------------------

    def _new_page(self) -> _Page:
        page = _Page()
        self._pages.append(page)
        return page

    def _ensure_space(self, needed: float) -> None:
        if self._y - needed < MARGIN_BOTTOM:
            self._cur = self._new_page()
            self._y = PAGE_HEIGHT - MARGIN_TOP

    # -------------------- высокоуровневые блоки --------------------

    def heading(self, text: str, size: int = 18, gap_below: float = 14.0) -> None:
        self._ensure_space(size + gap_below)
        self._cur.runs.append(_TextRun(
            x=MARGIN_LEFT,
            y=self._y,
            text=_pdf_escape(text),
            font=FONT_BOLD,
            size=size,
        ))
        self._y -= size + gap_below

    def paragraph(self, text: str, size: int = 11, leading: float = 1.4,
                  gap_below: float = 8.0, font: str = FONT_REGULAR) -> None:
        line_h = size * leading
        max_width = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
        for para in text.split("\n"):
            for line in _wrap_line(para, max_width, font, size):
                self._ensure_space(line_h)
                self._cur.runs.append(_TextRun(
                    x=MARGIN_LEFT,
                    y=self._y,
                    text=_pdf_escape(line),
                    font=font,
                    size=size,
                ))
                self._y -= line_h
        self._y -= gap_below

    def keyvalue_block(self, pairs: Sequence[tuple], size: int = 10,
                       leading: float = 1.5, gap_below: float = 10.0) -> None:
        """Печатает пары "ключ: значение" моноширинно — удобно для метаданных."""
        line_h = size * leading
        # Выравниваем по самому длинному ключу
        key_width = max(len(k) for k, _ in pairs) if pairs else 0
        for k, v in pairs:
            self._ensure_space(line_h)
            line = f"{k.ljust(key_width)}  {v}"
            self._cur.runs.append(_TextRun(
                x=MARGIN_LEFT,
                y=self._y,
                text=_pdf_escape(line),
                font=FONT_MONO,
                size=size,
            ))
            self._y -= line_h
        self._y -= gap_below

    def divider(self, gap_above: float = 4.0, gap_below: float = 4.0) -> None:
        """Тонкая горизонтальная линия (точнее, ряд '-' нужной длины)."""
        line_h = 12
        self._ensure_space(line_h + gap_above + gap_below)
        self._y -= gap_above
        # рисуем "—" символами через моноширинный шрифт
        approx_chars = (PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT) // (0.6 * 9)
        self._cur.runs.append(_TextRun(
            x=MARGIN_LEFT,
            y=self._y,
            text="-" * int(approx_chars),
            font=FONT_MONO,
            size=9,
            color=(0.6, 0.6, 0.6),
        ))
        self._y -= line_h + gap_below

    def bullet(self, text: str, size: int = 11, indent: float = 18.0,
               gap_below: float = 4.0) -> None:
        line_h = size * 1.4
        max_width = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT - indent
        wrapped = _wrap_line(text, max_width, FONT_REGULAR, size)
        for i, line in enumerate(wrapped):
            self._ensure_space(line_h)
            if i == 0:
                # WinAnsiEncoding не содержит '•' (U+2022); используем
                # bullet-glyph 0x95 в WinAnsi — но безопаснее обычный '*'.
                self._cur.runs.append(_TextRun(
                    x=MARGIN_LEFT,
                    y=self._y,
                    text="*",
                    font=FONT_REGULAR,
                    size=size,
                ))
            self._cur.runs.append(_TextRun(
                x=MARGIN_LEFT + indent,
                y=self._y,
                text=_pdf_escape(line),
                font=FONT_REGULAR,
                size=size,
            ))
            self._y -= line_h
        self._y -= gap_below

    # -------------------- сериализация --------------------

    def to_bytes(self) -> bytes:
        """Собираем готовый PDF."""
        return _serialize(self)


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

# Часто встречающиеся не-Latin1 символы → их Latin1 эквиваленты.
# Это позволяет нам не падать на тексте «по-человечески», но и не тащить
# полный шрифт-эмбеддинг для редких символов.
_LATIN1_FALLBACKS = {
    "—": "-",   # em-dash
    "–": "-",   # en-dash
    "•": "*",   # bullet (мы используем литералы внутри bullet(), но не везде)
    "…": "...",
    """: '"',
    """: '"',
    "'": "'",
    "'": "'",
    "→": "->",
    "≥": ">=",
    "≤": "<=",
    "×": "x",
    "©": "(c)",
    "®": "(R)",
    "™": "(TM)",
}


def _pdf_escape(s: str) -> str:
    """Экранируем спецсимволы в литерале строки PDF: \\, (, ).

    Также подставляем Latin-1-эквиваленты для частых не-Latin1 символов,
    чтобы базовые шрифты Helvetica/Courier (с WinAnsiEncoding) могли их
    отобразить без замены на '?'.
    """
    out = []
    for ch in s:
        if ch in _LATIN1_FALLBACKS:
            ch = _LATIN1_FALLBACKS[ch]
            # после подстановки ch может быть многосимвольным
            for c in ch:
                out.append(c if c not in ("\\", "(", ")") else "\\" + c)
            continue
        if ch in ("\\", "(", ")"):
            out.append("\\" + ch)
        elif ord(ch) < 32:
            out.append(" ")
        elif ord(ch) > 126:
            try:
                ch.encode("latin-1")
                out.append(ch)
            except UnicodeEncodeError:
                out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _wrap_line(line: str, max_width: float, font: str, size: float) -> List[str]:
    """Простой word-wrap по приблизительной ширине."""
    if not line.strip():
        return [""]
    words = line.split(" ")
    out: List[str] = []
    cur = ""
    for w in words:
        candidate = (cur + " " + w).strip() if cur else w
        if _approx_text_width(candidate, font, size) <= max_width:
            cur = candidate
        else:
            if cur:
                out.append(cur)
            # Если одно слово длиннее строки — режем.
            if _approx_text_width(w, font, size) > max_width:
                # очень длинная "строка" типа hash; режем по символам
                chunk = ""
                for ch in w:
                    if _approx_text_width(chunk + ch, font, size) > max_width:
                        out.append(chunk)
                        chunk = ch
                    else:
                        chunk += ch
                cur = chunk
            else:
                cur = w
    if cur:
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# Низкоуровневая сериализация в PDF wire-format
# ---------------------------------------------------------------------------

def _serialize(doc: PdfDocument) -> bytes:
    """
    Строит PDF из объектов в порядке:
      1. Catalog
      2. Pages (родитель)
      3. Font /F1 (Helvetica)
      4. Font /F2 (Helvetica-Bold)
      5. Font /F3 (Courier)
      6..: Page + Contents для каждой страницы (попарно)
    """
    # Собираем body как список (object_number, raw_bytes).
    objects: List[bytes] = []

    def add(obj_bytes: bytes) -> int:
        """Возвращает индекс объекта (1-based)."""
        objects.append(obj_bytes)
        return len(objects)

    # 1. Catalog (placeholder, отредактируем после Pages)
    catalog_idx = add(b"")  # placeholder

    # 2. Pages (placeholder)
    pages_idx = add(b"")

    # 3..5. Шрифты
    f1_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    f2_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    f3_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

    # 6.. Страницы
    page_obj_indices: List[int] = []

    for page in doc._pages:
        # contents
        stream = _render_page_contents(page)
        compressed = zlib.compress(stream)
        contents_obj = (
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\n"
            f"stream\n"
        ).encode("latin-1") + compressed + b"\nendstream"
        contents_idx = add(contents_obj)

        # page
        page_obj = (
            f"<< /Type /Page /Parent {pages_idx} 0 R "
            f"/MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << "
            f"/F1 {f1_idx} 0 R "
            f"/F2 {f2_idx} 0 R "
            f"/F3 {f3_idx} 0 R "
            f">> >> "
            f"/Contents {contents_idx} 0 R >>"
        ).encode("latin-1")
        page_idx = add(page_obj)
        page_obj_indices.append(page_idx)

    # Заполняем Pages и Catalog
    kids_str = " ".join(f"{i} 0 R" for i in page_obj_indices)
    objects[pages_idx - 1] = (
        f"<< /Type /Pages /Count {len(page_obj_indices)} /Kids [{kids_str}] >>"
    ).encode("latin-1")
    objects[catalog_idx - 1] = (
        f"<< /Type /Catalog /Pages {pages_idx} 0 R >>"
    ).encode("latin-1")

    # Info-объект (метаданные PDF)
    title = _pdf_escape(doc.title or "")
    author = _pdf_escape(doc.author or "")
    info_obj = f"<< /Title ({title}) /Author ({author}) /Producer (ml-guard) >>".encode("latin-1")
    info_idx = add(info_obj)

    # ---------- Финальная сборка ----------
    out = bytearray()
    out += b"%PDF-1.4\n"
    out += b"%\xe2\xe3\xcf\xd3\n"  # binary marker — указывает viewer'ам что файл не текст

    offsets = [0]  # offsets[0] не используется (object 0 — free)
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode("latin-1")
        out += body
        out += b"\nendobj\n"

    xref_offset = len(out)
    n = len(objects) + 1
    out += f"xref\n0 {n}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode("latin-1")

    out += b"trailer\n"
    out += (
        f"<< /Size {n} /Root {catalog_idx} 0 R /Info {info_idx} 0 R >>\n"
    ).encode("latin-1")
    out += b"startxref\n"
    out += f"{xref_offset}\n".encode("latin-1")
    out += b"%%EOF\n"
    return bytes(out)


def _render_page_contents(page: _Page) -> bytes:
    """Собираем content stream одной страницы."""
    out: List[bytes] = []
    cur_color = None
    for run in page.runs:
        # Цвет (rg = non-stroke RGB)
        if cur_color != run.color:
            r, g, b = run.color
            out.append(f"{r:.3f} {g:.3f} {b:.3f} rg".encode("latin-1"))
            cur_color = run.color

        font_alias = {
            FONT_REGULAR: "/F1",
            FONT_BOLD:    "/F2",
            FONT_MONO:    "/F3",
        }.get(run.font, "/F1")

        text_bytes = _encode_pdf_string(run.text)
        out.append(b"BT")
        out.append(f"{font_alias} {run.size} Tf".encode("latin-1"))
        out.append(f"{run.x} {run.y} Td".encode("latin-1"))
        out.append(b"(" + text_bytes + b") Tj")
        out.append(b"ET")
    return b"\n".join(out) + b"\n"


def _encode_pdf_string(s: str) -> bytes:
    """Кодируем строку для литерала (...) в PDF: latin-1 + escape."""
    try:
        return s.encode("latin-1")
    except UnicodeEncodeError:
        # Заменяем не-Latin1 символы
        return s.encode("latin-1", errors="replace")
