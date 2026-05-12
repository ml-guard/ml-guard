"""Minimal PDF 1.4 writer for compliance reports.

Why our own, not reportlab/fpdf:
  • We want to generate compliance reports in air-gapped environments.
  • External PDF libs pull in hundreds of KB and have their own CVE
    history — a bad fit for a security tool.
  • We only need flat text: headings, paragraphs, a findings table.
    That's ~200 lines of PDF generator code.

Supported PDF structure:
  1. Header: %PDF-1.4
  2. Objects:
     • Catalog (root)
     • Pages — root of pages
     • Page[1..N] — pages linking resources and content
     • Font — built-in Helvetica (Type1, base14 — no embedding required)
     • Contents[1..N] — drawing streams (FlateDecode)
  3. xref table with object offsets
  4. trailer + startxref + %%EOF

Fonts: PDF base-14 (Helvetica/Helvetica-Bold). Available in every viewer
without embedding. Restricts us to Latin-1 — fine for an English-language
compliance report. Unicode support is TODO.

Character format in content streams:
  BT      = begin text
  /F1 12 Tf = font 1 (Helvetica), size 12
  72 720 Td = move cursor to x=72, y=720 (PDF origin = bottom-left)
  (Hello) Tj = show text "Hello"
  ET      = end text

Coordinate grid: PDF points (1pt = 1/72"), letter = 612x792.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from typing import List, Sequence


# Letter size in PDF points (8.5"x11")
PAGE_WIDTH = 612
PAGE_HEIGHT = 792

# Margins
MARGIN_LEFT = 54
MARGIN_RIGHT = 54
MARGIN_TOP = 60
MARGIN_BOTTOM = 60

# Base-14 fonts
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"

# Helvetica font metrics (approximate, for line-wrap).
# Using half-em-width = 0.5 * size on average; for precision you could
# wire up the AFM table, but that's overkill for a compliance PDF.
def _approx_text_width(text: str, font: str, size: float) -> float:
    """Approximate string width in points."""
    avg_em = 0.55 if "Bold" in font else 0.50
    if "Courier" in font:
        avg_em = 0.60     # monospace
    return len(text) * avg_em * size


# ---------------------------------------------------------------------------
# High-level API: PdfDocument
# ---------------------------------------------------------------------------

@dataclass
class _TextRun:
    """A single text-drawing command in a content stream."""
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
    """Multi-page PDF builder.

    API:
        doc = PdfDocument(title="...", author="ML Guard")
        doc.heading("Compliance Report", size=24)
        doc.paragraph("This document attests that...")
        doc.table([[...], [...]])
        doc.save("report.pdf")

    We track a `_y` cursor top-down on the current page. When space runs
    out, a new page is added automatically.
    """

    def __init__(self, title: str = "", author: str = "ml-guard") -> None:
        self.title = title
        self.author = author
        self._pages: List[_Page] = []
        self._cur: _Page = self._new_page()
        self._y: float = PAGE_HEIGHT - MARGIN_TOP

    # -------------------- page management --------------------

    def _new_page(self) -> _Page:
        page = _Page()
        self._pages.append(page)
        return page

    def _ensure_space(self, needed: float) -> None:
        if self._y - needed < MARGIN_BOTTOM:
            self._cur = self._new_page()
            self._y = PAGE_HEIGHT - MARGIN_TOP

    # -------------------- high-level blocks --------------------

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
        """Print "key: value" pairs in monospace — handy for metadata."""
        line_h = size * leading
        # Align to the longest key
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
        """A thin horizontal rule (technically a row of '-' chars)."""
        line_h = 12
        self._ensure_space(line_h + gap_above + gap_below)
        self._y -= gap_above
        # draw "—" chars using a monospace font
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
                # WinAnsiEncoding doesn't have '•' (U+2022); we could use
                # bullet glyph 0x95 in WinAnsi — but plain '*' is safer.
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

    # -------------------- serialization --------------------

    def to_bytes(self) -> bytes:
        """Assemble the final PDF."""
        return _serialize(self)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

# Common non-Latin1 chars → their Latin1 equivalents.
# Lets us handle "normal" text gracefully without dragging in a full
# font-embedding stack for rare characters.
_LATIN1_FALLBACKS = {
    "—": "-",   # em-dash
    "–": "-",   # en-dash
    "•": "*",   # bullet (we use literals inside bullet(), but not everywhere)
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
    """Escape special chars in a PDF string literal: \\, (, ).

    Also substitute Latin-1 equivalents for common non-Latin1 chars so the
    base Helvetica/Courier fonts (with WinAnsiEncoding) can render them
    without falling back to '?'.
    """
    out = []
    for ch in s:
        if ch in _LATIN1_FALLBACKS:
            ch = _LATIN1_FALLBACKS[ch]
            # after substitution ch may be multi-char
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
    """Simple word-wrap by approximate width."""
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
            # If a single word is longer than the line — split it.
            if _approx_text_width(w, font, size) > max_width:
                # very long "word" like a hash; chunk character-wise
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
# Low-level serialization into PDF wire format
# ---------------------------------------------------------------------------

def _serialize(doc: PdfDocument) -> bytes:
    """
    Builds the PDF objects in this order:
      1. Catalog
      2. Pages (root)
      3. Font /F1 (Helvetica)
      4. Font /F2 (Helvetica-Bold)
      5. Font /F3 (Courier)
      6..: Page + Contents for each page (in pairs)
    """
    # Collect body as a list of (object_number, raw_bytes).
    objects: List[bytes] = []

    def add(obj_bytes: bytes) -> int:
        """Return the object's 1-based index."""
        objects.append(obj_bytes)
        return len(objects)

    # 1. Catalog (placeholder; fixed up after we know Pages)
    catalog_idx = add(b"")  # placeholder

    # 2. Pages (placeholder)
    pages_idx = add(b"")

    # 3..5. Fonts
    f1_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    f2_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    f3_idx = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

    # 6.. Pages
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

    # Fill in Pages and Catalog
    kids_str = " ".join(f"{i} 0 R" for i in page_obj_indices)
    objects[pages_idx - 1] = (
        f"<< /Type /Pages /Count {len(page_obj_indices)} /Kids [{kids_str}] >>"
    ).encode("latin-1")
    objects[catalog_idx - 1] = (
        f"<< /Type /Catalog /Pages {pages_idx} 0 R >>"
    ).encode("latin-1")

    # Info object (PDF metadata)
    title = _pdf_escape(doc.title or "")
    author = _pdf_escape(doc.author or "")
    info_obj = f"<< /Title ({title}) /Author ({author}) /Producer (ml-guard) >>".encode("latin-1")
    info_idx = add(info_obj)

    # ---------- Final assembly ----------
    out = bytearray()
    out += b"%PDF-1.4\n"
    out += b"%\xe2\xe3\xcf\xd3\n"  # binary marker — signals viewers the file is not text

    offsets = [0]  # offsets[0] is unused (object 0 is "free")
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
    """Build a single page's content stream."""
    out: List[bytes] = []
    cur_color = None
    for run in page.runs:
        # Color (rg = non-stroke RGB)
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
    """Encode a string for a PDF (...) literal: latin-1 + escape."""
    try:
        return s.encode("latin-1")
    except UnicodeEncodeError:
        # Replace non-Latin1 characters
        return s.encode("latin-1", errors="replace")
