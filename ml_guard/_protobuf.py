"""Минимальный protobuf wire-format reader.

ONNX-файлы — это сериализованный protobuf (`onnx.ModelProto`). Мы не хотим
тащить полную библиотеку `onnx` или `protobuf` в security-сканер: парсер
*того же формата*, что и атакуемая система, — это плохая практика
(уязвимости парсера = уязвимости сканера). Поэтому читаем wire-format
напрямую, на нескольких сотнях строк.

Wire-format protobuf, краткий обзор:

  Каждое поле = (tag, value), где tag = (field_number << 3) | wire_type.
  Wire types:
    0  VARINT     — целые: int32/int64/bool/enum, ZigZag для signed
    1  FIXED64    — double, fixed64, sfixed64
    2  LENGTH     — string, bytes, embedded message, packed repeated
    5  FIXED32    — float, fixed32, sfixed32
    (3, 4 — устарели: groups)

Мы безопасно читаем varint'ы и length-delimited блоки с жёсткими
проверками границ; никаких рекурсивных аллокаций. Глубину вложенности
ограничиваем — это защита от protobuf-bomb (как в JSON, миллион вложенных
сообщений может съесть стек).

Подробности: https://protobuf.dev/programming-guides/encoding/
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple


# Жёсткие лимиты — protobuf-bomb защита.
MAX_DEPTH = 32
MAX_VARINT_BYTES = 10  # 64-битный varint не может быть длиннее


class ProtobufError(Exception):
    """Любая проблема при парсинге; включает offset и контекст."""


# ---------------------------------------------------------------------------
# Низкоуровневое чтение
# ---------------------------------------------------------------------------

class _Cursor:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, start: int = 0, end: Optional[int] = None) -> None:
        self.data = data
        self.pos = start
        self.end = end if end is not None else len(data)

    def remaining(self) -> int:
        return self.end - self.pos

    def read_varint(self) -> int:
        """Читает unsigned varint (до 10 байт)."""
        result = 0
        shift = 0
        bytes_read = 0
        while True:
            if self.pos >= self.end:
                raise ProtobufError(f"varint truncated at offset {self.pos}")
            if bytes_read >= MAX_VARINT_BYTES:
                raise ProtobufError(f"varint too long at offset {self.pos}")
            b = self.data[self.pos]
            self.pos += 1
            bytes_read += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7

    def read_n(self, n: int) -> bytes:
        if n < 0:
            raise ProtobufError(f"negative length {n} at offset {self.pos}")
        if self.remaining() < n:
            raise ProtobufError(
                f"length-delimited: declared {n} bytes, only {self.remaining()} left "
                f"at offset {self.pos}"
            )
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_fixed(self, n: int) -> bytes:
        return self.read_n(n)


def _decode_tag(tag: int) -> Tuple[int, int]:
    """Из tag-varint достаём (field_number, wire_type)."""
    return (tag >> 3, tag & 0x7)


# ---------------------------------------------------------------------------
# Высокоуровневое: parse_message → dict
# ---------------------------------------------------------------------------
#
# Мы возвращаем "сырой" дерево: для каждого поля список значений (т.к. proto
# поля могут повторяться). Значения — bytes, int, или вложенный dict.
# Интерпретация конкретного поля (что int это enum, что bytes это строка)
# делается в onnx_scanner.py по схеме ONNX.

def parse_message(data: bytes, depth: int = 0) -> Dict[int, List[Any]]:
    """
    Парсит весь буфер как одно сообщение и возвращает dict {field_no: [values...]}.

    Реализован "плоско" без _Cursor: для protobuf-парсера accessor-overhead
    в Python ощутимый — каждое чтение байта/varint'а становится 2-3
    method-call'ами, и на 10K узлов это десятки ms. Тут мы держим pos как
    локальную переменную и читаем напрямую из bytes-объекта; благодаря
    этому ONNX-сканер на 10K узлов ускорился ~2x.

    Корректность тождественна: те же лимиты глубины, те же ProtobufError'ы.
    """
    if depth > MAX_DEPTH:
        raise ProtobufError(f"protobuf nesting too deep (>{MAX_DEPTH})")

    out: Dict[int, List[Any]] = {}
    pos = 0
    end = len(data)

    while pos < end:
        # ---- inline read_varint для tag ----
        result = 0
        shift = 0
        bytes_read = 0
        while True:
            if pos >= end:
                raise ProtobufError(f"varint truncated at offset {pos}")
            if bytes_read >= MAX_VARINT_BYTES:
                raise ProtobufError(f"varint too long at offset {pos}")
            b = data[pos]
            pos += 1
            bytes_read += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        tag = result

        field_no = tag >> 3
        wire_type = tag & 0x7
        if field_no == 0:
            raise ProtobufError(f"invalid field_no=0 at offset {pos}")

        if wire_type == 0:    # VARINT
            # ---- inline ещё один varint ----
            result = 0
            shift = 0
            bytes_read = 0
            while True:
                if pos >= end:
                    raise ProtobufError(f"varint truncated at offset {pos}")
                if bytes_read >= MAX_VARINT_BYTES:
                    raise ProtobufError(f"varint too long at offset {pos}")
                b = data[pos]
                pos += 1
                bytes_read += 1
                result |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            v: Any = result
        elif wire_type == 1:  # FIXED64
            if end - pos < 8:
                raise ProtobufError(f"fixed64 truncated at offset {pos}")
            v = data[pos:pos + 8]
            pos += 8
        elif wire_type == 2:  # LENGTH-delimited
            # длина — varint
            result = 0
            shift = 0
            bytes_read = 0
            while True:
                if pos >= end:
                    raise ProtobufError(f"varint truncated at offset {pos}")
                if bytes_read >= MAX_VARINT_BYTES:
                    raise ProtobufError(f"varint too long at offset {pos}")
                b = data[pos]
                pos += 1
                bytes_read += 1
                result |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            n = result
            if n < 0 or end - pos < n:
                raise ProtobufError(
                    f"length-delimited: declared {n} bytes, only {end - pos} left "
                    f"at offset {pos}"
                )
            v = data[pos:pos + n]
            pos += n
        elif wire_type == 5:  # FIXED32
            if end - pos < 4:
                raise ProtobufError(f"fixed32 truncated at offset {pos}")
            v = data[pos:pos + 4]
            pos += 4
        elif wire_type in (3, 4):
            raise ProtobufError(f"deprecated group wire-type {wire_type} at offset {pos}")
        else:
            raise ProtobufError(f"unknown wire_type {wire_type} at offset {pos}")

        # dict.setdefault быстрее, чем if/else
        bucket = out.get(field_no)
        if bucket is None:
            out[field_no] = [v]
        else:
            bucket.append(v)

    return out


def try_parse_nested(blob: bytes, depth: int = 0) -> Optional[Dict[int, List[Any]]]:
    """
    Пытается разобрать blob как nested message. Возвращает None, если
    blob — не валидный proto-message (т.е. это была обычная string/bytes).
    """
    try:
        return parse_message(blob, depth=depth + 1)
    except ProtobufError:
        return None


def bytes_to_str(b: bytes) -> str:
    """Декодирует UTF-8 bytes (proto string) с заменой плохих байт."""
    return b.decode("utf-8", errors="replace")
