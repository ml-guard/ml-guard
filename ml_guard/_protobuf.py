"""Minimal protobuf wire-format reader.

ONNX files are serialized protobuf (`onnx.ModelProto`). We don't want to
pull in the full `onnx` or `protobuf` library inside a security scanner:
parsing the *same format* you're scanning is a known bad pattern (parser
CVEs become scanner CVEs). So we read the wire format directly, in a
few hundred lines.

Wire-format protobuf, brief overview:

  Each field = (tag, value), where tag = (field_number << 3) | wire_type.
  Wire types:
    0  VARINT     — integers: int32/int64/bool/enum, ZigZag for signed
    1  FIXED64    — double, fixed64, sfixed64
    2  LENGTH     — string, bytes, embedded message, packed repeated
    5  FIXED32    — float, fixed32, sfixed32
    (3, 4 — deprecated: groups)

We read varints and length-delimited blocks with strict bounds checks;
no recursive allocations. Nesting depth is capped — defense against
protobuf-bomb (analogous to JSON, a million nested messages can blow
the stack).

Details: https://protobuf.dev/programming-guides/encoding/
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple


# Hard limits — protobuf-bomb defense.
MAX_DEPTH = 32
MAX_VARINT_BYTES = 10  # a 64-bit varint cannot be longer


class ProtobufError(Exception):
    """Any parser problem; carries the offset and context."""


# ---------------------------------------------------------------------------
# Low-level reading
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
        """Read an unsigned varint (up to 10 bytes)."""
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
    """Extract (field_number, wire_type) from a tag varint."""
    return (tag >> 3, tag & 0x7)


# ---------------------------------------------------------------------------
# High-level: parse_message → dict
# ---------------------------------------------------------------------------
#
# Returns a "raw" tree: for each field a list of values (proto fields may
# repeat). Values are bytes, int, or a nested dict. Per-field interpretation
# (this int is an enum, these bytes are a string) is done in onnx_scanner.py
# against the ONNX schema.

def parse_message(data: bytes, depth: int = 0) -> Dict[int, List[Any]]:
    """
    Parse the whole buffer as a single message; return {field_no: [values...]}.

    Implemented "flat", without _Cursor: in Python the accessor overhead
    for a protobuf parser is significant — each byte/varint read would
    become 2-3 method calls, and that adds up to tens of ms on 10K nodes.
    Here we keep pos as a local variable and read directly from the bytes
    object. The ONNX scanner on 10K nodes is ~2x faster as a result.

    Correctness is identical: same depth limits, same ProtobufError raises.
    """
    if depth > MAX_DEPTH:
        raise ProtobufError(f"protobuf nesting too deep (>{MAX_DEPTH})")

    out: Dict[int, List[Any]] = {}
    pos = 0
    end = len(data)

    while pos < end:
        # ---- inline read_varint for the tag ----
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
            # ---- inline another varint ----
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
            # length — varint
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

        # dict.setdefault is slower than this two-step
        bucket = out.get(field_no)
        if bucket is None:
            out[field_no] = [v]
        else:
            bucket.append(v)

    return out


def try_parse_nested(blob: bytes, depth: int = 0) -> Optional[Dict[int, List[Any]]]:
    """
    Try to parse `blob` as a nested message. Returns None if `blob` isn't
    a valid proto message (i.e. it was a plain string/bytes value).
    """
    try:
        return parse_message(blob, depth=depth + 1)
    except ProtobufError:
        return None


def bytes_to_str(b: bytes) -> str:
    """Decode UTF-8 bytes (proto string) with replacement for bad bytes."""
    return b.decode("utf-8", errors="replace")
