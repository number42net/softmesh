"""MeshCore packet structure.

Wire format (from src/Packet.cpp writeTo() in meshcore-dev/MeshCore):

    byte 0           : header (route_type:2 | payload_type:4 | payload_ver:2)
    bytes 1..4       : transport_codes — 2 x uint16 LE — ONLY when route_type is
                       TRANSPORT_FLOOD (0) or TRANSPORT_DIRECT (3)
    byte (1 or 5)    : path_len byte: hash_count in low 6 bits, (hash_size-1) in
                       top 2 bits
    next             : path bytes (hash_count * hash_size)
    rest             : payload bytes
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

ROUTE_TYPE_MASK = 0x03
PAYLOAD_TYPE_SHIFT = 2
PAYLOAD_TYPE_MASK = 0x0F
PAYLOAD_VER_SHIFT = 6
PAYLOAD_VER_MASK = 0x03

PATH_LEN_HASH_COUNT_MASK = 0x3F
PATH_LEN_HASH_SIZE_SHIFT = 6
PATH_LEN_HASH_SIZE_MASK = 0x03

TRANSPORT_CODES_SIZE = 4  # 2 x uint16

# Max path byte length, matching MeshCore's MAX_PATH_SIZE. A path_len byte whose
# decoded hash_count * hash_size exceeds this is invalid (firmware rejects it in
# isValidPathLen()).
MAX_PATH_SIZE = 64


class RouteType(IntEnum):
    TRANSPORT_FLOOD = 0x00
    FLOOD = 0x01
    DIRECT = 0x02
    TRANSPORT_DIRECT = 0x03


class PayloadType(IntEnum):
    REQ = 0x00
    RESPONSE = 0x01
    TXT_MSG = 0x02
    ACK = 0x03
    ADVERT = 0x04
    GRP_TXT = 0x05
    GRP_DATA = 0x06
    ANON_REQ = 0x07
    PATH = 0x08
    TRACE = 0x09
    MULTIPART = 0x0A
    CONTROL = 0x0B
    RAW_CUSTOM = 0x0F


class PayloadVer(IntEnum):
    V1 = 0x00
    V2 = 0x01
    V3 = 0x02
    V4 = 0x03


_TRANSPORT_ROUTES = frozenset({RouteType.TRANSPORT_FLOOD, RouteType.TRANSPORT_DIRECT})


def has_transport_codes(route_type: int) -> bool:
    return route_type in _TRANSPORT_ROUTES


def encode_header(route_type: int, payload_type: int, payload_ver: int = 0) -> int:
    return (
        (route_type & ROUTE_TYPE_MASK)
        | ((payload_type & PAYLOAD_TYPE_MASK) << PAYLOAD_TYPE_SHIFT)
        | ((payload_ver & PAYLOAD_VER_MASK) << PAYLOAD_VER_SHIFT)
    )


def decode_header(b: int) -> tuple[int, int, int]:
    return (
        b & ROUTE_TYPE_MASK,
        (b >> PAYLOAD_TYPE_SHIFT) & PAYLOAD_TYPE_MASK,
        (b >> PAYLOAD_VER_SHIFT) & PAYLOAD_VER_MASK,
    )


def encode_path_len(hash_count: int, hash_size: int = 1) -> int:
    if not 1 <= hash_size <= 4:
        raise ValueError("hash_size must be in 1..4")
    if not 0 <= hash_count <= PATH_LEN_HASH_COUNT_MASK:
        raise ValueError("hash_count must be in 0..63")
    return (hash_count & PATH_LEN_HASH_COUNT_MASK) | ((hash_size - 1) << PATH_LEN_HASH_SIZE_SHIFT)


def decode_path_len(b: int) -> tuple[int, int]:
    """Return (hash_count, hash_size)."""
    return (
        b & PATH_LEN_HASH_COUNT_MASK,
        ((b >> PATH_LEN_HASH_SIZE_SHIFT) & PATH_LEN_HASH_SIZE_MASK) + 1,
    )


@dataclass(frozen=True, slots=True)
class Packet:
    route_type: RouteType
    payload_type: PayloadType
    payload_ver: PayloadVer
    transport_codes: tuple[int, int] | None
    path: bytes
    payload: bytes
    hash_size: int = 1

    @property
    def has_transport_codes(self) -> bool:
        return has_transport_codes(self.route_type)

    @property
    def hash_count(self) -> int:
        return len(self.path) // self.hash_size


def encode_packet(pkt: Packet) -> bytes:
    out = bytearray()
    out.append(encode_header(pkt.route_type, pkt.payload_type, pkt.payload_ver))
    if pkt.has_transport_codes:
        if pkt.transport_codes is None:
            raise ValueError(f"route_type {pkt.route_type!r} requires transport_codes")
        a, b = pkt.transport_codes
        out += a.to_bytes(2, "little")
        out += b.to_bytes(2, "little")
    elif pkt.transport_codes is not None:
        raise ValueError(f"route_type {pkt.route_type!r} does not carry transport_codes")
    if pkt.hash_size != 1 and len(pkt.path) % pkt.hash_size != 0:
        raise ValueError("path length is not a multiple of hash_size")
    out.append(encode_path_len(pkt.hash_count, pkt.hash_size))
    out += pkt.path
    out += pkt.payload
    return bytes(out)


def decode_packet(data: bytes) -> Packet:
    if not data:
        raise ValueError("empty packet")

    i = 0
    route_type_v, payload_type_v, payload_ver_v = decode_header(data[i])
    i += 1

    transport_codes: tuple[int, int] | None = None
    if has_transport_codes(route_type_v):
        if len(data) < i + TRANSPORT_CODES_SIZE:
            raise ValueError("packet too short for transport_codes")
        transport_codes = (
            int.from_bytes(data[i : i + 2], "little"),
            int.from_bytes(data[i + 2 : i + 4], "little"),
        )
        i += TRANSPORT_CODES_SIZE

    if len(data) < i + 1:
        raise ValueError("packet too short for path_len")
    hash_count, hash_size = decode_path_len(data[i])
    i += 1

    path_bytes = hash_count * hash_size
    if path_bytes > MAX_PATH_SIZE:
        raise ValueError(
            f"path length {path_bytes} exceeds MAX_PATH_SIZE ({MAX_PATH_SIZE})"
        )
    if len(data) < i + path_bytes:
        raise ValueError("packet too short for path bytes")
    path = data[i : i + path_bytes]
    i += path_bytes

    payload = data[i:]

    # Tolerate unknown numeric values gracefully.
    return Packet(
        route_type=_as_enum(RouteType, route_type_v),
        payload_type=_as_enum(PayloadType, payload_type_v),
        payload_ver=_as_enum(PayloadVer, payload_ver_v),
        transport_codes=transport_codes,
        path=path,
        payload=payload,
        hash_size=hash_size,
    )


def _as_enum(cls, value):  # type: ignore[no-untyped-def]
    try:
        return cls(value)
    except ValueError:
        # Unknown enum member: return the raw int so callers can still see it.
        return value
