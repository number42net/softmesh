"""PAYLOAD_TYPE_ADVERT payload codec.

Wire format (from src/Mesh.cpp createAdvert and src/helpers/AdvertDataHelpers):

    bytes 0..31      : sender pub_key (Ed25519)
    bytes 32..35     : timestamp (uint32 little-endian, epoch seconds)
    bytes 36..99     : signature (Ed25519, 64 bytes)
    bytes 100+       : app_data (variable, format below)

The signature covers `pub_key || timestamp || app_data` (it does NOT include
itself).

app_data layout:

    byte 0           : type (bits 0..3) | flags (bits 4..7)
                         0x10 ADV_LATLON_MASK
                         0x20 ADV_FEAT1_MASK
                         0x40 ADV_FEAT2_MASK
                         0x80 ADV_NAME_MASK
                       type values:
                         0 = NONE
                         1 = CHAT     (companion node)
                         2 = REPEATER
                         3 = ROOM
                         4 = SENSOR
    if LATLON: int32 lat (LE) * 1e6, int32 lon (LE) * 1e6
    if FEAT1 : uint16 LE
    if FEAT2 : uint16 LE
    if NAME  : remaining bytes, UTF-8, NUL-terminated or end of message
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from . import crypto

ADVERT_TIMESTAMP_SIZE = 4
ADVERT_HEADER_SIZE = crypto.PUB_KEY_SIZE + ADVERT_TIMESTAMP_SIZE + crypto.SIGNATURE_SIZE

ADV_LATLON_MASK = 0x10
ADV_FEAT1_MASK = 0x20
ADV_FEAT2_MASK = 0x40
ADV_NAME_MASK = 0x80
ADV_TYPE_MASK = 0x0F

LATLON_SCALE = 1_000_000


class AdvertType(IntEnum):
    NONE = 0
    CHAT = 1
    REPEATER = 2
    ROOM = 3
    SENSOR = 4


@dataclass(frozen=True, slots=True)
class AdvertData:
    type: int  # AdvertType, but kept as int to tolerate unknown values
    name: str = ""
    lat: float | None = None
    lon: float | None = None
    feat1: int | None = None
    feat2: int | None = None

    def encode(self) -> bytes:
        flags = self.type & ADV_TYPE_MASK
        body = bytearray()
        if self.lat is not None or self.lon is not None:
            if self.lat is None or self.lon is None:
                raise ValueError("lat and lon must both be set or both be None")
            flags |= ADV_LATLON_MASK
            body += round(self.lat * LATLON_SCALE).to_bytes(4, "little", signed=True)
            body += round(self.lon * LATLON_SCALE).to_bytes(4, "little", signed=True)
        if self.feat1 is not None:
            flags |= ADV_FEAT1_MASK
            body += self.feat1.to_bytes(2, "little")
        if self.feat2 is not None:
            flags |= ADV_FEAT2_MASK
            body += self.feat2.to_bytes(2, "little")
        if self.name:
            flags |= ADV_NAME_MASK
            body += self.name.encode("utf-8")
        return bytes([flags]) + bytes(body)

    @classmethod
    def decode(cls, app_data: bytes) -> AdvertData:
        if not app_data:
            raise ValueError("empty advert app_data")
        flags = app_data[0]
        adv_type = flags & ADV_TYPE_MASK
        i = 1
        lat = lon = None
        feat1 = feat2 = None

        if flags & ADV_LATLON_MASK:
            if len(app_data) < i + 8:
                raise ValueError("advert app_data truncated in latlon")
            lat = int.from_bytes(app_data[i : i + 4], "little", signed=True) / LATLON_SCALE
            lon = int.from_bytes(app_data[i + 4 : i + 8], "little", signed=True) / LATLON_SCALE
            i += 8

        if flags & ADV_FEAT1_MASK:
            if len(app_data) < i + 2:
                raise ValueError("advert app_data truncated in feat1")
            feat1 = int.from_bytes(app_data[i : i + 2], "little")
            i += 2

        if flags & ADV_FEAT2_MASK:
            if len(app_data) < i + 2:
                raise ValueError("advert app_data truncated in feat2")
            feat2 = int.from_bytes(app_data[i : i + 2], "little")
            i += 2

        name = ""
        if flags & ADV_NAME_MASK:
            name_bytes = app_data[i:].split(b"\x00", 1)[0]
            name = name_bytes.decode("utf-8", errors="replace")

        return cls(type=adv_type, name=name, lat=lat, lon=lon, feat1=feat1, feat2=feat2)


@dataclass(frozen=True, slots=True)
class Advertisement:
    pub_key: bytes
    timestamp: int
    signature: bytes
    app_data: AdvertData
    raw_app_data: bytes  # preserved verbatim so the signature can be re-verified

    def signed_message(self) -> bytes:
        return (
            self.pub_key
            + self.timestamp.to_bytes(ADVERT_TIMESTAMP_SIZE, "little")
            + self.raw_app_data
        )

    @property
    def signature_valid(self) -> bool:
        return crypto.verify(self.pub_key, self.signature, self.signed_message())


def decode_advert(payload: bytes) -> Advertisement:
    if len(payload) < ADVERT_HEADER_SIZE:
        raise ValueError(
            f"advert payload too short: {len(payload)} bytes (need >= {ADVERT_HEADER_SIZE})"
        )
    pub_key = payload[: crypto.PUB_KEY_SIZE]
    ts_off = crypto.PUB_KEY_SIZE
    timestamp = int.from_bytes(payload[ts_off : ts_off + ADVERT_TIMESTAMP_SIZE], "little")
    sig_off = ts_off + ADVERT_TIMESTAMP_SIZE
    signature = payload[sig_off : sig_off + crypto.SIGNATURE_SIZE]
    raw_app_data = payload[ADVERT_HEADER_SIZE:]
    app_data = AdvertData.decode(raw_app_data)
    return Advertisement(
        pub_key=pub_key,
        timestamp=timestamp,
        signature=signature,
        app_data=app_data,
        raw_app_data=raw_app_data,
    )


def encode_advert(
    identity_seed: bytes,
    pub_key: bytes,
    timestamp: int,
    app_data: AdvertData,
) -> bytes:
    """Build a signed ADVERT payload."""
    raw_app_data = app_data.encode()
    msg = pub_key + timestamp.to_bytes(ADVERT_TIMESTAMP_SIZE, "little") + raw_app_data
    signature = crypto.sign(identity_seed, msg)
    return pub_key + timestamp.to_bytes(ADVERT_TIMESTAMP_SIZE, "little") + signature + raw_app_data
