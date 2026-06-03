"""Tests for advertisement payload codec."""

from __future__ import annotations

import time

import pytest
from softmesh_stack import crypto
from softmesh_stack.advert import (
    ADV_FEAT1_MASK,
    ADV_FEAT2_MASK,
    ADV_LATLON_MASK,
    ADV_NAME_MASK,
    AdvertData,
    AdvertType,
    decode_advert,
    encode_advert,
)


class TestAdvertData:
    def test_name_only(self) -> None:
        data = AdvertData(type=AdvertType.CHAT, name="ts-echo")
        encoded = data.encode()
        assert encoded[0] & ADV_NAME_MASK
        assert encoded[0] & 0x0F == AdvertType.CHAT
        decoded = AdvertData.decode(encoded)
        assert decoded.name == "ts-echo"
        assert decoded.type == AdvertType.CHAT
        assert decoded.lat is None
        assert decoded.lon is None

    def test_with_position(self) -> None:
        data = AdvertData(
            type=AdvertType.ROOM,
            name="amsterdam",
            lat=52.3702,
            lon=4.8952,
        )
        encoded = data.encode()
        assert encoded[0] & ADV_LATLON_MASK
        assert encoded[0] & ADV_NAME_MASK
        decoded = AdvertData.decode(encoded)
        assert decoded.name == "amsterdam"
        assert decoded.type == AdvertType.ROOM
        assert decoded.lat is not None
        assert decoded.lon is not None
        assert abs(decoded.lat - 52.3702) < 1e-5
        assert abs(decoded.lon - 4.8952) < 1e-5

    def test_with_features(self) -> None:
        data = AdvertData(
            type=AdvertType.REPEATER,
            name="rpt",
            feat1=0x0102,
            feat2=0x0304,
        )
        encoded = data.encode()
        assert encoded[0] & ADV_FEAT1_MASK
        assert encoded[0] & ADV_FEAT2_MASK
        decoded = AdvertData.decode(encoded)
        assert decoded.feat1 == 0x0102
        assert decoded.feat2 == 0x0304

    def test_decode_empty_rejects(self) -> None:
        with pytest.raises(ValueError):
            AdvertData.decode(b"")

    def test_partial_lat_lon_disallowed(self) -> None:
        with pytest.raises(ValueError):
            AdvertData(type=AdvertType.CHAT, name="x", lat=1.0).encode()


class TestAdvertisement:
    def test_encode_then_decode_with_valid_signature(self) -> None:
        seed, pub_key = crypto.generate_keypair()
        ts = int(time.time())
        app = AdvertData(type=AdvertType.CHAT, name="alice")
        payload = encode_advert(seed, pub_key, ts, app)
        decoded = decode_advert(payload)
        assert decoded.pub_key == pub_key
        assert decoded.timestamp == ts
        assert decoded.app_data.name == "alice"
        assert decoded.signature_valid is True

    def test_tampered_app_data_breaks_signature(self) -> None:
        seed, pub_key = crypto.generate_keypair()
        ts = int(time.time())
        app = AdvertData(type=AdvertType.CHAT, name="alice")
        payload = bytearray(encode_advert(seed, pub_key, ts, app))
        # Flip a bit in the app_data tail
        payload[-1] ^= 0x01
        decoded = decode_advert(bytes(payload))
        assert decoded.signature_valid is False

    def test_too_short_payload_rejected(self) -> None:
        with pytest.raises(ValueError):
            decode_advert(b"\x00" * 10)
