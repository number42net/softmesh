"""Tests for the MeshCore packet codec, including multi-byte paths."""

from __future__ import annotations

import pytest
from softmesh_stack.packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    decode_header,
    decode_packet,
    decode_path_len,
    encode_header,
    encode_packet,
    encode_path_len,
)


class TestHeader:
    def test_round_trip_all_fields(self) -> None:
        b = encode_header(RouteType.DIRECT, PayloadType.TXT_MSG, PayloadVer.V2)
        rt, pt, pv = decode_header(b)
        assert rt == RouteType.DIRECT
        assert pt == PayloadType.TXT_MSG
        assert pv == PayloadVer.V2

    def test_bit_layout(self) -> None:
        # route_type=0x03, payload_type=0x0F, payload_ver=0x03
        # binary: 11 1111 11 = 0xFF
        assert encode_header(0x03, 0x0F, 0x03) == 0xFF
        # route_type=0x00, payload_type=0x04 (ADVERT), payload_ver=0
        # binary: 00 0100 00 = 0x10
        assert encode_header(0x00, 0x04, 0x00) == 0x10


class TestPathLen:
    def test_round_trip_single_byte_hashes(self) -> None:
        b = encode_path_len(hash_count=5, hash_size=1)
        assert decode_path_len(b) == (5, 1)

    def test_round_trip_two_byte_hashes(self) -> None:
        b = encode_path_len(hash_count=3, hash_size=2)
        assert decode_path_len(b) == (3, 2)

    def test_round_trip_max_hash_size(self) -> None:
        b = encode_path_len(hash_count=10, hash_size=4)
        assert decode_path_len(b) == (10, 4)

    def test_zero_count(self) -> None:
        b = encode_path_len(hash_count=0, hash_size=1)
        assert decode_path_len(b) == (0, 1)

    def test_rejects_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            encode_path_len(hash_count=64, hash_size=1)
        with pytest.raises(ValueError):
            encode_path_len(hash_count=0, hash_size=5)
        with pytest.raises(ValueError):
            encode_path_len(hash_count=0, hash_size=0)


class TestPacket:
    def test_minimal_flood_advert(self) -> None:
        pkt = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.ADVERT,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=b"",
            payload=b"some-advert-bytes",
        )
        wire = encode_packet(pkt)
        decoded = decode_packet(wire)
        assert decoded.route_type == RouteType.FLOOD
        assert decoded.payload_type == PayloadType.ADVERT
        assert decoded.payload == b"some-advert-bytes"
        assert decoded.transport_codes is None
        assert decoded.path == b""

    def test_transport_flood_carries_transport_codes(self) -> None:
        pkt = Packet(
            route_type=RouteType.TRANSPORT_FLOOD,
            payload_type=PayloadType.TXT_MSG,
            payload_ver=PayloadVer.V1,
            transport_codes=(0x1234, 0xABCD),
            path=b"",
            payload=b"hello",
        )
        wire = encode_packet(pkt)
        # header(1) + transport_codes(4) + path_len(1) + payload
        assert len(wire) == 1 + 4 + 1 + len(pkt.payload)
        decoded = decode_packet(wire)
        assert decoded.transport_codes == (0x1234, 0xABCD)
        assert decoded.payload == b"hello"

    def test_non_transport_must_not_carry_codes(self) -> None:
        pkt = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.ADVERT,
            payload_ver=PayloadVer.V1,
            transport_codes=(1, 2),
            path=b"",
            payload=b"x",
        )
        with pytest.raises(ValueError):
            encode_packet(pkt)

    def test_one_byte_path(self) -> None:
        path = bytes([0xAA, 0xBB, 0xCC])  # 3 hops
        pkt = Packet(
            route_type=RouteType.DIRECT,
            payload_type=PayloadType.TXT_MSG,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=path,
            payload=b"hi",
            hash_size=1,
        )
        wire = encode_packet(pkt)
        decoded = decode_packet(wire)
        assert decoded.path == path
        assert decoded.hash_size == 1
        assert decoded.hash_count == 3

    def test_two_byte_path(self) -> None:
        # 3 hops, each hash 2 bytes => 6 path bytes
        path = bytes([0xAA, 0x11, 0xBB, 0x22, 0xCC, 0x33])
        pkt = Packet(
            route_type=RouteType.DIRECT,
            payload_type=PayloadType.TXT_MSG,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=path,
            payload=b"two-byte path",
            hash_size=2,
        )
        wire = encode_packet(pkt)
        decoded = decode_packet(wire)
        assert decoded.path == path
        assert decoded.hash_size == 2
        assert decoded.hash_count == 3
        assert decoded.payload == b"two-byte path"

    def test_two_byte_path_path_len_byte_encoding(self) -> None:
        # 5 hops at hash_size=2 => path_len byte = 5 | (1 << 6) = 0x45
        path = b"\x00" * 10  # 5 hops * 2 bytes
        pkt = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.TXT_MSG,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=path,
            payload=b"",
            hash_size=2,
        )
        wire = encode_packet(pkt)
        # wire = header(1) + path_len(1) + path(10)
        assert wire[1] == (5 & 0x3F) | (1 << 6)
        # And decode picks it back up:
        decoded = decode_packet(wire)
        assert decoded.hash_size == 2
        assert decoded.hash_count == 5

    def test_path_misaligned_to_hash_size_rejected(self) -> None:
        pkt = Packet(
            route_type=RouteType.DIRECT,
            payload_type=PayloadType.TXT_MSG,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=b"\x00\x00\x00",  # odd number of bytes for hash_size=2
            payload=b"",
            hash_size=2,
        )
        with pytest.raises(ValueError):
            encode_packet(pkt)

    def test_decode_rejects_path_over_max_size(self) -> None:
        # path_len byte claiming 16 hops * 4 bytes = 64 is the limit; 32 hops *
        # 4 bytes = 128 exceeds MAX_PATH_SIZE and must be rejected.
        from softmesh_stack.packet import encode_header

        header = encode_header(RouteType.FLOOD, PayloadType.TXT_MSG, PayloadVer.V1)
        path_len = encode_path_len(hash_count=32, hash_size=4)
        wire = bytes([header, path_len]) + b"\x00" * 128
        with pytest.raises(ValueError):
            decode_packet(wire)

    def test_decode_truncated_packet(self) -> None:
        # Build a transport packet then chop it.
        pkt = Packet(
            route_type=RouteType.TRANSPORT_DIRECT,
            payload_type=PayloadType.ACK,
            payload_ver=PayloadVer.V1,
            transport_codes=(1, 2),
            path=b"",
            payload=b"",
        )
        wire = encode_packet(pkt)
        # Cut off the transport_codes mid-field.
        with pytest.raises(ValueError):
            decode_packet(wire[:3])
