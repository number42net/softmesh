"""Tests for AES-128-ECB encryptThenMAC + the TXT_MSG / ACK codecs."""

from __future__ import annotations

import pytest
from softmesh_stack import crypto
from softmesh_stack.messaging import (
    ACK_HASH_SIZE,
    TXT_TYPE_PLAIN,
    TXT_TYPE_SIGNED_PLAIN,
    TxtMsg,
    ack_hash_for,
    build_ack_packet,
    build_path_packet,
    build_txt_msg_packet,
    build_txt_msg_payload,
    compose_plaintext,
    deliver_txt_msg_with_ack,
    parse_ack_payload,
    reverse_path,
    try_decrypt_path_msg,
    try_decrypt_txt_msg,
)
from softmesh_stack.packet import PayloadType, RouteType, decode_packet, encode_packet


class TestEncryptThenMac:
    def test_round_trip(self) -> None:
        secret = b"\x11" * 32
        plaintext = b"meshcore"  # 8 bytes; will be zero-padded to 16
        sealed = crypto.encrypt_then_mac(secret, plaintext)
        # 2-byte MAC + one 16-byte block
        assert len(sealed) == crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE
        recovered = crypto.mac_then_decrypt(secret, sealed)
        assert recovered is not None
        assert recovered.startswith(plaintext)
        assert recovered[len(plaintext) :] == b"\x00" * (crypto.CIPHER_BLOCK_SIZE - len(plaintext))

    def test_mac_failure_returns_none(self) -> None:
        secret = b"\x11" * 32
        sealed = bytearray(crypto.encrypt_then_mac(secret, b"hello"))
        sealed[0] ^= 0xFF  # corrupt the MAC
        assert crypto.mac_then_decrypt(secret, bytes(sealed)) is None

    def test_different_secret_fails(self) -> None:
        sealed = crypto.encrypt_then_mac(b"\x11" * 32, b"hi")
        assert crypto.mac_then_decrypt(b"\x22" * 32, sealed) is None

    def test_multi_block_round_trip(self) -> None:
        secret = b"\x33" * 32
        plaintext = b"x" * 40  # spans 3 blocks (48 bytes after padding)
        sealed = crypto.encrypt_then_mac(secret, plaintext)
        assert len(sealed) == crypto.CIPHER_MAC_SIZE + 48
        recovered = crypto.mac_then_decrypt(secret, sealed)
        assert recovered is not None
        assert recovered.startswith(plaintext)


class TestTxtMsgPlaintext:
    def test_compose_plaintext_layout(self) -> None:
        pt = compose_plaintext(timestamp=0x1234_5678, attempt=2, text="hi")
        # bytes 0..3 timestamp LE, byte 4 attempt, then "hi" + null
        assert pt[:4] == bytes([0x78, 0x56, 0x34, 0x12])
        assert pt[4] == 2
        assert pt[5:] == b"hi\x00"


class TestTxtMsgPacket:
    def test_encrypt_then_decrypt_round_trip(self) -> None:
        a_seed, a_pub = crypto.generate_keypair()
        b_seed, b_pub = crypto.generate_keypair()
        shared = crypto.calc_shared_secret(a_seed, b_pub)

        pkt = build_txt_msg_packet(
            shared_secret=shared,
            dest_pub_key=b_pub,
            src_pub_key=a_pub,
            timestamp=1_700_000_000,
            text="hello echo",
            attempt=0,
        )
        wire = encode_packet(pkt)
        decoded = decode_packet(wire)
        assert decoded.payload_type == PayloadType.TXT_MSG

        # The receiver side: same shared secret derived from its own seed.
        shared_b = crypto.calc_shared_secret(b_seed, a_pub)
        assert shared == shared_b

        msg = try_decrypt_txt_msg(decoded.payload, shared_b)
        assert msg is not None
        assert msg.text == "hello echo"
        assert msg.timestamp == 1_700_000_000
        assert msg.attempt == 0
        assert msg.dest_hash == b_pub[0]
        assert msg.src_hash == a_pub[0]

    def test_wrong_secret_returns_none(self) -> None:
        a_seed, a_pub = crypto.generate_keypair()
        _, b_pub = crypto.generate_keypair()
        c_seed, _ = crypto.generate_keypair()
        shared_ab = crypto.calc_shared_secret(a_seed, b_pub)
        shared_cb = crypto.calc_shared_secret(c_seed, b_pub)

        pkt = build_txt_msg_packet(
            shared_secret=shared_ab,
            dest_pub_key=b_pub,
            src_pub_key=a_pub,
            timestamp=1_700_000_000,
            text="secret",
        )
        # Wrong shared secret must NOT silently decrypt.
        assert try_decrypt_txt_msg(pkt.payload, shared_cb) is None

    def test_multi_block_text(self) -> None:
        a_seed, a_pub = crypto.generate_keypair()
        b_seed, b_pub = crypto.generate_keypair()
        shared = crypto.calc_shared_secret(a_seed, b_pub)
        text = "x" * 100  # spans multiple AES blocks
        pkt = build_txt_msg_packet(
            shared_secret=shared,
            dest_pub_key=b_pub,
            src_pub_key=a_pub,
            timestamp=42,
            text=text,
        )
        msg = try_decrypt_txt_msg(pkt.payload, crypto.calc_shared_secret(b_seed, a_pub))
        assert msg is not None
        assert msg.text == text

    def test_short_payload_returns_none(self) -> None:
        assert try_decrypt_txt_msg(b"\x00", b"\x00" * 32) is None


class TestAck:
    def test_ack_hash_is_4_bytes(self) -> None:
        _, sender_pub = crypto.generate_keypair()
        h = ack_hash_for(timestamp=42, attempt=0, text="hi", sender_pub_key=sender_pub)
        assert len(h) == ACK_HASH_SIZE

    def test_ack_hash_distinct_for_different_inputs(self) -> None:
        _, sender_pub = crypto.generate_keypair()
        h1 = ack_hash_for(timestamp=42, attempt=0, text="hi", sender_pub_key=sender_pub)
        h2 = ack_hash_for(timestamp=42, attempt=0, text="bye", sender_pub_key=sender_pub)
        assert h1 != h2

    def test_ack_hash_via_txt_msg_method(self) -> None:
        _, sender_pub = crypto.generate_keypair()
        msg = TxtMsg(dest_hash=1, src_hash=2, timestamp=42, attempt=0, text="hi")
        assert msg.ack_hash(sender_pub) == ack_hash_for(42, 0, "hi", sender_pub)

    def test_ack_hash_depends_on_txt_type(self) -> None:
        # The flags byte's type bits are part of the hashed buffer, so a SIGNED
        # message must produce a different ACK than a PLAIN one with the same
        # attempt/timestamp/text.
        _, sender_pub = crypto.generate_keypair()
        plain = ack_hash_for(42, 0, "hi", sender_pub, txt_type=TXT_TYPE_PLAIN)
        signed = ack_hash_for(42, 0, "hi", sender_pub, txt_type=TXT_TYPE_SIGNED_PLAIN)
        assert plain != signed

    def test_decrypt_preserves_txt_type_for_correct_ack(self) -> None:
        # A non-PLAIN message must round-trip its txt_type so the recomputed ACK
        # matches what the sender hashed (which includes the type bits).
        a_seed, a_pub = crypto.generate_keypair()
        b_seed, b_pub = crypto.generate_keypair()
        shared = crypto.calc_shared_secret(a_seed, b_pub)
        plaintext = compose_plaintext(
            timestamp=7, attempt=1, text="ping", txt_type=TXT_TYPE_SIGNED_PLAIN
        )
        sealed = crypto.encrypt_then_mac(shared, plaintext)
        payload = bytes([b_pub[0], a_pub[0]]) + sealed

        msg = try_decrypt_txt_msg(payload, crypto.calc_shared_secret(b_seed, a_pub))
        assert msg is not None
        assert msg.txt_type == TXT_TYPE_SIGNED_PLAIN
        assert msg.attempt == 1
        # The ACK the receiver computes equals what the sender (a) expects.
        assert msg.ack_hash(a_pub) == ack_hash_for(
            7, 1, "ping", a_pub, txt_type=TXT_TYPE_SIGNED_PLAIN
        )

    def test_build_and_parse_ack_packet(self) -> None:
        ack = b"\x01\x02\x03\x04"
        pkt = build_ack_packet(ack)
        wire = encode_packet(pkt)
        decoded = decode_packet(wire)
        assert decoded.payload_type == PayloadType.ACK
        assert parse_ack_payload(decoded.payload) == ack

    def test_build_ack_rejects_wrong_size(self) -> None:
        with pytest.raises(ValueError):
            build_ack_packet(b"\x00")


class TestPayloadAlignment:
    def test_payload_starts_with_dest_then_src_hash(self) -> None:
        a_seed, a_pub = crypto.generate_keypair()
        _, b_pub = crypto.generate_keypair()
        shared = crypto.calc_shared_secret(a_seed, b_pub)
        payload = build_txt_msg_payload(
            shared_secret=shared,
            dest_hash=b_pub[0],
            src_hash=a_pub[0],
            timestamp=1,
            attempt=0,
            text="x",
        )
        assert payload[0] == b_pub[0]
        assert payload[1] == a_pub[0]


def test_round_trip_uses_route_flood_by_default() -> None:
    a_seed, a_pub = crypto.generate_keypair()
    _, b_pub = crypto.generate_keypair()
    shared = crypto.calc_shared_secret(a_seed, b_pub)
    pkt = build_txt_msg_packet(
        shared_secret=shared,
        dest_pub_key=b_pub,
        src_pub_key=a_pub,
        timestamp=1,
        text="x",
    )
    assert pkt.route_type == RouteType.FLOOD


def test_reverse_path_preserves_hash_sized_entries() -> None:
    assert reverse_path(bytes.fromhex("aabbcc"), 1) == bytes.fromhex("ccbbaa")
    assert reverse_path(bytes.fromhex("aaaabbbbcccc"), 2) == bytes.fromhex("ccccbbbbaaaa")


def test_path_packet_round_trip_with_extra_ack() -> None:
    a_seed, a_pub = crypto.generate_keypair()
    b_seed, b_pub = crypto.generate_keypair()
    shared = crypto.calc_shared_secret(a_seed, b_pub)
    ack = b"\x01\x02\x00\x00"

    pkt = build_path_packet(
        shared_secret=shared,
        dest_hash=b_pub[0],
        src_pub_key=a_pub,
        path_payload=bytes.fromhex("aabb"),
        path_hash_size=1,
        extra_type=PayloadType.ACK,
        extra=ack,
    )
    msg = try_decrypt_path_msg(pkt.payload, crypto.calc_shared_secret(b_seed, a_pub))

    assert msg is not None
    assert msg.dest_hash == b_pub[0]
    assert msg.src_hash == a_pub[0]
    assert msg.path == bytes.fromhex("aabb")
    assert msg.hash_size == 1
    assert msg.extra_type == PayloadType.ACK
    assert msg.extra == ack


@pytest.mark.asyncio
async def test_delivery_tries_direct_path_then_flood() -> None:
    a_seed, a_pub = crypto.generate_keypair()
    _, b_pub = crypto.generate_keypair()
    shared = crypto.calc_shared_secret(a_seed, b_pub)
    sent = []

    async def publish(wire: bytes) -> None:
        sent.append(decode_packet(wire))

    async def wait_for_ack(_ack_hash: bytes, _timeout_s: float) -> bool:
        return False

    result = await deliver_txt_msg_with_ack(
        publish=publish,
        wait_for_ack=wait_for_ack,
        shared_secret=shared,
        dest_pub_key=b_pub,
        src_pub_key=a_pub,
        text="hello",
        timestamp=1,
        direct_path=bytes.fromhex("aabb"),
        direct_hash_size=1,
        direct_attempts=2,
        flood_attempts=1,
        ack_timeout_s=0,
    )

    assert [pkt.route_type for pkt in sent] == [RouteType.DIRECT, RouteType.DIRECT, RouteType.FLOOD]
    assert sent[0].path == bytes.fromhex("aabb")
    assert sent[1].path == bytes.fromhex("aabb")
    assert sent[2].path == b""
    assert result.route_type == RouteType.FLOOD
    assert not result.acked


@pytest.mark.asyncio
async def test_delivery_stops_after_ack() -> None:
    a_seed, a_pub = crypto.generate_keypair()
    _, b_pub = crypto.generate_keypair()
    shared = crypto.calc_shared_secret(a_seed, b_pub)
    sent = []

    async def publish(wire: bytes) -> None:
        sent.append(decode_packet(wire))

    async def wait_for_ack(_ack_hash: bytes, _timeout_s: float) -> bool:
        return len(sent) == 1

    result = await deliver_txt_msg_with_ack(
        publish=publish,
        wait_for_ack=wait_for_ack,
        shared_secret=shared,
        dest_pub_key=b_pub,
        src_pub_key=a_pub,
        text="hello",
        timestamp=1,
        direct_path=b"\xaa",
        direct_attempts=3,
        flood_attempts=3,
        ack_timeout_s=0,
    )

    assert len(sent) == 1
    assert sent[0].route_type == RouteType.DIRECT
    assert result.acked
