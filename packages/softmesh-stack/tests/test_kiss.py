"""Tests for KISS framing."""

from __future__ import annotations

import os

import pytest
from softmesh_stack.kiss import (
    FEND,
    FESC,
    TFEND,
    TFESC,
    KissCommand,
    KissDecoder,
    KissFrame,
    data_frame,
    encode,
)


class TestEncode:
    def test_empty_data_frame(self) -> None:
        result = encode(KissFrame(port=0, command=KissCommand.DATA, data=b""))
        assert result == bytes([FEND, 0x00, FEND])

    def test_simple_payload(self) -> None:
        result = encode(KissFrame(port=0, command=KissCommand.DATA, data=b"hello"))
        assert result == bytes([FEND, 0x00]) + b"hello" + bytes([FEND])

    def test_port_and_command_encoded_in_type_byte(self) -> None:
        result = encode(KissFrame(port=0xA, command=0x6, data=b""))
        assert result[1] == 0xA6

    def test_fend_in_payload_is_escaped(self) -> None:
        result = encode(KissFrame(port=0, command=KissCommand.DATA, data=bytes([FEND])))
        assert result == bytes([FEND, 0x00, FESC, TFEND, FEND])

    def test_fesc_in_payload_is_escaped(self) -> None:
        result = encode(KissFrame(port=0, command=KissCommand.DATA, data=bytes([FESC])))
        assert result == bytes([FEND, 0x00, FESC, TFESC, FEND])

    def test_return_command_is_0xff_type(self) -> None:
        result = encode(KissFrame(port=0, command=KissCommand.RETURN, data=b""))
        assert result == bytes([FEND, 0xFF, FEND])

    def test_out_of_range_port_raises(self) -> None:
        with pytest.raises(ValueError):
            encode(KissFrame(port=16, command=0, data=b""))

    def test_out_of_range_command_raises(self) -> None:
        with pytest.raises(ValueError):
            encode(KissFrame(port=0, command=0x10, data=b""))


class TestDecoder:
    def test_decodes_simple_frame(self) -> None:
        decoder = KissDecoder()
        frames = decoder.feed(bytes([FEND, 0x00]) + b"hello" + bytes([FEND]))
        assert len(frames) == 1
        assert frames[0].port == 0
        assert frames[0].command == KissCommand.DATA
        assert frames[0].data == b"hello"

    def test_unescapes_fend(self) -> None:
        decoder = KissDecoder()
        frames = decoder.feed(bytes([FEND, 0x00, FESC, TFEND, FEND]))
        assert len(frames) == 1
        assert frames[0].data == bytes([FEND])

    def test_unescapes_fesc(self) -> None:
        decoder = KissDecoder()
        frames = decoder.feed(bytes([FEND, 0x00, FESC, TFESC, FEND]))
        assert len(frames) == 1
        assert frames[0].data == bytes([FESC])

    def test_handles_back_to_back_frames(self) -> None:
        decoder = KissDecoder()
        wire = encode(KissFrame(port=0, command=KissCommand.DATA, data=b"one")) + encode(
            KissFrame(port=0, command=KissCommand.DATA, data=b"two")
        )
        frames = decoder.feed(wire)
        assert [f.data for f in frames] == [b"one", b"two"]

    def test_handles_byte_at_a_time(self) -> None:
        decoder = KissDecoder()
        wire = encode(KissFrame(port=0, command=KissCommand.DATA, data=b"streamy"))
        out: list[bytes] = []
        for byte in wire:
            out.extend(f.data for f in decoder.feed(bytes([byte])))
        assert out == [b"streamy"]

    def test_ignores_leading_garbage(self) -> None:
        decoder = KissDecoder()
        wire = b"\x01\x02\x03" + encode(KissFrame(port=0, command=KissCommand.DATA, data=b"x"))
        frames = decoder.feed(wire)
        assert len(frames) == 1
        assert frames[0].data == b"x"

    def test_redundant_fend_does_not_emit_empty_frame(self) -> None:
        decoder = KissDecoder()
        frames = decoder.feed(bytes([FEND, FEND, FEND]))
        assert frames == []

    def test_return_command_decodes(self) -> None:
        decoder = KissDecoder()
        frames = decoder.feed(bytes([FEND, 0xFF, FEND]))
        assert len(frames) == 1
        assert frames[0].command == KissCommand.RETURN

    def test_decoder_round_trip_random(self) -> None:
        rng = os.urandom
        for _ in range(64):
            payload = rng(rng(1)[0])  # random length up to 255
            decoder = KissDecoder()
            frames = decoder.feed(data_frame(payload))
            assert len(frames) == 1
            assert frames[0].data == payload


def test_data_frame_helper_round_trips() -> None:
    decoder = KissDecoder()
    frames = decoder.feed(data_frame(b"meshcore"))
    assert len(frames) == 1
    assert frames[0].data == b"meshcore"
    assert frames[0].command == KissCommand.DATA
