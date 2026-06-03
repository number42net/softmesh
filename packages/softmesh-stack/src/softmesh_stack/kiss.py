"""KISS framing for the Heltec KISS modem serial transport.

The KA9Q KISS protocol uses four special bytes:

    FEND  = 0xC0  frame delimiter
    FESC  = 0xDB  escape
    TFEND = 0xDC  literal FEND when preceded by FESC
    TFESC = 0xDD  literal FESC when preceded by FESC

A frame is `FEND <type> <data...> FEND`. The type byte's upper nibble is the
port (typically 0) and the lower nibble is the command (0x00 = data). The
special type 0xFF means "exit KISS mode" (no data).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD


class KissCommand(IntEnum):
    DATA = 0x00
    TX_DELAY = 0x01
    PERSISTENCE = 0x02
    SLOT_TIME = 0x03
    TX_TAIL = 0x04
    FULL_DUPLEX = 0x05
    SET_HARDWARE = 0x06
    RETURN = 0xFF


@dataclass(frozen=True, slots=True)
class KissFrame:
    port: int
    command: int
    data: bytes


def encode(frame: KissFrame) -> bytes:
    """Encode a KissFrame to its on-wire byte sequence."""
    if frame.command == KissCommand.RETURN:
        type_byte = 0xFF
    else:
        if not 0 <= frame.port <= 0x0F:
            raise ValueError(f"port out of range 0..15: {frame.port}")
        if not 0 <= frame.command <= 0x0F:
            raise ValueError(f"command out of range 0..15: {frame.command}")
        type_byte = ((frame.port & 0x0F) << 4) | (frame.command & 0x0F)

    out = bytearray()
    out.append(FEND)
    out.append(type_byte)
    for b in frame.data:
        if b == FEND:
            out.append(FESC)
            out.append(TFEND)
        elif b == FESC:
            out.append(FESC)
            out.append(TFESC)
        else:
            out.append(b)
    out.append(FEND)
    return bytes(out)


def data_frame(payload: bytes, port: int = 0) -> bytes:
    """Convenience: encode a type-0x00 data frame ready to write to serial."""
    return encode(KissFrame(port=port, command=KissCommand.DATA, data=payload))


class KissDecoder:
    """Stateful streaming KISS decoder.

    Feed raw serial bytes via `feed()`; it returns any frames that have
    just completed. The decoder tolerates partial frames at startup,
    back-to-back FENDs, and arbitrary chunking of the input stream.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._escaped = False
        self._in_frame = False

    def feed(self, data: bytes) -> list[KissFrame]:
        completed: list[KissFrame] = []
        for byte in data:
            if byte == FEND:
                if self._in_frame and self._buf:
                    frame = self._build_frame(self._buf)
                    if frame is not None:
                        completed.append(frame)
                self._buf = bytearray()
                self._escaped = False
                self._in_frame = True
            elif not self._in_frame:
                # Stream noise before the first frame delimiter; drop.
                continue
            elif self._escaped:
                if byte == TFEND:
                    self._buf.append(FEND)
                elif byte == TFESC:
                    self._buf.append(FESC)
                # Invalid escape sequence: drop the byte and resync.
                self._escaped = False
            elif byte == FESC:
                self._escaped = True
            else:
                self._buf.append(byte)
        return completed

    @staticmethod
    def _build_frame(buf: bytearray) -> KissFrame | None:
        if not buf:
            return None
        type_byte = buf[0]
        if type_byte == 0xFF:
            return KissFrame(port=0, command=KissCommand.RETURN, data=b"")
        port = (type_byte >> 4) & 0x0F
        command = type_byte & 0x0F
        return KissFrame(port=port, command=command, data=bytes(buf[1:]))
