"""PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_GRP_TXT, and PAYLOAD_TYPE_ACK codecs.

A direct text message (TXT_MSG) payload:

    dest_hash (1 byte)   PATH_HASH_SIZE
    src_hash  (1 byte)
    MAC       (2 bytes)  truncated HMAC-SHA256 over the ciphertext
    ciphertext           AES-128-ECB, zero-padded to a 16-byte multiple

A group/channel text message (GRP_TXT) payload uses the same MAC+cipher
scheme but with a channel-derived key instead of an ECDH shared secret:

    channel_hash (1 byte)  first byte of SHA-256(channel_secret)
    sender_hash  (1 byte)  path_hash of the sender
    MAC          (2 bytes)
    ciphertext

Inner plaintext (both TXT_MSG and GRP_TXT after decryption):

    timestamp (4 bytes LE)
    attempt   (1 byte; low 2 bits are the retry counter)
    text                  (null-terminated UTF-8 string)

The channel key passed to `try_decode_grp_txt` must be the full SHA-256 of
the channel secret/password (32 bytes), matching MeshCore's key derivation.
For the default public channel (empty secret): SHA-256(b"").

The sender computes a 4-byte ACK hash for TXT_MSG:

    ack_hash = SHA256(plaintext_up_to_and_including_text || sender_pub_key)[:4]

(`plaintext_up_to_and_including_text` is 5 + text_len bytes — it does NOT
include the trailing null byte.) The recipient sends a PAYLOAD_TYPE_ACK
packet whose payload is exactly those 4 bytes.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from . import crypto
from .packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    encode_packet,
)

TXT_MSG_HEADER_SIZE = 2 * crypto.PATH_HASH_SIZE  # dest_hash + src_hash
ACK_HASH_SIZE = 4

TIMESTAMP_SIZE = 4
ATTEMPT_SIZE = 1

# The byte after the timestamp packs the retry counter (low 2 bits) and the
# message type (bits 2..7), per `temp[4] = (attempt & 3) | (TXT_TYPE << 2)` in
# MeshCore's BaseChatMesh.cpp.
TXT_TYPE_PLAIN = 0
TXT_TYPE_CLI_DATA = 1
TXT_TYPE_SIGNED_PLAIN = 2

ATTEMPT_MASK = 0x03
TXT_TYPE_SHIFT = 2


def encode_flags_byte(attempt: int, txt_type: int = TXT_TYPE_PLAIN) -> int:
    """Pack the attempt counter and message type into the wire flags byte."""
    return (attempt & ATTEMPT_MASK) | (txt_type << TXT_TYPE_SHIFT)


@dataclass(frozen=True, slots=True)
class TxtMsg:
    """A decrypted direct text message."""

    dest_hash: int
    src_hash: int
    timestamp: int
    attempt: int  # low 2 bits in the wire format
    text: str
    txt_type: int = TXT_TYPE_PLAIN  # bits 2..7 of the flags byte

    def ack_hash(self, sender_pub_key: bytes) -> bytes:
        return ack_hash_for(
            self.timestamp, self.attempt, self.text, sender_pub_key, self.txt_type
        )


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    route_type: RouteType
    attempt: int
    ack_hash: bytes
    acked: bool


@dataclass(frozen=True, slots=True)
class PathMsg:
    dest_hash: int
    src_hash: int
    path: bytes
    hash_size: int
    extra_type: int
    extra: bytes


@dataclass(frozen=True, slots=True)
class ReqMsg:
    dest_hash: int
    src_hash: int
    timestamp: int
    data: bytes


@dataclass(frozen=True, slots=True)
class GrpTxtMsg:
    """A decoded PAYLOAD_TYPE_GRP_TXT (group/channel) message."""

    channel_hash: int
    sender_hash: int
    timestamp: int
    attempt: int
    text: str
    txt_type: int = TXT_TYPE_PLAIN


GRP_TXT_HEADER_SIZE = 2 * crypto.PATH_HASH_SIZE  # channel_hash + sender_hash


def channel_key_from_secret(secret: str) -> bytes:
    """Derive the 32-byte channel key from the channel secret/password.

    Pass the result directly to `try_decode_grp_txt`.  For the default public
    channel (no password) use ``channel_key_from_secret("")``.
    """
    return crypto.sha256(secret.encode("utf-8"))


def try_decode_grp_txt(payload: bytes, channel_key: bytes) -> GrpTxtMsg | None:
    """Try to decode a GRP_TXT payload using the given channel key.

    `channel_key` must be 32 bytes — the SHA-256 of the channel secret, as
    returned by `channel_key_from_secret`.  Returns None if the MAC does not
    verify (wrong key or corrupt packet).
    """
    if len(payload) < GRP_TXT_HEADER_SIZE + crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE:
        return None
    channel_hash = payload[0]
    sender_hash = payload[1]
    plaintext = crypto.mac_then_decrypt(channel_key, payload[GRP_TXT_HEADER_SIZE:])
    if plaintext is None:
        return None
    if len(plaintext) < TIMESTAMP_SIZE + ATTEMPT_SIZE + 1:
        return None
    timestamp = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    flags = plaintext[TIMESTAMP_SIZE]
    attempt = flags & ATTEMPT_MASK
    txt_type = flags >> TXT_TYPE_SHIFT
    text_bytes = plaintext[TIMESTAMP_SIZE + ATTEMPT_SIZE:]
    null_at = text_bytes.find(b"\x00")
    if null_at >= 0:
        text_bytes = text_bytes[:null_at]
    return GrpTxtMsg(
        channel_hash=channel_hash,
        sender_hash=sender_hash,
        timestamp=timestamp,
        attempt=attempt,
        text=text_bytes.decode("utf-8", errors="replace"),
        txt_type=txt_type,
    )


def compose_plaintext(
    timestamp: int, attempt: int, text: str, txt_type: int = TXT_TYPE_PLAIN
) -> bytes:
    """Build the inner plaintext blob: timestamp(4) | flags(1) | text | null."""
    return (
        timestamp.to_bytes(TIMESTAMP_SIZE, "little")
        + bytes([encode_flags_byte(attempt, txt_type)])
        + text.encode("utf-8")
        + b"\x00"
    )


def ack_hash_for(
    timestamp: int,
    attempt: int,
    text: str,
    sender_pub_key: bytes,
    txt_type: int = TXT_TYPE_PLAIN,
) -> bytes:
    """The 4-byte ACK hash the recipient must echo to acknowledge this message.

    Hashes `timestamp(4) | flags(1) | text` (no null terminator) concatenated
    with the sender's full 32-byte public key. The flags byte must include the
    message's `txt_type` bits exactly as the sender transmitted them, otherwise
    the recomputed ACK will not match what the sender expects (this matters for
    any non-PLAIN message type).
    """
    msg = (
        timestamp.to_bytes(TIMESTAMP_SIZE, "little")
        + bytes([encode_flags_byte(attempt, txt_type)])
        + text.encode("utf-8")
    )
    return crypto.sha256(msg + sender_pub_key)[:ACK_HASH_SIZE]


def build_txt_msg_payload(
    shared_secret: bytes,
    dest_hash: int,
    src_hash: int,
    timestamp: int,
    attempt: int,
    text: str,
) -> bytes:
    """Build the bytes that go into a PAYLOAD_TYPE_TXT_MSG packet's payload."""
    plaintext = compose_plaintext(timestamp, attempt, text)
    sealed = crypto.encrypt_then_mac(shared_secret, plaintext)
    return bytes([dest_hash & 0xFF, src_hash & 0xFF]) + sealed


def build_path_plaintext(
    path: bytes,
    hash_size: int,
    extra_type: int = 0xFF,
    extra: bytes | None = None,
) -> bytes:
    if extra is None:
        extra = os.urandom(4)
    from .packet import encode_path_len

    if len(path) % hash_size != 0:
        raise ValueError("path length is not a multiple of hash_size")
    return bytes([encode_path_len(len(path) // hash_size, hash_size)]) + path + bytes(
        [extra_type & 0xFF]
    ) + extra


def build_path_payload(
    shared_secret: bytes,
    dest_hash: int,
    src_hash: int,
    path: bytes,
    hash_size: int,
    extra_type: int = 0xFF,
    extra: bytes | None = None,
) -> bytes:
    plaintext = build_path_plaintext(path, hash_size, extra_type, extra)
    sealed = crypto.encrypt_then_mac(shared_secret, plaintext)
    return bytes([dest_hash & 0xFF, src_hash & 0xFF]) + sealed


def try_decrypt_txt_msg(payload: bytes, shared_secret: bytes) -> TxtMsg | None:
    """Try to decrypt a TXT_MSG payload using the given shared secret.

    Returns the `TxtMsg` if the MAC verifies; `None` otherwise (caller can
    try other candidate contacts).
    """
    if len(payload) < TXT_MSG_HEADER_SIZE + crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE:
        return None
    dest_hash = payload[0]
    src_hash = payload[1]
    sealed = payload[TXT_MSG_HEADER_SIZE:]
    plaintext = crypto.mac_then_decrypt(shared_secret, sealed)
    if plaintext is None:
        return None
    if len(plaintext) < TIMESTAMP_SIZE + ATTEMPT_SIZE + 1:
        return None
    timestamp = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    flags = plaintext[TIMESTAMP_SIZE]
    attempt = flags & ATTEMPT_MASK
    txt_type = flags >> TXT_TYPE_SHIFT
    text_bytes = plaintext[TIMESTAMP_SIZE + ATTEMPT_SIZE :]
    # Strip the null terminator and any trailing zero padding.
    null_at = text_bytes.find(b"\x00")
    if null_at >= 0:
        text_bytes = text_bytes[:null_at]
    text = text_bytes.decode("utf-8", errors="replace")
    return TxtMsg(
        dest_hash=dest_hash,
        src_hash=src_hash,
        timestamp=timestamp,
        attempt=attempt,
        text=text,
        txt_type=txt_type,
    )


def try_decrypt_path_msg(payload: bytes, shared_secret: bytes) -> PathMsg | None:
    if len(payload) < TXT_MSG_HEADER_SIZE + crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE:
        return None
    dest_hash = payload[0]
    src_hash = payload[1]
    plaintext = crypto.mac_then_decrypt(shared_secret, payload[TXT_MSG_HEADER_SIZE:])
    if plaintext is None or len(plaintext) < 2:
        return None

    from .packet import decode_path_len

    hash_count, hash_size = decode_path_len(plaintext[0])
    path_len = hash_count * hash_size
    if len(plaintext) < 1 + path_len + 1:
        return None
    path = plaintext[1 : 1 + path_len]
    extra_type = plaintext[1 + path_len] & 0x0F
    extra = plaintext[2 + path_len :]
    if extra_type == PayloadType.ACK and len(extra) >= ACK_HASH_SIZE:
        extra = extra[:ACK_HASH_SIZE]
    else:
        extra = extra.rstrip(b"\x00")
    return PathMsg(
        dest_hash=dest_hash,
        src_hash=src_hash,
        path=path,
        hash_size=hash_size,
        extra_type=extra_type,
        extra=extra,
    )


def try_decrypt_req_msg(payload: bytes, shared_secret: bytes) -> ReqMsg | None:
    if len(payload) < TXT_MSG_HEADER_SIZE + crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE:
        return None
    dest_hash = payload[0]
    src_hash = payload[1]
    plaintext = crypto.mac_then_decrypt(shared_secret, payload[TXT_MSG_HEADER_SIZE:])
    if plaintext is None or len(plaintext) < TIMESTAMP_SIZE + 1:
        return None
    timestamp = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    return ReqMsg(
        dest_hash=dest_hash,
        src_hash=src_hash,
        timestamp=timestamp,
        data=plaintext[TIMESTAMP_SIZE:].rstrip(b"\x00"),
    )


def build_txt_msg_packet(
    shared_secret: bytes,
    dest_pub_key: bytes,
    src_pub_key: bytes,
    timestamp: int,
    text: str,
    attempt: int = 0,
    route_type: RouteType = RouteType.FLOOD,
    path: bytes = b"",
    hash_size: int = 1,
) -> Packet:
    """Construct a fully-formed direct text message Packet."""
    payload = build_txt_msg_payload(
        shared_secret=shared_secret,
        dest_hash=crypto.path_hash(dest_pub_key),
        src_hash=crypto.path_hash(src_pub_key),
        timestamp=timestamp,
        attempt=attempt,
        text=text,
    )
    return Packet(
        route_type=route_type,
        payload_type=PayloadType.TXT_MSG,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=path,
        payload=payload,
        hash_size=hash_size,
    )


def build_path_packet(
    shared_secret: bytes,
    dest_hash: int,
    src_pub_key: bytes,
    path_payload: bytes,
    path_hash_size: int,
    extra_type: int = 0xFF,
    extra: bytes | None = None,
    route_type: RouteType = RouteType.FLOOD,
    route_path: bytes = b"",
    route_hash_size: int = 1,
) -> Packet:
    payload = build_path_payload(
        shared_secret=shared_secret,
        dest_hash=dest_hash,
        src_hash=crypto.path_hash(src_pub_key),
        path=path_payload,
        hash_size=path_hash_size,
        extra_type=extra_type,
        extra=extra,
    )
    return Packet(
        route_type=route_type,
        payload_type=PayloadType.PATH,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=route_path,
        payload=payload,
        hash_size=route_hash_size,
    )


def reverse_path(path: bytes, hash_size: int) -> bytes:
    """Reverse a MeshCore path byte string while preserving hash-sized entries."""
    if not path:
        return b""
    if not 1 <= hash_size <= 4:
        raise ValueError("hash_size must be in 1..4")
    if len(path) % hash_size != 0:
        raise ValueError("path length is not a multiple of hash_size")
    entries = [path[i : i + hash_size] for i in range(0, len(path), hash_size)]
    return b"".join(reversed(entries))


async def deliver_txt_msg_with_ack(
    *,
    publish: Callable[[bytes], Awaitable[None]],
    wait_for_ack: Callable[[bytes, float], Awaitable[bool]],
    shared_secret: bytes,
    dest_pub_key: bytes,
    src_pub_key: bytes,
    text: str,
    timestamp: int,
    direct_path: bytes = b"",
    direct_hash_size: int = 1,
    direct_attempts: int = 3,
    flood_attempts: int = 3,
    ack_timeout_s: float = 8.0,
) -> DeliveryResult:
    """Send a direct text message, preferring a known return path then flooding.

    If `direct_path` is non-empty, the first `direct_attempts` sends use
    `RouteType.DIRECT` with that path. If no ACK arrives, sends `flood_attempts`
    `RouteType.FLOOD` attempts. Returns the first ACKed attempt or the final
    unacked attempt.
    """
    if direct_attempts < 0 or flood_attempts < 0:
        raise ValueError("attempt counts must be >= 0")
    if direct_path and not 1 <= direct_hash_size <= 4:
        raise ValueError("direct_hash_size must be in 1..4")

    attempts: list[tuple[RouteType, bytes, int]] = []
    if direct_path:
        attempts.extend(
            (RouteType.DIRECT, direct_path, direct_hash_size) for _ in range(direct_attempts)
        )
    attempts.extend((RouteType.FLOOD, b"", 1) for _ in range(flood_attempts))
    if not attempts:
        raise ValueError("at least one delivery attempt is required")

    last_result: DeliveryResult | None = None
    for attempt, (route_type, path, hash_size) in enumerate(attempts):
        wire_timestamp = timestamp + attempt // 4
        wire_attempt = attempt & 0x03
        pkt = build_txt_msg_packet(
            shared_secret=shared_secret,
            dest_pub_key=dest_pub_key,
            src_pub_key=src_pub_key,
            timestamp=wire_timestamp,
            attempt=wire_attempt,
            text=text,
            route_type=route_type,
            path=path,
            hash_size=hash_size,
        )
        ack_hash = ack_hash_for(wire_timestamp, wire_attempt, text, src_pub_key)
        await publish(encode_packet(pkt))
        acked = await wait_for_ack(ack_hash, ack_timeout_s)
        last_result = DeliveryResult(
            route_type=route_type,
            attempt=attempt,
            ack_hash=ack_hash,
            acked=acked,
        )
        if acked:
            return last_result
        if attempt + 1 < len(attempts):
            await asyncio.sleep(0)

    assert last_result is not None
    return last_result


def build_ack_packet(
    ack_hash: bytes,
    route_type: RouteType = RouteType.FLOOD,
) -> Packet:
    """Build a PAYLOAD_TYPE_ACK packet carrying a 4-byte hash."""
    if len(ack_hash) != ACK_HASH_SIZE:
        raise ValueError(f"ack_hash must be {ACK_HASH_SIZE} bytes")
    return Packet(
        route_type=route_type,
        payload_type=PayloadType.ACK,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=b"",
        payload=ack_hash,
    )


def parse_ack_payload(payload: bytes) -> bytes | None:
    """Return the 4-byte ACK hash from an ACK packet's payload, or None."""
    if len(payload) < ACK_HASH_SIZE:
        return None
    return payload[:ACK_HASH_SIZE]
