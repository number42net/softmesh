"""Room-server protocol codecs: ANON_REQ login, login RESPONSE, and post pushes.

These build on the same encrypt-then-MAC datagram body as direct text messages
(`crypto.encrypt_then_mac` / `mac_then_decrypt`, AES-128-ECB + 2-byte HMAC). The
shared secret is `ECDH(room_seed, client_pub_key)`.

Wire formats (confirmed against meshcore-dev/MeshCore):

  ANON_REQ login (client -> room), PAYLOAD_TYPE_ANON_REQ:
    dest_hash(1) | client_pub_key(32) | encrypt_then_mac(shared, inner)
    inner: sender_ts(4 LE) | sync_since(4 LE) | password(UTF-8, null-terminated)

  RESPONSE login-OK (room -> client), PAYLOAD_TYPE_RESPONSE:
    dest_hash(1) | src_hash(1) | encrypt_then_mac(shared, inner)
    inner: server_ts(4 LE) | status(1) | reserved(1) | admin(1) | permissions(1)
         | random(4) | firmware_ver_level(1)

  Post push (room -> client), PAYLOAD_TYPE_TXT_MSG, TXT_TYPE_SIGNED_PLAIN:
    dest_hash(1) | room_hash(1) | encrypt_then_mac(shared, inner)
    inner: post_ts(4 LE) | flags(1)=(TXT_TYPE_SIGNED_PLAIN<<2)|attempt
         | author_pub_key[0:4] | text(UTF-8, null-terminated)
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from . import crypto
from .messaging import (
    ACK_HASH_SIZE,
    TXT_TYPE_SIGNED_PLAIN,
    DeliveryResult,
    encode_flags_byte,
)
from .packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    encode_packet,
)

DEST_HASH_SIZE = 1
SYNC_SINCE_SIZE = 4
TIMESTAMP_SIZE = 4
AUTHOR_PREFIX_SIZE = 4

# ANON_REQ carries the sender's full pubkey in the clear so the room can ECDH.
ANON_REQ_HEADER_SIZE = DEST_HASH_SIZE + crypto.PUB_KEY_SIZE
# dest_hash + src_hash, like a normal direct datagram.
DATAGRAM_HEADER_SIZE = 2 * crypto.PATH_HASH_SIZE

RESP_SERVER_LOGIN_OK = 0x00
FIRMWARE_VER_LEVEL = 1  # best-effort; clients ignore for basic login

# Client ACL roles, carried in the low 2 bits of the RESPONSE permissions byte
# (MeshCore ClientACL.h). A client may post to a room only with READ_WRITE or
# ADMIN; GUEST and READ_ONLY are read-only.
PERM_ACL_GUEST = 0
PERM_ACL_READ_ONLY = 1
PERM_ACL_READ_WRITE = 2
PERM_ACL_ADMIN = 3
PERM_ACL_ROLE_MASK = 3

_MIN_SEALED = crypto.CIPHER_MAC_SIZE + crypto.CIPHER_BLOCK_SIZE


# --------------------------------------------------------------------------- #
# ANON_REQ login
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class LoginReq:
    client_pub_key: bytes
    timestamp: int
    sync_since: int
    password: str


def build_anon_login_inner(timestamp: int, sync_since: int, password: str) -> bytes:
    return (
        timestamp.to_bytes(TIMESTAMP_SIZE, "little")
        + sync_since.to_bytes(SYNC_SINCE_SIZE, "little")
        + password.encode("utf-8")
        + b"\x00"
    )


def build_anon_login_payload(
    shared_secret: bytes,
    room_hash: int,
    client_pub_key: bytes,
    timestamp: int,
    sync_since: int,
    password: str,
) -> bytes:
    if len(client_pub_key) != crypto.PUB_KEY_SIZE:
        raise ValueError("client_pub_key must be 32 bytes")
    inner = build_anon_login_inner(timestamp, sync_since, password)
    sealed = crypto.encrypt_then_mac(shared_secret, inner)
    return bytes([room_hash & 0xFF]) + client_pub_key + sealed


def build_anon_login_packet(
    shared_secret: bytes,
    room_hash: int,
    client_pub_key: bytes,
    timestamp: int,
    sync_since: int,
    password: str,
    route_type: RouteType = RouteType.FLOOD,
    path: bytes = b"",
    hash_size: int = 1,
) -> Packet:
    payload = build_anon_login_payload(
        shared_secret, room_hash, client_pub_key, timestamp, sync_since, password
    )
    return Packet(
        route_type=route_type,
        payload_type=PayloadType.ANON_REQ,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=path,
        payload=payload,
        hash_size=hash_size,
    )


def try_decrypt_login(payload: bytes, room_seed: bytes) -> LoginReq | None:
    """Parse an ANON_REQ login payload using the room's identity seed.

    Returns the `LoginReq` (including the client's full pubkey) if the MAC
    verifies, else `None`. The caller is responsible for checking that
    `payload[0]` matches the room's own path hash.
    """
    if len(payload) < ANON_REQ_HEADER_SIZE + _MIN_SEALED:
        return None
    client_pub_key = payload[DEST_HASH_SIZE : DEST_HASH_SIZE + crypto.PUB_KEY_SIZE]
    sealed = payload[ANON_REQ_HEADER_SIZE:]
    # The client pubkey is attacker/traffic-controlled (anyone whose dest_hash
    # collides with ours reaches here). 32 bytes that aren't a valid Ed25519
    # point make libsodium's X25519 conversion raise, so treat any failure as a
    # non-match rather than letting it crash the server.
    try:
        shared = crypto.calc_shared_secret(room_seed, client_pub_key)
    except Exception:
        return None
    plaintext = crypto.mac_then_decrypt(shared, sealed)
    if plaintext is None or len(plaintext) < TIMESTAMP_SIZE + SYNC_SINCE_SIZE:
        return None
    timestamp = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    sync_since = int.from_bytes(
        plaintext[TIMESTAMP_SIZE : TIMESTAMP_SIZE + SYNC_SINCE_SIZE], "little"
    )
    pwd_bytes = plaintext[TIMESTAMP_SIZE + SYNC_SINCE_SIZE :]
    null_at = pwd_bytes.find(b"\x00")
    if null_at >= 0:
        pwd_bytes = pwd_bytes[:null_at]
    password = pwd_bytes.decode("utf-8", errors="replace")
    return LoginReq(
        client_pub_key=client_pub_key,
        timestamp=timestamp,
        sync_since=sync_since,
        password=password,
    )


# --------------------------------------------------------------------------- #
# Login RESPONSE
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class LoginResponse:
    server_ts: int
    status: int
    is_admin: bool
    permissions: int


def build_login_response_inner(
    server_ts: int,
    is_admin: bool,
    permissions: int = 0,
    random_blob: bytes | None = None,
) -> bytes:
    if random_blob is None:
        random_blob = os.urandom(4)
    return (
        server_ts.to_bytes(TIMESTAMP_SIZE, "little")
        + bytes([RESP_SERVER_LOGIN_OK, 0x00, 1 if is_admin else 0, permissions & 0xFF])
        + random_blob
        + bytes([FIRMWARE_VER_LEVEL])
    )


def build_login_response_payload(
    shared_secret: bytes,
    dest_hash: int,
    src_hash: int,
    server_ts: int,
    is_admin: bool,
    permissions: int = 0,
    random_blob: bytes | None = None,
) -> bytes:
    inner = build_login_response_inner(server_ts, is_admin, permissions, random_blob)
    sealed = crypto.encrypt_then_mac(shared_secret, inner)
    return bytes([dest_hash & 0xFF, src_hash & 0xFF]) + sealed


def build_login_response_packet(
    shared_secret: bytes,
    dest_hash: int,
    src_hash: int,
    server_ts: int,
    is_admin: bool,
    permissions: int = 0,
    random_blob: bytes | None = None,
    route_type: RouteType = RouteType.FLOOD,
    path: bytes = b"",
    hash_size: int = 1,
) -> Packet:
    payload = build_login_response_payload(
        shared_secret, dest_hash, src_hash, server_ts, is_admin, permissions, random_blob
    )
    return Packet(
        route_type=route_type,
        payload_type=PayloadType.RESPONSE,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=path,
        payload=payload,
        hash_size=hash_size,
    )


def try_decrypt_login_response(payload: bytes, shared_secret: bytes) -> LoginResponse | None:
    if len(payload) < DATAGRAM_HEADER_SIZE + _MIN_SEALED:
        return None
    plaintext = crypto.mac_then_decrypt(shared_secret, payload[DATAGRAM_HEADER_SIZE:])
    if plaintext is None or len(plaintext) < 8:
        return None
    server_ts = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    status = plaintext[4]
    is_admin = bool(plaintext[6])
    permissions = plaintext[7]
    return LoginResponse(
        server_ts=server_ts, status=status, is_admin=is_admin, permissions=permissions
    )


# --------------------------------------------------------------------------- #
# Post push (SIGNED_PLAIN TXT_MSG)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class RoomPush:
    post_ts: int
    attempt: int
    author_prefix: bytes
    text: str


def _room_push_inner_through_text(
    post_ts: int, attempt: int, author_pub_key: bytes, text: str
) -> bytes:
    return (
        post_ts.to_bytes(TIMESTAMP_SIZE, "little")
        + bytes([encode_flags_byte(attempt, TXT_TYPE_SIGNED_PLAIN)])
        + author_pub_key[:AUTHOR_PREFIX_SIZE]
        + text.encode("utf-8")
    )


def build_room_push_inner(post_ts: int, attempt: int, author_pub_key: bytes, text: str) -> bytes:
    return _room_push_inner_through_text(post_ts, attempt, author_pub_key, text) + b"\x00"


def room_push_ack_hash(
    post_ts: int, attempt: int, author_pub_key: bytes, text: str, dest_pub_key: bytes
) -> bytes:
    """The 4-byte ACK a client echoes back for a pushed post.

    Hashes the push inner up to (not including) the null terminator, concatenated
    with the *recipient client's* full public key. Note this differs from the
    normal TXT_MSG convention (which uses the sender's key): MeshCore's room
    server hashes the pushed-post ACK with `client->id.pub_key` (see
    `pushPostToClient` in examples/simple_room_server/MyMesh.cpp).
    """
    inner = _room_push_inner_through_text(post_ts, attempt, author_pub_key, text)
    return crypto.sha256(inner + dest_pub_key)[:ACK_HASH_SIZE]


def build_room_push_payload(
    shared_secret: bytes,
    dest_hash: int,
    room_hash: int,
    post_ts: int,
    author_pub_key: bytes,
    text: str,
    attempt: int = 0,
) -> bytes:
    inner = build_room_push_inner(post_ts, attempt, author_pub_key, text)
    sealed = crypto.encrypt_then_mac(shared_secret, inner)
    return bytes([dest_hash & 0xFF, room_hash & 0xFF]) + sealed


def build_room_push_packet(
    shared_secret: bytes,
    dest_pub_key: bytes,
    room_pub_key: bytes,
    post_ts: int,
    author_pub_key: bytes,
    text: str,
    attempt: int = 0,
    route_type: RouteType = RouteType.FLOOD,
    path: bytes = b"",
    hash_size: int = 1,
) -> Packet:
    payload = build_room_push_payload(
        shared_secret=shared_secret,
        dest_hash=crypto.path_hash(dest_pub_key),
        room_hash=crypto.path_hash(room_pub_key),
        post_ts=post_ts,
        author_pub_key=author_pub_key,
        text=text,
        attempt=attempt,
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


def try_decrypt_room_push(payload: bytes, shared_secret: bytes) -> RoomPush | None:
    if len(payload) < DATAGRAM_HEADER_SIZE + _MIN_SEALED:
        return None
    plaintext = crypto.mac_then_decrypt(shared_secret, payload[DATAGRAM_HEADER_SIZE:])
    if plaintext is None or len(plaintext) < TIMESTAMP_SIZE + 1 + AUTHOR_PREFIX_SIZE:
        return None
    post_ts = int.from_bytes(plaintext[:TIMESTAMP_SIZE], "little")
    flags = plaintext[TIMESTAMP_SIZE]
    attempt = flags & 0x03
    off = TIMESTAMP_SIZE + 1
    author_prefix = plaintext[off : off + AUTHOR_PREFIX_SIZE]
    text_bytes = plaintext[off + AUTHOR_PREFIX_SIZE :]
    null_at = text_bytes.find(b"\x00")
    if null_at >= 0:
        text_bytes = text_bytes[:null_at]
    text = text_bytes.decode("utf-8", errors="replace")
    return RoomPush(post_ts=post_ts, attempt=attempt, author_prefix=author_prefix, text=text)


async def deliver_room_push_with_ack(
    *,
    publish: Callable[[bytes], Awaitable[None]],
    wait_for_ack: Callable[[bytes, float], Awaitable[bool]],
    shared_secret: bytes,
    dest_pub_key: bytes,
    room_pub_key: bytes,
    post_ts: int,
    author_pub_key: bytes,
    text: str,
    direct_path: bytes = b"",
    direct_hash_size: int = 1,
    direct_attempts: int = 3,
    flood_attempts: int = 3,
    ack_timeout_s: float = 8.0,
) -> DeliveryResult:
    """Push one stored post to a client, preferring a known return path then flood.

    Mirrors `messaging.deliver_txt_msg_with_ack` but emits SIGNED_PLAIN push
    packets and computes the room-push ACK. `post_ts` is held fixed so the
    client can dedup the post across retries; only the attempt counter varies.
    """
    if direct_attempts < 0 or flood_attempts < 0:
        raise ValueError("attempt counts must be >= 0")

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
        wire_attempt = attempt & 0x03
        pkt = build_room_push_packet(
            shared_secret=shared_secret,
            dest_pub_key=dest_pub_key,
            room_pub_key=room_pub_key,
            post_ts=post_ts,
            author_pub_key=author_pub_key,
            text=text,
            attempt=wire_attempt,
            route_type=route_type,
            path=path,
            hash_size=hash_size,
        )
        ack_hash = room_push_ack_hash(post_ts, wire_attempt, author_pub_key, text, dest_pub_key)
        await publish(encode_packet(pkt))
        acked = await wait_for_ack(ack_hash, ack_timeout_s)
        last_result = DeliveryResult(
            route_type=route_type, attempt=attempt, ack_hash=ack_hash, acked=acked
        )
        if acked:
            return last_result
        if attempt + 1 < len(attempts):
            await asyncio.sleep(0)

    assert last_result is not None
    return last_result
