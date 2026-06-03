"""Tests for room-server protocol handling (PATH+ACK push confirmation)."""

from __future__ import annotations

import asyncio

from softmesh_stack import crypto
from softmesh_stack.identity import Identity
from softmesh_stack.messaging import build_path_packet
from softmesh_stack.packet import PayloadType, RouteType
from room_server.config import RoomConfig
from room_server.db import RoomStore
from room_server.protocol import ClientSession, RoomServer


def _make_server() -> tuple[RoomServer, Identity]:
    room = Identity.generate(name="py-room")
    server = RoomServer(config=RoomConfig.from_env(), identity=room, store=RoomStore(":memory:"))
    return server, room


def _add_session(server: RoomServer, client_pub: bytes) -> ClientSession:
    session = ClientSession(pub_key=client_pub, name="client", is_admin=False)
    server._sessions[client_pub] = session
    server._by_hash[crypto.path_hash(client_pub)].add(client_pub)
    return session


async def test_path_ack_confirms_push_and_learns_route() -> None:
    server, room = _make_server()
    client_seed, client_pub = crypto.generate_keypair()
    session = _add_session(server, client_pub)
    shared = crypto.calc_shared_secret(client_seed, room.pub_key)

    ack = b"\x01\x02\x03\x04"
    # A client answering a flood push sends a PATH carrying the route + the ACK.
    path_pkt = build_path_packet(
        shared_secret=shared,
        dest_hash=room.address,
        src_pub_key=client_pub,
        path_payload=bytes([0xAA, 0xBB]),
        path_hash_size=1,
        extra_type=PayloadType.ACK,
        extra=ack,
    )

    # A push is waiting on this ACK.
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bool] = loop.create_future()
    server._ack_waiters[ack].append(fut)

    await server.handle_path(path_pkt, mqtt=None)  # type: ignore[arg-type]

    assert fut.done() and fut.result() is True
    # And the room learned a direct route to the client for future pushes.
    assert session.route_type == RouteType.DIRECT
    assert session.path == bytes([0xAA, 0xBB])


async def test_path_to_other_address_is_ignored() -> None:
    server, room = _make_server()
    client_seed, client_pub = crypto.generate_keypair()
    _add_session(server, client_pub)
    shared = crypto.calc_shared_secret(client_seed, room.pub_key)

    ack = b"\x09\x09\x09\x09"
    # Addressed to a different node (dest_hash != room.address) -> ignored before decrypt.
    path_pkt = build_path_packet(
        shared_secret=shared,
        dest_hash=(room.address + 1) & 0xFF,
        src_pub_key=client_pub,
        path_payload=b"\xaa",
        path_hash_size=1,
        extra_type=PayloadType.ACK,
        extra=ack,
    )
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bool] = loop.create_future()
    server._ack_waiters[ack].append(fut)

    await server.handle_path(path_pkt, mqtt=None)  # type: ignore[arg-type]

    assert not fut.done()  # not ours -> not resolved
