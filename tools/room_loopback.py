"""Internal loopback test for the room server (no radio; MQTT only).

Drives the full room flow against a running room-server:
  1. Read the room's pub_key from the retained mesh/identities/room-server topic.
  2. Client A logs in (ANON_REQ) -> expect a RESPONSE with LOGIN_OK.
  3. Client A posts a TXT_MSG -> expect the room's ACK.
  4. Client B logs in -> expect the room to push A's stored post to B.

Start the room first with a known guest password, e.g.:
    ROOM_GUEST_PASSWORD=guestpw uv run room-server -vv
then:
    uv run python tools/room_loopback.py --password guestpw
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

import aiomqtt
from softmesh_stack import crypto
from softmesh_stack.messaging import (
    ack_hash_for,
    build_txt_msg_packet,
    parse_ack_payload,
    try_decrypt_path_msg,
)
from softmesh_stack.packet import PayloadType, RouteType, decode_packet, encode_packet
from softmesh_stack.room import (
    RESP_SERVER_LOGIN_OK,
    build_anon_login_packet,
    try_decrypt_login_response,
    try_decrypt_room_push,
)


async def _get_room_pub_key(host: str, port: int) -> bytes:
    async with aiomqtt.Client(hostname=host, port=port) as c:
        await c.subscribe("mesh/identities/room-server")
        msg = await asyncio.wait_for(anext(aiter(c.messages)), timeout=5)
        info = json.loads(bytes(msg.payload))
        return bytes.fromhex(info["pub_key"])


async def _wait_for(it, match, timeout: float):
    async with asyncio.timeout(timeout):
        while True:
            raw = await anext(it)
            payload = bytes(raw.payload) if isinstance(raw.payload, (bytes, bytearray)) else b""
            try:
                pkt = decode_packet(payload)
            except ValueError:
                continue
            res = match(pkt)
            if res:
                return res


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--password", default="guestpw", help="must match ROOM_GUEST/ADMIN_PASSWORD")
    ap.add_argument("--text", default="hello room from loopback")
    args = ap.parse_args()

    room_pub = await _get_room_pub_key(args.host, args.port)
    print(f"room pub_key   : {room_pub.hex()}")
    print(f"room path_hash : {room_pub[0]:#04x}")

    a_seed, a_pub = crypto.generate_keypair()
    b_seed, b_pub = crypto.generate_keypair()
    shared_a = crypto.calc_shared_secret(a_seed, room_pub)
    shared_b = crypto.calc_shared_secret(b_seed, room_pub)

    async with aiomqtt.Client(hostname=args.host, port=args.port) as c:
        await c.subscribe("mesh/tx")
        it = aiter(c.messages)

        # --- Phase 1: client A logs in -------------------------------------- #
        login = build_anon_login_packet(
            shared_secret=shared_a,
            room_hash=room_pub[0],
            client_pub_key=a_pub,
            timestamp=int(time.time()),
            sync_since=0,
            password=args.password,
        )
        await c.publish("mesh/rx", encode_packet(login))
        print("A: sent ANON_REQ login")

        def match_resp(pkt):
            if pkt.payload_type != PayloadType.RESPONSE or pkt.payload[:1] != bytes([a_pub[0]]):
                return None
            return try_decrypt_login_response(pkt.payload, shared_a)

        resp = await _wait_for(it, match_resp, timeout=5)
        if resp.status != RESP_SERVER_LOGIN_OK:
            print(f"A: login NOT ok, status={resp.status}")
            return 1
        print(f"A: login OK (admin={resp.is_admin})")

        # --- Phase 2: client A posts a message ------------------------------ #
        ts = int(time.time())
        post = build_txt_msg_packet(
            shared_secret=shared_a,
            dest_pub_key=room_pub,
            src_pub_key=a_pub,
            timestamp=ts,
            text=args.text,
            attempt=0,
            route_type=RouteType.DIRECT,  # direct -> room replies with a plain ACK
        )
        expected_ack = ack_hash_for(ts, 0, args.text, a_pub)
        await c.publish("mesh/rx", encode_packet(post))
        print(f"A: posted {args.text!r}, expecting ack={expected_ack.hex()}")

        def match_ack(pkt):
            if pkt.payload_type == PayloadType.ACK:
                return parse_ack_payload(pkt.payload) == expected_ack or None
            if pkt.payload_type == PayloadType.PATH and pkt.payload[:1] == bytes([a_pub[0]]):
                pm = try_decrypt_path_msg(pkt.payload, shared_a)
                if pm and pm.extra_type == PayloadType.ACK and pm.extra == expected_ack:
                    return True
            return None

        await _wait_for(it, match_ack, timeout=5)
        print("A: post ACKed by room")

        # --- Phase 3: client B logs in and should receive A's post ---------- #
        login_b = build_anon_login_packet(
            shared_secret=shared_b,
            room_hash=room_pub[0],
            client_pub_key=b_pub,
            timestamp=int(time.time()),
            sync_since=0,
            password=args.password,
        )
        await c.publish("mesh/rx", encode_packet(login_b))
        print("B: sent ANON_REQ login; awaiting pushed post")

        def match_push(pkt):
            if pkt.payload_type != PayloadType.TXT_MSG or pkt.payload[:1] != bytes([b_pub[0]]):
                return None
            return try_decrypt_room_push(pkt.payload, shared_b)

        push = await _wait_for(it, match_push, timeout=8)
        print(f"B: received pushed post: text={push.text!r} author={push.author_prefix.hex()}")
        if push.text != args.text:
            print("B: pushed text did NOT match the original post")
            return 1

    print("\nROOM LOOPBACK OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except TimeoutError:
        print("TIMEOUT waiting for room server response")
        sys.exit(2)
