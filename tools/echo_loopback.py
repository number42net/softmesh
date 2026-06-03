"""Internal loopback test for the echo server.

Pretends to be a MeshCore client ("test-app") sending a direct message to the
running echo server. Does NOT use the radio — talks straight to MQTT.

Flow:
  1. Read the echo server's pub_key from the retained
     mesh/identities/home-auto-client status topic.
  2. Generate a throwaway "test-app" identity.
  3. Subscribe to mesh/tx so we see the gateway-bound traffic.
  4. Publish a signed ADVERT for test-app to mesh/rx so the echo server learns
     us as a contact.
  5. Publish an encrypted TXT_MSG from test-app to echo-server to mesh/rx.
  6. Watch mesh/tx for the ACK + echoed reply; decrypt the reply.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

import aiomqtt
from softmesh_stack import crypto
from softmesh_stack.advert import AdvertData, AdvertType, encode_advert
from softmesh_stack.messaging import (
    ack_hash_for,
    build_txt_msg_packet,
    parse_ack_payload,
    try_decrypt_txt_msg,
)
from softmesh_stack.packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    decode_packet,
    encode_packet,
)


async def _get_echo_pub_key(host: str, port: int) -> bytes:
    async with aiomqtt.Client(hostname=host, port=port) as c:
        await c.subscribe("mesh/identities/home-auto-client")
        msg = await asyncio.wait_for(anext(c.messages.__aiter__()), timeout=5)
        info = json.loads(bytes(msg.payload))
        return bytes.fromhex(info["pub_key"])


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--text", default="hello from loopback")
    args = ap.parse_args()

    echo_pub = await _get_echo_pub_key(args.host, args.port)
    print(f"echo server pub_key   : {echo_pub.hex()}")
    print(f"echo server path_hash : {echo_pub[0]:#04x}")

    test_seed, test_pub = crypto.generate_keypair()
    print(f"test-app pub_key      : {test_pub.hex()}")
    print(f"test-app path_hash    : {test_pub[0]:#04x}")

    shared = crypto.calc_shared_secret(test_seed, echo_pub)
    expected_ack = ack_hash_for(
        timestamp=int(time.time()), attempt=0, text=args.text, sender_pub_key=test_pub
    )

    async with aiomqtt.Client(hostname=args.host, port=args.port) as c:
        await c.subscribe("mesh/tx")

        # Step 1: send test-app's ADVERT so the echo server learns us
        ts = int(time.time())
        advert_payload = encode_advert(
            test_seed, test_pub, ts, AdvertData(type=AdvertType.CHAT, name="loopback-app")
        )
        advert_pkt = Packet(
            route_type=RouteType.FLOOD,
            payload_type=PayloadType.ADVERT,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=b"",
            payload=advert_payload,
        )
        await c.publish("mesh/rx", encode_packet(advert_pkt))
        print("sent test-app advert via mesh/rx")
        await asyncio.sleep(0.5)

        # Step 2: send encrypted TXT_MSG from test-app to echo-server
        ts = int(time.time())
        msg_pkt = build_txt_msg_packet(
            shared_secret=shared,
            dest_pub_key=echo_pub,
            src_pub_key=test_pub,
            timestamp=ts,
            text=args.text,
            attempt=0,
        )
        # Recompute expected ack to match the actual timestamp used.
        expected_ack = ack_hash_for(
            timestamp=ts, attempt=0, text=args.text, sender_pub_key=test_pub
        )
        await c.publish("mesh/rx", encode_packet(msg_pkt))
        print(f"sent TXT_MSG to echo server: {args.text!r}")
        print(f"expecting ACK hash    : {expected_ack.hex()}")

        # Step 3: collect responses on mesh/tx for 3 seconds
        got_ack = False
        got_echo = False
        async with asyncio.timeout(5):
            async for raw in c.messages:
                payload = bytes(raw.payload) if isinstance(raw.payload, (bytes, bytearray)) else b""
                try:
                    pkt = decode_packet(payload)
                except ValueError:
                    continue
                if pkt.payload_type == PayloadType.ACK:
                    h = parse_ack_payload(pkt.payload)
                    print(f"saw ACK packet, hash={h.hex() if h else None}")
                    if h == expected_ack:
                        got_ack = True
                        print("  ✓ ACK matches expected")
                elif pkt.payload_type == PayloadType.TXT_MSG:
                    if not pkt.payload or pkt.payload[0] != test_pub[0]:
                        continue
                    msg = try_decrypt_txt_msg(pkt.payload, shared)
                    if msg is None:
                        print("  saw TXT_MSG to us but decrypt failed")
                        continue
                    print(f"saw echo reply: text={msg.text!r}")
                    got_echo = True
                if got_ack and got_echo:
                    break

        if got_ack and got_echo:
            print("\nLOOPBACK OK")
            return 0
        print(f"\nLOOPBACK FAIL — got_ack={got_ack} got_echo={got_echo}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except TimeoutError:
        print("TIMEOUT waiting for echo server response")
        sys.exit(2)
