"""mesh-sniff: subscribe to the gateway's mesh/rx topic and print decoded packets.

Used to verify that the codec works against real on-air traffic.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import UTC, datetime

import aiomqtt
from softmesh_stack.advert import decode_advert
from softmesh_stack.packet import PayloadType, decode_packet

from .config import GatewayConfig

log = logging.getLogger(__name__)


def _format_packet_summary(raw: bytes) -> str:
    try:
        pkt = decode_packet(raw)
    except ValueError as e:
        return f"undecodable ({e}); {len(raw)} bytes: {raw.hex()}"

    parts = [
        f"route={getattr(pkt.route_type, 'name', pkt.route_type)}",
        f"type={getattr(pkt.payload_type, 'name', pkt.payload_type)}",
        f"ver={getattr(pkt.payload_ver, 'name', pkt.payload_ver)}",
        f"hash_size={pkt.hash_size}",
        f"hops={pkt.hash_count}",
        f"payload={len(pkt.payload)}B",
    ]
    if pkt.transport_codes is not None:
        parts.append(f"tc=({pkt.transport_codes[0]:#06x},{pkt.transport_codes[1]:#06x})")

    if pkt.payload_type == PayloadType.ADVERT:
        try:
            advert = decode_advert(pkt.payload)
            ad = advert.app_data
            parts.append(f"pub={advert.pub_key[:4].hex()}…")
            parts.append(f"ts={advert.timestamp}")
            parts.append(f"adv_type={getattr(ad.type, 'name', ad.type)}")
            if ad.name:
                parts.append(f"name={ad.name!r}")
            if ad.lat is not None and ad.lon is not None:
                parts.append(f"pos=({ad.lat:.6f},{ad.lon:.6f})")
            parts.append(f"sig_valid={advert.signature_valid}")
        except ValueError as e:
            parts.append(f"advert decode failed: {e}")

    return " ".join(parts)


async def _run(config: GatewayConfig, topic: str) -> None:
    mqtt = config.mqtt
    async with aiomqtt.Client(
        hostname=mqtt.host,
        port=mqtt.port,
        username=mqtt.username,
        password=mqtt.password,
        tls_params=aiomqtt.TLSParameters() if mqtt.use_tls else None,
    ) as client:
        log.info("subscribed to %s on %s:%d", topic, mqtt.host, mqtt.port)
        await client.subscribe(topic)
        async for msg in client.messages:
            payload = bytes(msg.payload) if isinstance(msg.payload, (bytes, bytearray)) else b""
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            summary = _format_packet_summary(payload)
            print(f"[{ts}] {summary}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(prog="mesh-sniff", description=__doc__)
    parser.add_argument("--mqtt-url", default=None)
    parser.add_argument("--topic", default="mesh/rx")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()

    logging.basicConfig(
        level=max(logging.WARNING - 10 * args.verbose, logging.DEBUG),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    import os

    if args.mqtt_url:
        os.environ["MESH_GATEWAY_MQTT_URL"] = args.mqtt_url
    config = GatewayConfig.from_env()
    try:
        asyncio.run(_run(config, args.topic))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
