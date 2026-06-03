from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

import aiomqtt
from aiomqtt import MqttError, Will
from softmesh_stack.advert import AdvertData, AdvertType, encode_advert
from softmesh_stack.identity import Identity, resolve_identity
from softmesh_stack.mqtt import MqttConfig
from softmesh_stack.packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    decode_packet,
    decode_path_len,
    encode_packet,
)

from .auth import auth_username, build_auth_token
from .config import ObserverConfig

log = logging.getLogger(__name__)

# Single-letter route codes used by the Cornmeister / mc-radar collectors
# (mctomqtt.py convention): TRANSPORT_DIRECT is reported as "T", everything else
# floods as "F" / directs as "D"; unknown route types fall back to "U".
_ROUTE_MAP: dict[int, str] = {
    RouteType.TRANSPORT_FLOOD: "F",
    RouteType.FLOOD: "F",
    RouteType.DIRECT: "D",
    RouteType.TRANSPORT_DIRECT: "T",
}

_PAYLOAD_TYPE_TRACE = 0x09


def calculate_packet_hash(raw: bytes, payload_type: int | None = None) -> str:
    """Replicate MeshCore ``Packet::calculatePacketHash()``.

    SHA-256 over ``payload_type(1) [+ path_len(2, LE) for TRACE] + payload``,
    returned as the first 16 hex chars uppercased — the packet identifier the
    collectors dedupe on.
    """
    try:
        header = raw[0]
        if payload_type is None:
            payload_type = (header >> 2) & 0x0F
        route_type = header & 0x03
        has_transport = route_type in (0x00, 0x03)  # TRANSPORT_FLOOD / TRANSPORT_DIRECT
        offset = 1 + (4 if has_transport else 0)
        if len(raw) <= offset:
            return "0000000000000000"
        path_len_byte = raw[offset]
        offset += 1
        hash_count, hash_size = decode_path_len(path_len_byte)
        payload_start = offset + hash_count * hash_size
        if payload_start > len(raw):
            return "0000000000000000"
        payload_data = raw[payload_start:]
        h = hashlib.sha256()
        h.update(bytes([payload_type]))
        if payload_type == _PAYLOAD_TYPE_TRACE:
            h.update(path_len_byte.to_bytes(2, byteorder="little"))
        h.update(payload_data)
        return h.hexdigest()[:16].upper()
    except Exception as exc:  # pragma: no cover - defensive, mirrors reference impl
        log.debug("hash calculation failed: %s", exc)
        return "0000000000000000"


def build_event(raw: bytes, *, origin: str, origin_id: str) -> dict[str, Any]:
    """Build a flat packet event in the Cornmeister / mc-radar (mctomqtt) schema.

    The local bus only carries raw frame bytes, so SNR/RSSI are reported as
    "Unknown" (the gateway does not surface RF metadata on ``mesh/rx``).
    """
    now = datetime.now()
    packet_len = len(raw)

    route = "U"
    packet_type = "0"
    payload_len = "0"
    path_field: str | None = None

    pkt = None
    try:
        pkt = decode_packet(raw)
    except ValueError as exc:
        log.debug("packet decode failed (forwarding raw anyway): %s", exc)

    if pkt is not None:
        route = _ROUTE_MAP.get(pkt.route_type, "U")
        payload_type_value = int(pkt.payload_type)
        packet_type = str(payload_type_value)
        payload_len = str(len(pkt.payload))
        if route == "D" and pkt.path:
            hs = pkt.hash_size
            path_field = ",".join(
                pkt.path[i : i + hs].hex() for i in range(0, len(pkt.path), hs)
            )
    else:
        header = raw[0] if raw else 0
        payload_type_value = (header >> 2) & 0x0F
        packet_type = str(payload_type_value)
        payload_len = str(max(0, packet_len - 1))

    event: dict[str, Any] = {
        "origin": origin,
        "origin_id": origin_id,
        "timestamp": now.isoformat(),
        "type": "PACKET",
        "direction": "rx",
        "time": now.strftime("%H:%M:%S"),
        "date": now.strftime("%d/%m/%Y"),
        "len": str(packet_len),
        "packet_type": packet_type,
        "route": route,
        "payload_len": payload_len,
        "raw": raw.hex().upper(),
        "SNR": "Unknown",
        "RSSI": "Unknown",
        "hash": calculate_packet_hash(raw, payload_type_value),
    }
    if path_field is not None:
        event["path"] = path_field
    return event


async def _publish_event(
    client: aiomqtt.Client, topic: str, event: dict[str, Any], label: str
) -> None:
    payload = json.dumps(event, separators=(",", ":")).encode()
    await client.publish(topic, payload)
    log.debug("published to %s topic=%s bytes=%d", label, topic, len(payload))


def build_self_advert(
    identity: Identity,
    *,
    name: str,
    lat: float | None,
    lon: float | None,
    flood: bool,
) -> bytes:
    """Signed ADVERT packet announcing this observer's name and (optional) location.

    Analyzers read a node's name and position from its advert, so broadcasting
    one is how the observer shows up as a named, located node on the map.
    """
    app = AdvertData(type=AdvertType.CHAT, name=name, lat=lat, lon=lon)
    payload = encode_advert(identity.seed, identity.pub_key, int(time.time()), app)
    pkt = Packet(
        route_type=RouteType.FLOOD if flood else RouteType.DIRECT,
        payload_type=PayloadType.ADVERT,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=b"",
        payload=payload,
    )
    return encode_packet(pkt)


def _status_payload(
    status: str,
    *,
    origin: str,
    origin_id: str,
    lat: float | None = None,
    lon: float | None = None,
) -> bytes:
    """Retained status announcement; analyzers list observers from this topic.

    When configured, the observer's fixed location is reported here as flat
    ``latitude``/``longitude`` (the shape the analyzers' node API resolves), so
    the observer is placed on the map without transmitting anything on-air.
    """
    payload: dict[str, Any] = {
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "origin": origin,
        "origin_id": origin_id,
    }
    if lat is not None and lon is not None:
        payload["latitude"] = lat
        payload["longitude"] = lon
    return json.dumps(payload, separators=(",", ":")).encode()


class _ForwardTarget:
    def __init__(
        self,
        *,
        config: MqttConfig,
        topic: str,
        label: str,
        status_topic: str,
        origin: str,
        origin_id: str,
        lat: float | None = None,
        lon: float | None = None,
        auth_factory: Callable[[], tuple[str, str]] | None = None,
    ) -> None:
        self.config = config
        self.topic = topic
        self.label = label
        self.status_topic = status_topic
        self.origin = origin
        self.origin_id = origin_id
        self.lat = lat
        self.lon = lon
        # Builds a fresh (username, JWT) pair on each connect so expiring tokens
        # are renewed on reconnect. Skipped if the config already carries an
        # explicit username (env override wins).
        self._auth_factory = auth_factory if config.username is None else None
        self.client: aiomqtt.Client | None = None
        self._backoff = 5.0
        self._next_retry = 0.0

    async def _connect(self) -> bool:
        now = asyncio.get_running_loop().time()
        if now < self._next_retry:
            return False
        overrides: dict[str, Any] = {}
        if self._auth_factory is not None:
            username, password = self._auth_factory()
            overrides = {"username": username, "password": password}
        # LWT: brokers flip us to "offline" on this retained status topic if the
        # connection drops without a clean disconnect.
        overrides["will"] = Will(
            topic=self.status_topic,
            payload=_status_payload(
                "offline", origin=self.origin, origin_id=self.origin_id, lat=self.lat, lon=self.lon
            ),
            qos=0,
            retain=True,
        )
        client = self.config.client(**overrides)
        try:
            await client.__aenter__()
        except MqttError as exc:
            log.warning(
                "failed to connect to %s broker %s:%d (%s); retrying in %ds",
                self.label,
                self.config.host,
                self.config.port,
                exc,
                int(self._backoff),
            )
            self._next_retry = now + self._backoff
            self._backoff = min(self._backoff * 2, 300.0)
            return False
        self.client = client
        self._backoff = 5.0
        self._next_retry = 0.0
        log.info("connected to %s broker %s:%d", self.label, self.config.host, self.config.port)
        # Retained "online" announcement so analyzers list this observer.
        try:
            await client.publish(
                self.status_topic,
                _status_payload(
                    "online",
                    origin=self.origin,
                    origin_id=self.origin_id,
                    lat=self.lat,
                    lon=self.lon,
                ),
                retain=True,
            )
            log.info("announced online status to %s topic=%s", self.label, self.status_topic)
        except MqttError as exc:
            log.warning("status announce to %s failed (%s)", self.label, exc)
        return True

    async def publish(self, event: dict[str, Any]) -> None:
        if self.client is None and not await self._connect():
            return
        assert self.client is not None
        try:
            await _publish_event(self.client, self.topic, event, self.label)
        except MqttError as exc:
            log.warning("publish to %s failed (%s); reconnecting", self.label, exc)
            await self.close()

    async def close(self) -> None:
        if self.client is not None:
            await self.client.__aexit__(None, None, None)
            self.client = None


async def run(config: ObserverConfig) -> None:
    identity: Identity
    identity, source = resolve_identity(
        config.identity_seed, config.identity_path, name="observer"
    )
    origin = config.name or identity.name or "softmesh-observer"
    origin_id = identity.pub_key.hex().upper()
    log.info(
        "identity (%s): origin=%s pub=%s addr=%#04x",
        source,
        origin,
        identity.pub_key[:8].hex() + "…",
        identity.address,
    )

    # Self-signed MeshCore token proving ownership of the observer pubkey; the
    # collector brokers reject anonymous connects with code 135 ("Not
    # authorized"). The JWT `aud` claim must match the broker's expected
    # audience — for the DutchMeshCore collectors that is the broker's own
    # hostname (and differs per broker), so default each target's audience to
    # its host unless OBSERVER_TOKEN_AUDIENCE overrides it. Rebuilt on each
    # connect so the (expiring) token is refreshed on reconnect.
    def make_auth_factory(audience: str | None) -> Callable[[], tuple[str, str]]:
        def factory() -> tuple[str, str]:
            return auth_username(identity), build_auth_token(identity, aud=audience)

        return factory

    status_topic = config.status_topic(identity.pub_key)

    forwarders: list[_ForwardTarget] = []
    async with config.mqtt_local.client() as local:
        topic_corn = config.cornmeister_topic(identity.pub_key)
        topic_radar = config.radar_topic(identity.pub_key)
        if config.enable_cornmeister:
            forwarders.append(
                _ForwardTarget(
                    config=config.mqtt_cornmeister,
                    topic=topic_corn,
                    label="cornmeister",
                    status_topic=status_topic,
                    origin=origin,
                    origin_id=origin_id,
                    lat=config.lat,
                    lon=config.lon,
                    auth_factory=make_auth_factory(
                        config.token_audience or config.mqtt_cornmeister.host
                    ),
                )
            )
        if config.enable_radar:
            forwarders.append(
                _ForwardTarget(
                    config=config.mqtt_radar,
                    topic=topic_radar,
                    label="radar",
                    status_topic=status_topic,
                    origin=origin,
                    origin_id=origin_id,
                    lat=config.lat,
                    lon=config.lon,
                    auth_factory=make_auth_factory(
                        config.token_audience or config.mqtt_radar.host
                    ),
                )
            )
        await local.subscribe(config.rx_topic)
        log.info(
            "listening on %s; forwarding to %s%s",
            config.rx_topic,
            topic_corn if config.enable_cornmeister else "(cornmeister disabled)",
            f", {topic_radar}" if config.enable_radar else "",
        )
        uploaded_messages = 0

        async def forward_loop() -> None:
            nonlocal uploaded_messages
            async for msg in local.messages:
                payload = bytes(msg.payload) if isinstance(msg.payload, (bytes, bytearray)) else b""
                if not payload:
                    continue
                event = build_event(payload, origin=origin, origin_id=origin_id)
                publish_tasks = [f.publish(event) for f in forwarders]
                if publish_tasks:
                    await asyncio.gather(*publish_tasks, return_exceptions=False)
                    uploaded_messages += 1

        async def upload_stats_loop() -> None:
            nonlocal uploaded_messages
            while True:
                await asyncio.sleep(600)
                log.info("uploaded %d messages in the last 10 minutes", uploaded_messages)
                uploaded_messages = 0

        async def advertise_loop() -> None:
            # Broadcast a signed self-advert (name + optional location) on mesh/tx
            # so the gateway transmits it and analyzers list us as a located node.
            while True:
                wire = build_self_advert(
                    identity,
                    name=origin,
                    lat=config.lat,
                    lon=config.lon,
                    flood=config.advert_flood,
                )
                log.info(
                    "broadcasting %s self-advert as %r (%d bytes)%s",
                    "flood" if config.advert_flood else "zero-hop",
                    origin,
                    len(wire),
                    f" at {config.lat},{config.lon}" if config.lat is not None else "",
                )
                await local.publish(config.tx_topic, wire)
                await asyncio.sleep(config.advert_interval_s)

        tasks = [asyncio.create_task(forward_loop()), asyncio.create_task(upload_stats_loop())]
        if config.advert_interval_s > 0:
            tasks.append(asyncio.create_task(advertise_loop()))
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            for forwarder in forwarders:
                await forwarder.close()