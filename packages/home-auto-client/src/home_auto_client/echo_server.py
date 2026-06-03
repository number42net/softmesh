"""Echo server: receives direct text messages and replies with the same text.

Behaviour:
  * Generates or loads a persistent Ed25519 identity from disk.
  * Periodically broadcasts a PAYLOAD_TYPE_ADVERT (CHAT/companion advert) so
    other MeshCore nodes can add it as a contact.
  * Tracks senders learned from received advertisements (`path_hash -> set of
    pub_keys`) so it can ECDH-decrypt incoming direct messages.
  * For each successfully-decrypted direct message:
      - Sends a PAYLOAD_TYPE_ACK with the message's 4-byte ack hash.
      - Sends a new PAYLOAD_TYPE_TXT_MSG echoing the original text back.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import defaultdict
from collections.abc import Iterable

import aiomqtt
from softmesh_stack import crypto
from softmesh_stack.advert import (
    AdvertData,
    AdvertType,
    decode_advert,
    encode_advert,
)
from softmesh_stack.identity import Identity, resolve_identity
from softmesh_stack.messaging import (
    build_ack_packet,
    build_path_packet,
    deliver_txt_msg_with_ack,
    parse_ack_payload,
    reverse_path,
    try_decrypt_path_msg,
    try_decrypt_req_msg,
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

from .config import EchoConfig

log = logging.getLogger(__name__)

REQ_TYPE_GET_TELEMETRY_DATA = 0x03


def _load_identity(config: EchoConfig) -> Identity:
    ident, source = resolve_identity(
        config.identity_seed, config.identity_path, config.display_name
    )
    log.info(
        "identity (%s): name=%r pub=%s address=%#04x",
        source,
        ident.name,
        ident.pub_key.hex().upper(),
        ident.address,
    )
    return ident


class EchoServer:
    def __init__(self, config: EchoConfig, identity: Identity) -> None:
        self.config = config
        self.identity = identity
        # path_hash -> {pub_key_hex: name}
        self._contacts: dict[int, dict[bytes, str]] = defaultdict(dict)
        self._recent_messages: dict[tuple[int, bytes], float] = {}
        self._recent_paths: dict[tuple[int, bytes], Packet] = {}
        self._ack_waiters: dict[bytes, list[asyncio.Future[bool]]] = defaultdict(list)
        # Last accepted advert timestamp per pub_key, to drop stale/replayed adverts.
        self._advert_ts: dict[bytes, int] = {}
        # Strong refs to in-flight echo tasks so they aren't garbage-collected.
        self._tasks: set[asyncio.Task[None]] = set()

    def known_pub_keys_for(self, path_hash: int) -> Iterable[bytes]:
        return self._contacts.get(path_hash, {}).keys()

    def add_contact(self, pub_key: bytes, name: str) -> bool:
        h = crypto.path_hash(pub_key)
        prev = self._contacts[h].get(pub_key)
        self._contacts[h][pub_key] = name
        if prev != name:
            log.info(
                "contact %s: pub=%s name=%r (path_hash=%#04x, %d candidates here)",
                "added" if prev is None else "updated",
                pub_key[:8].hex() + "…",
                name,
                h,
                len(self._contacts[h]),
            )
            return True
        return False

    def load_contact_cache(self) -> None:
        path = self.config.contact_cache_path
        if not path.exists():
            return
        try:
            raw = json.loads(path.read_text())
            contacts = raw.get("contacts", []) if isinstance(raw, dict) else []
            loaded = 0
            for item in contacts:
                if not isinstance(item, dict):
                    continue
                pub_key = bytes.fromhex(str(item.get("pub_key", "")))
                if len(pub_key) != 32:
                    continue
                name = str(item.get("name") or "cached-contact")
                self.add_contact(pub_key, name)
                loaded += 1
            if loaded:
                log.info("loaded %d cached contact(s) from %s", loaded, path)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            log.warning("could not load contact cache %s: %s", path, e)

    def save_contact_cache(self) -> None:
        path = self.config.contact_cache_path
        path.parent.mkdir(parents=True, exist_ok=True)
        contacts = [
            {"pub_key": pub_key.hex(), "name": name}
            for by_pub in self._contacts.values()
            for pub_key, name in by_pub.items()
        ]
        path.write_text(json.dumps({"contacts": contacts}, indent=2, sort_keys=True) + "\n")
        with contextlib.suppress(OSError):
            path.chmod(0o600)

    def remember_message(self, src_hash: int, ack_hash: bytes) -> bool:
        now = time.monotonic()
        cutoff = now - self.config.recent_message_ttl_s
        for key, seen_at in list(self._recent_messages.items()):
            if seen_at < cutoff:
                del self._recent_messages[key]
                self._recent_paths.pop(key, None)
        key = (src_hash, ack_hash)
        if key in self._recent_messages:
            return False
        self._recent_messages[key] = now
        return True

    def remember_path(self, src_hash: int, ack_hash: bytes, packet: Packet) -> None:
        key = (src_hash, ack_hash)
        prev = self._recent_paths.get(key)
        if prev is None or packet.hash_count > prev.hash_count:
            self._recent_paths[key] = packet

    def best_path_packet(self, src_hash: int, ack_hash: bytes, fallback: Packet) -> Packet:
        return self._recent_paths.get((src_hash, ack_hash), fallback)

    def handle_ack(self, packet: Packet) -> None:
        ack_hash = parse_ack_payload(packet.payload)
        if ack_hash is None:
            return
        waiters = self._ack_waiters.pop(ack_hash, [])
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(True)

    @staticmethod
    def is_flood(packet: Packet) -> bool:
        return packet.route_type in {RouteType.FLOOD, RouteType.TRANSPORT_FLOOD}

    async def wait_for_ack(self, ack_hash: bytes, timeout_s: float) -> bool:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._ack_waiters[ack_hash].append(fut)
        try:
            return await asyncio.wait_for(fut, timeout=timeout_s)
        except TimeoutError:
            return False
        finally:
            waiters = self._ack_waiters.get(ack_hash)
            if waiters is not None:
                with contextlib.suppress(ValueError):
                    waiters.remove(fut)
                if not waiters:
                    self._ack_waiters.pop(ack_hash, None)

    def build_self_advert(self) -> bytes:
        """Build a signed ADVERT packet representing this service.

        Uses a FLOOD route when `config.advert_flood` is set (repeaters
        re-broadcast it across the mesh) or a DIRECT zero-hop route otherwise
        (only direct RF neighbours see it).
        """
        ts = int(time.time())
        app = AdvertData(type=AdvertType.CHAT, name=self.config.display_name)
        payload = encode_advert(self.identity.seed, self.identity.pub_key, ts, app)
        pkt = Packet(
            route_type=RouteType.FLOOD if self.config.advert_flood else RouteType.DIRECT,
            payload_type=PayloadType.ADVERT,
            payload_ver=PayloadVer.V1,
            transport_codes=None,
            path=b"",
            payload=payload,
        )
        return encode_packet(pkt)

    @staticmethod
    def format_path_info(packet: Packet) -> str:
        if packet.hash_count == 0:
            path = "none"
        else:
            chunks = [
                packet.path[i : i + packet.hash_size].hex()
                for i in range(0, len(packet.path), packet.hash_size)
            ]
            path = ">".join(chunks)
        return (
            f"route={getattr(packet.route_type, 'name', packet.route_type)} "
            f"hash_size={packet.hash_size} hops={packet.hash_count} path={path}"
        )

    def handle_advert(self, packet: Packet) -> None:
        try:
            advert = decode_advert(packet.payload)
        except ValueError as e:
            log.debug("could not decode ADVERT payload: %s", e)
            return
        if advert.pub_key == self.identity.pub_key:
            return  # our own advert echoed back via the mesh — ignore
        if not advert.signature_valid:
            log.debug(
                "advert from %s has invalid signature; ignoring",
                advert.pub_key[:4].hex(),
            )
            return
        last_ts = self._advert_ts.get(advert.pub_key)
        if last_ts is not None and advert.timestamp < last_ts:
            log.debug(
                "advert from %s is stale (ts=%d < last=%d); ignoring",
                advert.pub_key[:4].hex(),
                advert.timestamp,
                last_ts,
            )
            return
        self._advert_ts[advert.pub_key] = advert.timestamp
        if self.add_contact(advert.pub_key, advert.app_data.name):
            self.save_contact_cache()

    async def handle_txt_msg(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        if not packet.payload or packet.payload[0] != self.identity.address:
            return  # not addressed to us
        src_hash = packet.payload[1] if len(packet.payload) > 1 else None
        candidates = list(self._contacts.get(src_hash, {}).items()) if src_hash is not None else []
        if not candidates:
            log.debug(
                "TXT_MSG to us from src_hash=%#04x but no candidate contacts known yet",
                src_hash if src_hash is not None else 0,
            )
            return
        for sender_pub, sender_name in candidates:
            shared = self.identity.calc_shared_secret(sender_pub)
            msg = try_decrypt_txt_msg(packet.payload, shared)
            if msg is None:
                continue
            log.info(
                "received from %s (%s): %r (ts=%d, attempt=%d)",
                sender_name,
                sender_pub[:4].hex() + "…",
                msg.text,
                msg.timestamp,
                msg.attempt,
            )
            # Acknowledge first.
            ack = msg.ack_hash(sender_pub)
            self.remember_path(msg.src_hash, ack, packet)
            if not self.remember_message(msg.src_hash, ack):
                await self.send_txt_ack(mqtt, shared, msg.src_hash, ack, packet)
                log.info("duplicate message suppressed: %r", msg.text)
                return
            await self.send_txt_ack(mqtt, shared, msg.src_hash, ack, packet)
            task = asyncio.create_task(
                self.deliver_echo(
                    mqtt=mqtt,
                    shared=shared,
                    sender_pub=sender_pub,
                    src_hash=msg.src_hash,
                    inbound_ack=ack,
                    inbound_packet=packet,
                    original_text=msg.text,
                ),
                name="deliver_echo",
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            return
        log.debug(
            "TXT_MSG to us from src_hash=%#04x did not decrypt for any of %d candidates",
            src_hash if src_hash is not None else 0,
            len(candidates),
        )

    async def send_txt_ack(
        self,
        mqtt: aiomqtt.Client,
        shared: bytes,
        dest_hash: int,
        ack: bytes,
        packet: Packet,
    ) -> None:
        if self.is_flood(packet):
            reply = build_path_packet(
                shared_secret=shared,
                dest_hash=dest_hash,
                src_pub_key=self.identity.pub_key,
                path_payload=packet.path,
                path_hash_size=packet.hash_size,
                extra_type=PayloadType.ACK,
                extra=ack,
            )
            await mqtt.publish(self.config.tx_topic, encode_packet(reply))
            log.info(
                "sent PATH+ACK return for flood TXT_MSG, payload_hops=%d",
                packet.hash_count,
            )
            return
        await mqtt.publish(self.config.tx_topic, encode_packet(build_ack_packet(ack)))

    async def handle_req_msg(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        if not packet.payload or packet.payload[0] != self.identity.address:
            return
        src_hash = packet.payload[1] if len(packet.payload) > 1 else None
        candidates = list(self._contacts.get(src_hash, {}).items()) if src_hash is not None else []
        for sender_pub, sender_name in candidates:
            shared = self.identity.calc_shared_secret(sender_pub)
            req = try_decrypt_req_msg(packet.payload, shared)
            if req is None:
                continue
            req_type = req.data[0] if req.data else None
            log.info(
                "REQ from %s (%s): route=%s type=%#04x observed_hops=%d",
                sender_name,
                sender_pub[:4].hex() + "…",
                getattr(packet.route_type, "name", packet.route_type),
                req_type if req_type is not None else 0,
                packet.hash_count,
            )
            if req_type != REQ_TYPE_GET_TELEMETRY_DATA or not self.is_flood(packet):
                return

            # Path discovery is a flood telemetry request. The official firmware
            # returns a PATH packet with the observed inbound path plus a bundled
            # RESPONSE whose first four bytes reflect the request tag.
            reply = build_path_packet(
                shared_secret=shared,
                dest_hash=req.src_hash,
                src_pub_key=self.identity.pub_key,
                path_payload=packet.path,
                path_hash_size=packet.hash_size,
                extra_type=PayloadType.RESPONSE,
                extra=req.timestamp.to_bytes(4, "little") + b"\x00",
            )
            await mqtt.publish(self.config.tx_topic, encode_packet(reply))
            log.info(
                "sent PATH+RESPONSE for discovery to %s, payload_hops=%d",
                sender_name,
                packet.hash_count,
            )
            return
        log.debug(
            "REQ to us from src_hash=%#04x did not decrypt for any of %d candidates",
            src_hash if src_hash is not None else 0,
            len(candidates),
        )

    async def handle_path_msg(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        if not packet.payload or packet.payload[0] != self.identity.address:
            return
        src_hash = packet.payload[1] if len(packet.payload) > 1 else None
        candidates = list(self._contacts.get(src_hash, {}).items()) if src_hash is not None else []
        for sender_pub, sender_name in candidates:
            shared = self.identity.calc_shared_secret(sender_pub)
            path_msg = try_decrypt_path_msg(packet.payload, shared)
            if path_msg is None:
                continue
            log.info(
                "PATH from %s (%s): route=%s req_path_hops=%d observed_hops=%d",
                sender_name,
                sender_pub[:4].hex() + "…",
                getattr(packet.route_type, "name", packet.route_type),
                len(path_msg.path) // path_msg.hash_size,
                packet.hash_count,
            )
            if not self.is_flood(packet):
                return
            if not path_msg.path:
                log.info("PATH return skipped for %s: request included no return path", sender_name)
                return
            reply = build_path_packet(
                shared_secret=shared,
                dest_hash=path_msg.src_hash,
                src_pub_key=self.identity.pub_key,
                path_payload=packet.path,
                path_hash_size=packet.hash_size,
                route_type=RouteType.DIRECT,
                route_path=path_msg.path,
                route_hash_size=path_msg.hash_size,
            )
            await mqtt.publish(self.config.tx_topic, encode_packet(reply))
            log.info(
                "sent PATH return to %s over %d hop(s), payload_hops=%d",
                sender_name,
                len(path_msg.path) // path_msg.hash_size,
                packet.hash_count,
            )
            return
        log.debug(
            "PATH to us from src_hash=%#04x did not decrypt for any of %d candidates",
            src_hash if src_hash is not None else 0,
            len(candidates),
        )

    async def deliver_echo(
        self,
        *,
        mqtt: aiomqtt.Client,
        shared: bytes,
        sender_pub: bytes,
        src_hash: int,
        inbound_ack: bytes,
        inbound_packet: Packet,
        original_text: str,
    ) -> None:
        async def publish(wire: bytes) -> None:
            await mqtt.publish(self.config.tx_topic, wire)

        if self.config.ack_reply_delay_s > 0:
            await asyncio.sleep(self.config.ack_reply_delay_s)

        best_packet = self.best_path_packet(src_hash, inbound_ack, inbound_packet)
        reply_text = (
            f"{self.config.echo_prefix}{original_text} [{self.format_path_info(best_packet)}]"
        )
        direct_path = (
            reverse_path(best_packet.path, best_packet.hash_size) if best_packet.path else b""
        )

        result = await deliver_txt_msg_with_ack(
            publish=publish,
            wait_for_ack=self.wait_for_ack,
            shared_secret=shared,
            dest_pub_key=sender_pub,
            src_pub_key=self.identity.pub_key,
            text=reply_text,
            timestamp=int(time.time()),
            direct_path=direct_path,
            direct_hash_size=best_packet.hash_size,
            direct_attempts=self.config.reply_direct_attempts,
            flood_attempts=self.config.reply_flood_attempts,
            ack_timeout_s=self.config.reply_ack_timeout_s,
        )
        log.info(
            "echoed back: %r (route=%s attempt=%d acked=%s)",
            reply_text,
            getattr(result.route_type, "name", result.route_type),
            result.attempt,
            result.acked,
        )


async def run(config: EchoConfig) -> None:
    identity = _load_identity(config)
    server = EchoServer(config, identity)
    server.load_contact_cache()
    for pub_key in config.contact_pub_keys:
        if server.add_contact(pub_key, "configured-contact"):
            server.save_contact_cache()
    if config.contact_pub_keys:
        log.info("loaded %d configured contact pubkey(s)", len(config.contact_pub_keys))

    async with config.mqtt.client() as mqtt:
        m = config.mqtt
        log.info("connected to MQTT %s:%d (tls=%s)", m.host, m.port, m.use_tls)
        await mqtt.publish(
            config.status_topic,
            json.dumps(
                {
                    "state": "up",
                    "name": identity.name,
                    "pub_key": identity.pub_key.hex(),
                    "path_hash": identity.address,
                }
            ).encode(),
            retain=True,
        )

        async def advertise_loop() -> None:
            while True:
                wire = server.build_self_advert()
                log.info(
                    "sending %s advert (%d bytes) as %r path_hash=%#04x",
                    "flood" if config.advert_flood else "zero-hop",
                    len(wire),
                    identity.name,
                    identity.address,
                )
                await mqtt.publish(config.tx_topic, wire)
                await asyncio.sleep(config.advertisement_interval_s)

        async def receive_loop() -> None:
            await mqtt.subscribe(config.rx_topic)
            async for raw_msg in mqtt.messages:
                payload = (
                    bytes(raw_msg.payload)
                    if isinstance(raw_msg.payload, (bytes, bytearray))
                    else b""
                )
                if not payload:
                    continue
                try:
                    packet = decode_packet(payload)
                except ValueError as e:
                    log.debug("rx undecodable: %s", e)
                    continue
                if packet.payload_type == PayloadType.ADVERT:
                    server.handle_advert(packet)
                elif packet.payload_type == PayloadType.ACK:
                    server.handle_ack(packet)
                elif packet.payload_type == PayloadType.PATH:
                    await server.handle_path_msg(packet, mqtt)
                elif packet.payload_type == PayloadType.REQ:
                    await server.handle_req_msg(packet, mqtt)
                elif packet.payload_type == PayloadType.TXT_MSG:
                    await server.handle_txt_msg(packet, mqtt)

        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(advertise_loop(), name="advertise_loop")
                tg.create_task(receive_loop(), name="receive_loop")
        finally:
            await mqtt.publish(
                config.status_topic,
                json.dumps({"state": "down"}).encode(),
                retain=True,
            )
