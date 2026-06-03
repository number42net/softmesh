"""Room server: password-gated, store-and-forward bulletin board on the mesh.

Behaviour:
  * Loads/generates a persistent Ed25519 identity and advertises as a ROOM node.
  * Accepts ANON_REQ logins; a password matching the configured admin or guest
    password is admitted (admin/guest), anything else is refused.
  * On login, replies with a RESPONSE (LOGIN_OK) and pushes stored posts newer
    than the client's sync cursor.
  * Treats each plain TXT_MSG from a logged-in client as a new post: stores it,
    ACKs it, and fans it out to the other logged-in clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

import aiomqtt
from softmesh_stack import crypto
from softmesh_stack.advert import AdvertData, AdvertType, decode_advert, encode_advert
from softmesh_stack.identity import Identity, resolve_identity
from softmesh_stack.messaging import (
    TXT_TYPE_PLAIN,
    build_ack_packet,
    build_path_packet,
    parse_ack_payload,
    reverse_path,
    try_decrypt_path_msg,
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
from softmesh_stack.room import (
    PERM_ACL_ADMIN,
    PERM_ACL_READ_WRITE,
    build_login_response_packet,
    deliver_room_push_with_ack,
    try_decrypt_login,
)

from .config import RoomConfig
from .db import Post, RoomStore

log = logging.getLogger(__name__)


def _load_identity(config: RoomConfig) -> Identity:
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


@dataclass(slots=True)
class ClientSession:
    """A currently-known client: how to reach it and what role it holds."""

    pub_key: bytes
    name: str
    is_admin: bool
    route_type: RouteType = RouteType.FLOOD
    path: bytes = b""  # forward route to the client (already reversed), for DIRECT
    hash_size: int = 1


@dataclass(slots=True)
class RoomServer:
    config: RoomConfig
    identity: Identity
    store: RoomStore
    _sessions: dict[bytes, ClientSession] = field(default_factory=dict)
    _by_hash: dict[int, set[bytes]] = field(default_factory=lambda: defaultdict(set))
    _names: dict[bytes, str] = field(default_factory=dict)
    _advert_ts: dict[bytes, int] = field(default_factory=dict)
    _recent_messages: dict[tuple[int, bytes], float] = field(default_factory=dict)
    _ack_waiters: dict[bytes, list[asyncio.Future[bool]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)

    # --- helpers ------------------------------------------------------------ #
    @staticmethod
    def is_flood(packet: Packet) -> bool:
        return packet.route_type in {RouteType.FLOOD, RouteType.TRANSPORT_FLOOD}

    def _spawn(self, coro, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            self._tasks.discard(t)
            if not t.cancelled() and t.exception() is not None:
                log.error("background task %s failed: %r", name, t.exception())

        task.add_done_callback(_done)

    def _return_route(self, packet: Packet) -> tuple[RouteType, bytes, int]:
        """Forward route back to the sender, derived from an observed inbound path."""
        if packet.hash_count and packet.path:
            return RouteType.DIRECT, reverse_path(packet.path, packet.hash_size), packet.hash_size
        return RouteType.FLOOD, b"", 1

    def _classify(self, password: str) -> str | None:
        if self.config.admin_password and password == self.config.admin_password:
            return "admin"
        if self.config.guest_password and password == self.config.guest_password:
            return "guest"
        return None

    def remember_message(self, src_hash: int, ack_hash: bytes) -> bool:
        now = time.monotonic()
        cutoff = now - self.config.recent_message_ttl_s
        for key, seen_at in list(self._recent_messages.items()):
            if seen_at < cutoff:
                del self._recent_messages[key]
        key = (src_hash, ack_hash)
        if key in self._recent_messages:
            return False
        self._recent_messages[key] = now
        return True

    def _track_session(self, pub_key: bytes, is_admin: bool, packet: Packet) -> ClientSession:
        route_type, path, hash_size = self._return_route(packet)
        name = self._names.get(pub_key, f"client-{pub_key[:2].hex()}")
        session = self._sessions.get(pub_key)
        if session is None:
            session = ClientSession(pub_key=pub_key, name=name, is_admin=is_admin)
            self._sessions[pub_key] = session
            self._by_hash[crypto.path_hash(pub_key)].add(pub_key)
        session.name = name
        session.is_admin = is_admin
        # Only overwrite the route when we actually observed a usable one.
        if route_type == RouteType.DIRECT:
            session.route_type, session.path, session.hash_size = route_type, path, hash_size
        return session

    def sessions_at(self, src_hash: int) -> list[ClientSession]:
        pubs = self._by_hash.get(src_hash, set())
        return [self._sessions[p] for p in pubs if p in self._sessions]

    async def wait_for_ack(self, ack_hash: bytes, timeout_s: float) -> bool:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[bool] = loop.create_future()
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

    def _resolve_ack(self, ack_hash: bytes) -> bool:
        waiters = self._ack_waiters.pop(ack_hash, [])
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(True)
        return bool(waiters)

    def handle_ack(self, packet: Packet) -> None:
        """A plain ACK (clients use this for messages received over a direct route)."""
        ack_hash = parse_ack_payload(packet.payload)
        if ack_hash is None:
            return
        self._resolve_ack(ack_hash)

    async def handle_path(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        """A returned PATH packet. Clients answer a *flood* push with a PATH whose
        decrypted payload carries the observed route plus a bundled ACK, so we
        both confirm the push and learn a direct route for next time."""
        if not packet.payload or packet.payload[0] != self.identity.address:
            return
        src_hash = packet.payload[1] if len(packet.payload) > 1 else None
        if src_hash is None:
            return
        for session in self.sessions_at(src_hash):
            shared = self.identity.calc_shared_secret(session.pub_key)
            path_msg = try_decrypt_path_msg(packet.payload, shared)
            if path_msg is None:
                continue
            # The embedded path is the route from us to the client; use it as-is.
            if path_msg.path:
                session.route_type = RouteType.DIRECT
                session.path = path_msg.path
                session.hash_size = path_msg.hash_size
            if path_msg.extra_type == PayloadType.ACK and len(path_msg.extra) >= 4:
                ack = path_msg.extra[:4]
                if self._resolve_ack(ack):
                    log.debug("PATH+ACK from %s confirmed push (ack=%s)", session.name, ack.hex())
            return

    # --- advert ------------------------------------------------------------- #
    def build_self_advert(self) -> bytes:
        ts = int(time.time())
        app = AdvertData(type=AdvertType.ROOM, name=self.config.display_name)
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

    def handle_advert(self, packet: Packet) -> None:
        try:
            advert = decode_advert(packet.payload)
        except ValueError:
            return
        if advert.pub_key == self.identity.pub_key or not advert.signature_valid:
            return
        last = self._advert_ts.get(advert.pub_key)
        if last is not None and advert.timestamp < last:
            return
        self._advert_ts[advert.pub_key] = advert.timestamp
        if advert.app_data.name:
            self._names[advert.pub_key] = advert.app_data.name
            session = self._sessions.get(advert.pub_key)
            if session is not None:
                session.name = advert.app_data.name

    # --- login -------------------------------------------------------------- #
    async def handle_login(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        if not packet.payload or packet.payload[0] != self.identity.address:
            return
        req = try_decrypt_login(packet.payload, self.identity.seed)
        if req is None:
            log.debug("ANON_REQ to us did not decrypt")
            return
        role = self._classify(req.password)
        if role is None:
            log.info("login refused for %s (no matching password)", req.client_pub_key[:4].hex())
            return
        is_admin = role == "admin"
        session = self._track_session(req.client_pub_key, is_admin, packet)
        await self.store.upsert_client(req.client_pub_key, session.name, is_admin)
        log.info(
            "login OK: %s as %s (sync_since=%d, route=%s)",
            session.name,
            role,
            req.sync_since,
            session.route_type.name,
        )

        shared = self.identity.calc_shared_secret(req.client_pub_key)
        route_type, path, hash_size = self._return_route(packet)
        # Both admin and (password-holding) guests may post; only the role differs.
        permissions = PERM_ACL_ADMIN if is_admin else PERM_ACL_READ_WRITE
        resp = build_login_response_packet(
            shared_secret=shared,
            dest_hash=crypto.path_hash(req.client_pub_key),
            src_hash=self.identity.address,
            server_ts=int(time.time()),
            is_admin=is_admin,
            permissions=permissions,
            route_type=route_type,
            path=path,
            hash_size=hash_size,
        )
        await mqtt.publish(self.config.tx_topic, encode_packet(resp))
        self._spawn(self.sync_client(mqtt, session, req.sync_since), name="sync_client")

    async def sync_client(
        self, mqtt: aiomqtt.Client, session: ClientSession, sync_since: int
    ) -> None:
        posts = await self.store.posts_since(sync_since, exclude_pubkey=session.pub_key)
        posts = posts[: self.config.max_sync_posts]
        if not posts:
            return
        log.info("syncing %d post(s) to %s since ts=%d", len(posts), session.name, sync_since)
        for post in posts:
            await self.push_post(mqtt, session, post)

    # --- posts -------------------------------------------------------------- #
    async def handle_post(self, packet: Packet, mqtt: aiomqtt.Client) -> None:
        if not packet.payload or packet.payload[0] != self.identity.address:
            return
        src_hash = packet.payload[1] if len(packet.payload) > 1 else None
        if src_hash is None:
            return
        for session in self.sessions_at(src_hash):
            shared = self.identity.calc_shared_secret(session.pub_key)
            msg = try_decrypt_txt_msg(packet.payload, shared)
            if msg is None:
                continue
            # Refresh the client's return route from this packet.
            self._track_session(session.pub_key, session.is_admin, packet)
            ack = msg.ack_hash(session.pub_key)
            if not self.remember_message(msg.src_hash, ack):
                await self.send_post_ack(mqtt, shared, msg.src_hash, ack, packet)
                log.info("duplicate post suppressed from %s", session.name)
                return
            await self.send_post_ack(mqtt, shared, msg.src_hash, ack, packet)
            if msg.txt_type != TXT_TYPE_PLAIN:
                log.info("ignoring non-plain TXT (type=%d) from %s", msg.txt_type, session.name)
                return
            post = await self.store.add_post(session.pub_key, msg.timestamp, msg.text)
            log.info("stored post #%d from %s: %r", post.id, session.name, msg.text)
            self._spawn(self.fan_out(mqtt, post), name="fan_out")
            return
        log.debug("TXT_MSG to room from src_hash=%#04x not from a logged-in client", src_hash)

    async def send_post_ack(
        self, mqtt: aiomqtt.Client, shared: bytes, dest_hash: int, ack: bytes, packet: Packet
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
            return
        await mqtt.publish(self.config.tx_topic, encode_packet(build_ack_packet(ack)))

    async def fan_out(self, mqtt: aiomqtt.Client, post: Post) -> None:
        author = bytes.fromhex(post.author_pubkey)
        targets = [s for s in self._sessions.values() if s.pub_key != author]
        if not targets:
            return
        # Push to all clients concurrently: a slow/unacking client must not
        # block delivery to the others. One failed push is logged, not fatal.
        results = await asyncio.gather(
            *(self.push_post(mqtt, s, post) for s in targets), return_exceptions=True
        )
        for session, result in zip(targets, results, strict=True):
            if isinstance(result, Exception):
                log.warning("push of post #%d to %s failed: %r", post.id, session.name, result)

    async def push_post(self, mqtt: aiomqtt.Client, session: ClientSession, post: Post) -> None:
        async def publish(wire: bytes) -> None:
            await mqtt.publish(self.config.tx_topic, wire)

        shared = self.identity.calc_shared_secret(session.pub_key)
        result = await deliver_room_push_with_ack(
            publish=publish,
            wait_for_ack=self.wait_for_ack,
            shared_secret=shared,
            dest_pub_key=session.pub_key,
            room_pub_key=self.identity.pub_key,
            post_ts=post.ts,
            author_pub_key=bytes.fromhex(post.author_pubkey),
            text=post.body,
            direct_path=session.path,
            direct_hash_size=session.hash_size,
            direct_attempts=self.config.push_direct_attempts,
            flood_attempts=self.config.push_flood_attempts,
            ack_timeout_s=self.config.push_ack_timeout_s,
        )
        log.info(
            "pushed post #%d to %s (route=%s acked=%s)",
            post.id,
            session.name,
            result.route_type.name,
            result.acked,
        )
        if result.acked:
            await self.store.set_client_cursor(session.pub_key, post.ts)


async def run(config: RoomConfig) -> None:
    identity = _load_identity(config)
    store = RoomStore(config.db_path)
    await store.open()
    server = RoomServer(config=config, identity=identity, store=store)

    try:
        async with config.mqtt.client() as mqtt:
            log.info("connected to MQTT %s:%d (tls=%s)", config.mqtt.host, config.mqtt.port,
                     config.mqtt.use_tls)
            await mqtt.publish(
                config.status_topic,
                json.dumps(
                    {
                        "state": "up",
                        "name": identity.name,
                        "room": config.room_name,
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
                        "sending %s ROOM advert as %r path_hash=%#04x",
                        "flood" if config.advert_flood else "zero-hop",
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
                    # One malformed/unexpected frame must never take the server
                    # down: handle each packet defensively and keep serving.
                    try:
                        if packet.payload_type == PayloadType.ADVERT:
                            server.handle_advert(packet)
                        elif packet.payload_type == PayloadType.ACK:
                            server.handle_ack(packet)
                        elif packet.payload_type == PayloadType.PATH:
                            await server.handle_path(packet, mqtt)
                        elif packet.payload_type == PayloadType.ANON_REQ:
                            await server.handle_login(packet, mqtt)
                        elif packet.payload_type == PayloadType.TXT_MSG:
                            await server.handle_post(packet, mqtt)
                    except Exception:
                        log.exception(
                            "error handling %s packet (%d bytes); continuing",
                            getattr(packet.payload_type, "name", packet.payload_type),
                            len(payload),
                        )

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
    finally:
        await store.close()
