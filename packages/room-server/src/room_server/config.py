"""room-server config (env-driven, mirrors home-auto-client)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from softmesh_stack.mqtt import MqttConfig


def _state_path(name: str) -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "softmesh" / name


def _parse_bool(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True, slots=True)
class RoomConfig:
    identity_path: Path
    identity_seed: str | None  # hex 32-byte private seed (e.g. from a Secret)
    db_path: Path
    display_name: str
    room_name: str
    admin_password: str
    guest_password: str
    mqtt: MqttConfig
    rx_topic: str
    tx_topic: str
    status_topic: str
    advertisement_interval_s: float
    advert_flood: bool
    recent_message_ttl_s: float
    push_ack_timeout_s: float
    push_direct_attempts: int
    push_flood_attempts: int
    max_sync_posts: int

    @classmethod
    def from_env(cls) -> RoomConfig:
        return cls(
            identity_path=Path(
                os.environ.get("ROOM_IDENTITY", str(_state_path("room-server.identity")))
            ),
            identity_seed=os.environ.get("ROOM_IDENTITY_SEED") or None,
            db_path=Path(os.environ.get("ROOM_DB", str(_state_path("room-server.sqlite3")))),
            display_name=os.environ.get("ROOM_NAME", "py-room"),
            room_name=os.environ.get("ROOM_TITLE", "py-room"),
            admin_password=os.environ.get("ROOM_ADMIN_PASSWORD", ""),
            guest_password=os.environ.get("ROOM_GUEST_PASSWORD", ""),
            mqtt=MqttConfig.from_env("ROOM"),
            rx_topic=os.environ.get("ROOM_RX_TOPIC", "mesh/rx"),
            tx_topic=os.environ.get("ROOM_TX_TOPIC", "mesh/tx"),
            status_topic=os.environ.get("ROOM_STATUS_TOPIC", "mesh/identities/room-server"),
            advertisement_interval_s=float(os.environ.get("ROOM_ADVERT_INTERVAL_S", "3600")),
            advert_flood=_parse_bool(os.environ.get("ROOM_ADVERT_FLOOD"), default=False),
            recent_message_ttl_s=float(os.environ.get("ROOM_RECENT_MESSAGE_TTL_S", "300")),
            push_ack_timeout_s=float(os.environ.get("ROOM_PUSH_ACK_TIMEOUT_S", "6")),
            push_direct_attempts=int(os.environ.get("ROOM_PUSH_DIRECT_ATTEMPTS", "2")),
            push_flood_attempts=int(os.environ.get("ROOM_PUSH_FLOOD_ATTEMPTS", "2")),
            max_sync_posts=int(os.environ.get("ROOM_MAX_SYNC_POSTS", "20")),
        )
