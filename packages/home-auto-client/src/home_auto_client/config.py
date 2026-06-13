"""home-auto-client config."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from softmesh_stack.crypto import sha256
from softmesh_stack.mqtt import MqttConfig


def _default_identity_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "softmesh" / "home-auto-client.identity"


def _default_contact_cache_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "softmesh" / "home-auto-client.contacts.json"


@dataclass(frozen=True, slots=True)
class EchoConfig:
    identity_path: Path
    identity_seed: str | None  # hex 32-byte private seed (e.g. from a Secret)
    contact_cache_path: Path
    display_name: str
    mqtt: MqttConfig
    rx_topic: str
    tx_topic: str
    status_topic: str
    advertisement_interval_s: float
    advert_flood: bool
    echo_prefix: str
    ack_reply_delay_s: float
    recent_message_ttl_s: float
    reply_ack_timeout_s: float
    reply_direct_attempts: int
    reply_flood_attempts: int
    contact_pub_keys: tuple[bytes, ...]
    # Channel monitoring: decoded GRP_TXT from matching contacts are logged.
    # channel_keys holds SHA-256(channel_secret) for each channel to monitor.
    monitor_channel_keys: tuple[bytes, ...]
    monitor_name_filter: str  # case-insensitive substring; empty = any contact

    @classmethod
    def from_env(cls) -> EchoConfig:
        return cls(
            identity_path=Path(os.environ.get("HOMEAUTO_IDENTITY", str(_default_identity_path()))),
            identity_seed=os.environ.get("HOMEAUTO_IDENTITY_SEED") or None,
            contact_cache_path=Path(
                os.environ.get("HOMEAUTO_CONTACT_CACHE", str(_default_contact_cache_path()))
            ),
            display_name=os.environ.get("HOMEAUTO_NAME", "py-echo"),
            mqtt=MqttConfig.from_env("HOMEAUTO"),
            rx_topic=os.environ.get("HOMEAUTO_RX_TOPIC", "mesh/rx"),
            tx_topic=os.environ.get("HOMEAUTO_TX_TOPIC", "mesh/tx"),
            status_topic=os.environ.get(
                "HOMEAUTO_STATUS_TOPIC", "mesh/identities/home-auto-client"
            ),
            advertisement_interval_s=float(os.environ.get("HOMEAUTO_ADVERT_INTERVAL_S", "3600")),
            advert_flood=_parse_bool(os.environ.get("HOMEAUTO_ADVERT_FLOOD"), default=False),
            echo_prefix=os.environ.get("HOMEAUTO_ECHO_PREFIX", "echo: "),
            ack_reply_delay_s=float(os.environ.get("HOMEAUTO_ACK_REPLY_DELAY_S", "2.0")),
            recent_message_ttl_s=float(os.environ.get("HOMEAUTO_RECENT_MESSAGE_TTL_S", "300")),
            reply_ack_timeout_s=float(os.environ.get("HOMEAUTO_REPLY_ACK_TIMEOUT_S", "8")),
            reply_direct_attempts=int(os.environ.get("HOMEAUTO_REPLY_DIRECT_ATTEMPTS", "3")),
            reply_flood_attempts=int(os.environ.get("HOMEAUTO_REPLY_FLOOD_ATTEMPTS", "3")),
            contact_pub_keys=_parse_pub_keys(os.environ.get("HOMEAUTO_CONTACT_PUB_KEYS", "")),
            monitor_channel_keys=_parse_monitor_keys(
                os.environ.get("HOMEAUTO_MONITOR_CHANNEL_KEYS", "")
            ),
            monitor_name_filter=os.environ.get("HOMEAUTO_MONITOR_NAME_FILTER", ""),
        )


def _parse_bool(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _parse_pub_keys(raw: str) -> tuple[bytes, ...]:
    keys = []
    for item in raw.replace(";", ",").split(","):
        hex_key = item.strip().removeprefix("0x")
        if not hex_key:
            continue
        pub_key = bytes.fromhex(hex_key)
        if len(pub_key) != 32:
            raise ValueError("HOMEAUTO_CONTACT_PUB_KEYS entries must be 32-byte public keys")
        keys.append(pub_key)
    return tuple(keys)


def _parse_monitor_keys(raw: str) -> tuple[bytes, ...]:
    """Parse HOMEAUTO_MONITOR_CHANNEL_KEYS as comma-separated channel secrets.

    Each entry is the plain-text channel password/secret (not hex).  The key
    is derived as SHA-256(secret.encode()).  For the public channel (no
    password) use an explicit empty entry inside a non-empty value, e.g.
    ``HOMEAUTO_MONITOR_CHANNEL_KEYS=,`` (two entries: public + public) or
    ``HOMEAUTO_MONITOR_CHANNEL_KEYS=public`` if "public" is the channel name.

    An entirely empty or whitespace-only value disables monitoring (returns
    an empty tuple).  Alternatively supply a 64-char hex string to pass the
    derived key directly.
    """
    if not raw.strip():
        return ()
    keys: list[bytes] = []
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            # Explicit empty entry within a non-empty value → public channel.
            keys.append(sha256(b""))
            continue
        # If it looks like a 64-char hex string, accept it as a raw key.
        stripped = entry.removeprefix("0x")
        if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
            keys.append(bytes.fromhex(stripped))
        else:
            keys.append(sha256(entry.encode("utf-8")))
    return tuple(keys)
