from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from softmesh_stack.mqtt import MqttConfig


def _default_identity_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return base / "softmesh" / "observer.identity"


def _parse_bool(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _parse_float(raw: str | None) -> float | None:
    if raw is None or not raw.strip():
        return None
    return float(raw)


def _parse_int(raw: str | None, *, default: int) -> int:
    if raw is None or not raw.strip():
        return default
    return int(raw)


@dataclass(frozen=True, slots=True)
class ObserverConfig:
    identity_path: Path
    identity_seed: str | None
    iata_code: str
    token_audience: str | None
    mqtt_local: MqttConfig
    mqtt_cornmeister: MqttConfig
    mqtt_radar: MqttConfig
    enable_cornmeister: bool
    enable_radar: bool
    rx_topic: str
    cornmeister_topic_template: str
    radar_topic_template: str
    status_topic_template: str
    # Self-advert (so the observer appears as a named, located node on analyzers).
    name: str | None
    lat: float | None
    lon: float | None
    tx_topic: str
    advert_interval_s: int  # 0 = do not broadcast a self-advert
    advert_flood: bool

    @classmethod
    def from_env(cls) -> ObserverConfig:
        return cls(
            identity_path=Path(os.environ.get("OBSERVER_IDENTITY", str(_default_identity_path()))),
            identity_seed=os.environ.get("OBSERVER_IDENTITY_SEED") or None,
            iata_code=os.environ.get("OBSERVER_IATA", "AMS"),
            token_audience=os.environ.get("OBSERVER_TOKEN_AUDIENCE") or None,
            mqtt_local=MqttConfig.from_env("OBSERVER"),
            mqtt_cornmeister=MqttConfig.from_env(
                "OBSERVER_CORN",
                default_url=os.environ.get(
                    "OBSERVER_CORN_MQTT_URL", "wss://collector1.dutchmeshcore.nl:443/mqtt"
                ),
            ),
            mqtt_radar=MqttConfig.from_env(
                "OBSERVER_RADAR",
                default_url=os.environ.get(
                    "OBSERVER_RADAR_MQTT_URL", "wss://collector2.dutchmeshcore.nl:443/mqtt"
                ),
            ),
            enable_cornmeister=_parse_bool(
                os.environ.get("OBSERVER_ENABLE_CORNMEISTER"), default=True
            ),
            enable_radar=_parse_bool(os.environ.get("OBSERVER_ENABLE_RADAR"), default=True),
            rx_topic=os.environ.get("OBSERVER_RX_TOPIC", "mesh/rx"),
            cornmeister_topic_template=os.environ.get(
                "OBSERVER_CORN_TOPIC", "meshcore/{iata}/{observer_pub}/packets"
            ),
            radar_topic_template=os.environ.get(
                "OBSERVER_RADAR_TOPIC", "meshcore/{iata}/{observer_pub}/packets"
            ),
            status_topic_template=os.environ.get(
                "OBSERVER_STATUS_TOPIC", "meshcore/{iata}/{observer_pub}/status"
            ),
            name=os.environ.get("OBSERVER_NAME") or None,
            lat=_parse_float(os.environ.get("OBSERVER_LAT")),
            lon=_parse_float(os.environ.get("OBSERVER_LON")),
            tx_topic=os.environ.get("OBSERVER_TX_TOPIC", "mesh/tx"),
            advert_interval_s=_parse_int(os.environ.get("OBSERVER_ADVERT_INTERVAL"), default=0),
            advert_flood=_parse_bool(os.environ.get("OBSERVER_ADVERT_FLOOD"), default=True),
        )

    def cornmeister_topic(self, observer_pub_key: bytes) -> str:
        return self.cornmeister_topic_template.format(
            iata=self.iata_code,
            observer_pub=observer_pub_key.hex().upper(),
        )

    def radar_topic(self, observer_pub_key: bytes) -> str:
        return self.radar_topic_template.format(
            iata=self.iata_code,
            observer_pub=observer_pub_key.hex().upper(),
        )

    def status_topic(self, observer_pub_key: bytes) -> str:
        return self.status_topic_template.format(
            iata=self.iata_code,
            observer_pub=observer_pub_key.hex().upper(),
        )