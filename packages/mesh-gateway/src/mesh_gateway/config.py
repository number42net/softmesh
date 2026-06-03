"""Gateway configuration.

Resolved from CLI args / env vars / defaults. Broker-agnostic: the MQTT
connection (host/port/auth/TLS) is configured via the shared ``MqttConfig``
(``MESH_GATEWAY_MQTT_*`` env vars).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from softmesh_stack import radio
from softmesh_stack.mqtt import MqttConfig


def _opt_int(name: str) -> int | None:
    return int(os.environ[name]) if name in os.environ and os.environ[name].strip() else None


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    serial_port: str
    baud: int
    mqtt: MqttConfig
    rx_topic: str
    tx_topic: str
    status_topic: str
    radio_preset: str | None  # named preset, e.g. "NL"
    radio_freq_hz: int | None  # custom radio: set all four to override the preset
    radio_bw_hz: int | None
    radio_sf: int | None
    radio_cr: int | None
    tx_power_dbm: int | None  # None = leave modem TX power alone
    duty_cycle: float

    @classmethod
    def from_env(cls) -> GatewayConfig:
        return cls(
            serial_port=os.environ.get("MESH_GATEWAY_SERIAL", "/dev/cu.usbserial-0001"),
            baud=int(os.environ.get("MESH_GATEWAY_BAUD", "115200")),
            mqtt=MqttConfig.from_env("MESH_GATEWAY"),
            rx_topic=os.environ.get("MESH_GATEWAY_RX_TOPIC", "mesh/rx"),
            tx_topic=os.environ.get("MESH_GATEWAY_TX_TOPIC", "mesh/tx"),
            status_topic=os.environ.get("MESH_GATEWAY_STATUS_TOPIC", "mesh/status/gateway"),
            radio_preset=os.environ.get("MESH_GATEWAY_RADIO_PRESET") or None,
            radio_freq_hz=_opt_int("MESH_GATEWAY_FREQ_HZ"),
            radio_bw_hz=_opt_int("MESH_GATEWAY_BW_HZ"),
            radio_sf=_opt_int("MESH_GATEWAY_SF"),
            radio_cr=_opt_int("MESH_GATEWAY_CR"),
            tx_power_dbm=_opt_int("MESH_GATEWAY_TX_POWER"),
            duty_cycle=float(os.environ.get("MESH_GATEWAY_DUTY_CYCLE", "0.10")),
        )

    @property
    def radio_config(self) -> radio.RadioConfig | None:
        """The radio settings to program at startup, or None to leave the modem alone.

        A full custom set (FREQ_HZ + BW_HZ + SF + CR) overrides any named preset.
        """
        custom = (self.radio_freq_hz, self.radio_bw_hz, self.radio_sf, self.radio_cr)
        if all(v is not None for v in custom):
            return radio.RadioConfig(
                name="custom",
                frequency_hz=self.radio_freq_hz,  # type: ignore[arg-type]
                bandwidth_hz=self.radio_bw_hz,  # type: ignore[arg-type]
                spreading_factor=self.radio_sf,  # type: ignore[arg-type]
                coding_rate=self.radio_cr,  # type: ignore[arg-type]
                tx_power_dbm=self.tx_power_dbm if self.tx_power_dbm is not None else 22,
            )
        if any(v is not None for v in custom):
            raise ValueError(
                "partial custom radio config: set all of "
                "MESH_GATEWAY_FREQ_HZ/BW_HZ/SF/CR, or none and use MESH_GATEWAY_RADIO_PRESET"
            )
        if self.radio_preset:
            return radio.get_preset(self.radio_preset)
        return None

    def __post_init__(self) -> None:
        if not 0 < self.duty_cycle <= 1:
            raise ValueError("MESH_GATEWAY_DUTY_CYCLE must be > 0 and <= 1")
