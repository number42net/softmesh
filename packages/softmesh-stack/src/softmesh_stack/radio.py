"""Radio configuration for the Heltec KISS modem.

The KISS modem firmware exposes a SetHardware command (KISS type-byte 0x06)
with the following sub-commands relevant to radio configuration:

  0x01  GetIdentity   -> returns the modem's pub_key
  0x09  SetRadio      payload: freq (uint32 LE, Hz) | bw (uint32 LE, Hz)
                               | sf (uint8) | cr (uint8)
  0x0A  SetTxPower    payload: dBm (int8)
  0x0B  GetRadio      -> returns current settings
  0x0C  GetTxPower    -> returns current TX power
  0x11  GetVersion    -> returns the firmware version string
"""

from __future__ import annotations

from dataclasses import dataclass


class SetHardwareCmd:
    GET_IDENTITY = 0x01
    SET_RADIO = 0x09
    SET_TX_POWER = 0x0A
    GET_RADIO = 0x0B
    GET_TX_POWER = 0x0C
    GET_VERSION = 0x11


@dataclass(frozen=True, slots=True)
class RadioConfig:
    """A complete LoRa radio configuration."""

    name: str
    frequency_hz: int
    bandwidth_hz: int
    spreading_factor: int
    coding_rate: int
    tx_power_dbm: int = 22  # 22 dBm is typical for SX1262-class radios

    def __post_init__(self) -> None:
        if not 5 <= self.spreading_factor <= 12:
            raise ValueError(f"spreading_factor must be in 5..12, got {self.spreading_factor}")
        if not 5 <= self.coding_rate <= 8:
            raise ValueError(f"coding_rate must be in 5..8, got {self.coding_rate}")

    def encode_set_radio_payload(self) -> bytes:
        """Bytes for the SetRadio sub-command (after the sub-command byte)."""
        return (
            self.frequency_hz.to_bytes(4, "little")
            + self.bandwidth_hz.to_bytes(4, "little")
            + bytes([self.spreading_factor, self.coding_rate])
        )


# Current MeshCore Netherlands channel.
#
# The Dutch community migrated from SF8/CR8 to SF7/CR5 on 2026-05-09 13:00
# after a coordinated SF Test Weekend (6-8 March 2026) showed the busier mesh
# was getting congested at SF8 (traceroute success ~38%) and that SF7
# (~53% success, ~3x channel capacity) was the better tradeoff. Frequency
# and bandwidth were not changed.
#
#   Sources:
#     https://assets.woodwar.com/meshcore_sf7_switch_instructions.pdf
#     https://settings.woodwar.com/en/
NL = RadioConfig(
    name="NL",
    frequency_hz=869_618_000,
    bandwidth_hz=62_500,
    spreading_factor=7,
    coding_rate=5,
)

# The pre-2026-05-09 NL channel, kept here for interop with nodes that
# haven't migrated yet.
NL_LEGACY_SF8 = RadioConfig(
    name="NL_LEGACY_SF8",
    frequency_hz=869_618_000,
    bandwidth_hz=62_500,
    spreading_factor=8,
    coding_rate=8,
)

# The default EU/UK Narrow preset some MeshCore documentation references.
# Kept here as a fallback for nodes that haven't moved to the NL channel.
EU_UK_NARROW = RadioConfig(
    name="EU_UK_NARROW",
    frequency_hz=869_525_000,
    bandwidth_hz=62_500,
    spreading_factor=7,
    coding_rate=5,
)

PRESETS: dict[str, RadioConfig] = {
    NL.name: NL,
    NL_LEGACY_SF8.name: NL_LEGACY_SF8,
    EU_UK_NARROW.name: EU_UK_NARROW,
}


def get_preset(name: str) -> RadioConfig:
    try:
        return PRESETS[name]
    except KeyError as exc:
        raise ValueError(f"unknown radio preset {name!r}; known: {sorted(PRESETS)}") from exc


def build_set_radio_frame(config: RadioConfig) -> bytes:
    """Payload bytes for the KISS SetHardware data frame (sub-cmd 0x09)."""
    return bytes([SetHardwareCmd.SET_RADIO]) + config.encode_set_radio_payload()


def build_set_tx_power_frame(dbm: int) -> bytes:
    """Payload bytes for the KISS SetHardware data frame (sub-cmd 0x0A)."""
    return bytes([SetHardwareCmd.SET_TX_POWER, dbm & 0xFF])


def build_get_identity_frame() -> bytes:
    return bytes([SetHardwareCmd.GET_IDENTITY])


def build_get_radio_frame() -> bytes:
    return bytes([SetHardwareCmd.GET_RADIO])


def build_get_version_frame() -> bytes:
    return bytes([SetHardwareCmd.GET_VERSION])
