"""Tests for radio configuration encoding."""

from __future__ import annotations

import pytest
from softmesh_stack import radio


def test_nl_preset_values() -> None:
    # NL switched from SF8/CR8 to SF7/CR5 on 2026-05-09.
    cfg = radio.get_preset("NL")
    assert cfg.frequency_hz == 869_618_000
    assert cfg.bandwidth_hz == 62_500
    assert cfg.spreading_factor == 7
    assert cfg.coding_rate == 5


def test_nl_legacy_sf8_preset_values() -> None:
    cfg = radio.get_preset("NL_LEGACY_SF8")
    assert cfg.frequency_hz == 869_618_000
    assert cfg.spreading_factor == 8
    assert cfg.coding_rate == 8


def test_eu_uk_narrow_preset_values() -> None:
    cfg = radio.get_preset("EU_UK_NARROW")
    assert cfg.frequency_hz == 869_525_000
    assert cfg.bandwidth_hz == 62_500
    assert cfg.spreading_factor == 7
    assert cfg.coding_rate == 5


def test_unknown_preset_raises() -> None:
    with pytest.raises(ValueError):
        radio.get_preset("MARS")


def test_encode_set_radio_payload_byte_layout() -> None:
    cfg = radio.RadioConfig(
        name="t",
        frequency_hz=0x12345678,
        bandwidth_hz=0xAABBCCDD,
        spreading_factor=9,
        coding_rate=7,
    )
    payload = cfg.encode_set_radio_payload()
    assert payload == bytes([0x78, 0x56, 0x34, 0x12, 0xDD, 0xCC, 0xBB, 0xAA, 9, 7])


def test_build_set_radio_frame_includes_subcmd() -> None:
    frame = radio.build_set_radio_frame(radio.NL)
    assert frame[0] == radio.SetHardwareCmd.SET_RADIO  # 0x09
    assert len(frame) == 1 + 4 + 4 + 1 + 1


def test_set_tx_power_frame() -> None:
    assert radio.build_set_tx_power_frame(22) == bytes([radio.SetHardwareCmd.SET_TX_POWER, 22])


def test_rejects_invalid_sf() -> None:
    with pytest.raises(ValueError):
        radio.RadioConfig(
            name="bad", frequency_hz=1, bandwidth_hz=1, spreading_factor=13, coding_rate=5
        )


def test_rejects_invalid_cr() -> None:
    with pytest.raises(ValueError):
        radio.RadioConfig(
            name="bad", frequency_hz=1, bandwidth_hz=1, spreading_factor=8, coding_rate=4
        )
