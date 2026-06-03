from __future__ import annotations

import json

from softmesh_stack.advert import AdvertData, AdvertType, decode_advert, encode_advert
from softmesh_stack.crypto import derive_pub_key
from softmesh_stack.identity import Identity
from softmesh_stack.packet import (
    Packet,
    PayloadType,
    PayloadVer,
    RouteType,
    decode_packet,
    encode_packet,
)
from observer.reporter import _status_payload, build_event, build_self_advert


def _build_advert_packet(name: str) -> bytes:
    seed = bytes.fromhex("11" * 32)
    pub = derive_pub_key(seed)
    payload = encode_advert(seed, pub, 1_700_000_000, AdvertData(type=AdvertType.CHAT, name=name))
    pkt = Packet(
        route_type=RouteType.FLOOD,
        payload_type=PayloadType.ADVERT,
        payload_ver=PayloadVer.V1,
        transport_codes=None,
        path=b"",
        payload=payload,
    )
    return encode_packet(pkt)


def test_build_event_matches_collector_schema() -> None:
    raw = _build_advert_packet("observer-test")
    event = build_event(raw, origin="obs", origin_id="ABCD")

    # Flat mctomqtt-style schema expected by Cornmeister / mc-radar.
    assert event["origin"] == "obs"
    assert event["origin_id"] == "ABCD"
    assert event["type"] == "PACKET"
    assert event["direction"] == "rx"
    assert event["packet_type"] == "4"  # ADVERT
    assert event["route"] == "F"  # FLOOD
    assert event["len"] == str(len(raw))
    assert event["raw"] == raw.hex().upper()
    assert event["SNR"] == "Unknown"
    assert event["RSSI"] == "Unknown"
    # hash is 16 uppercase hex chars and not the all-zero error sentinel
    assert len(event["hash"]) == 16
    assert event["hash"] != "0000000000000000"


def test_build_event_handles_undecodable_packet() -> None:
    event = build_event(b"\xff", origin="obs", origin_id="ABCD")
    assert event["type"] == "PACKET"
    assert event["route"] == "U"
    assert event["raw"] == "FF"


def test_build_self_advert_carries_name_and_location() -> None:
    ident = Identity.from_seed(bytes.fromhex("44" * 32), name="seed-name")
    wire = build_self_advert(ident, name="My Observer", lat=52.37, lon=4.9, flood=True)

    pkt = decode_packet(wire)
    assert pkt.payload_type == PayloadType.ADVERT
    assert pkt.route_type == RouteType.FLOOD

    advert = decode_advert(pkt.payload)
    assert advert.signature_valid is True
    assert advert.pub_key == ident.pub_key
    assert advert.app_data.name == "My Observer"
    assert round(advert.app_data.lat, 5) == 52.37
    assert round(advert.app_data.lon, 5) == 4.9


def test_status_payload_includes_location_when_set() -> None:
    with_loc = json.loads(
        _status_payload("online", origin="obs", origin_id="ABCD", lat=52.337, lon=5.236)
    )
    assert with_loc["status"] == "online"
    assert with_loc["origin"] == "obs"
    assert with_loc["latitude"] == 52.337
    assert with_loc["longitude"] == 5.236

    without = json.loads(_status_payload("online", origin="obs", origin_id="ABCD"))
    assert "latitude" not in without
    assert "longitude" not in without


def test_build_self_advert_without_location_is_zero_hop() -> None:
    ident = Identity.from_seed(bytes.fromhex("55" * 32))
    wire = build_self_advert(ident, name="obs", lat=None, lon=None, flood=False)
    pkt = decode_packet(wire)
    assert pkt.route_type == RouteType.DIRECT
    advert = decode_advert(pkt.payload)
    assert advert.app_data.lat is None
    assert advert.app_data.lon is None