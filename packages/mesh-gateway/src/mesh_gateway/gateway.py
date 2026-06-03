"""Gateway: bridges the Heltec KISS modem (USB serial) and an MQTT bus.

The gateway is intentionally protocol-agnostic. It speaks KISS to the radio
and shuttles only the data-frame payloads (KISS command 0x00) to/from MQTT.
Services on the bus decode the MeshCore protocol themselves.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from collections import deque

import serial_asyncio
from serial import SerialException
from aiomqtt import MqttError
from softmesh_stack import radio
from softmesh_stack.kiss import KissCommand, KissDecoder, KissFrame, data_frame, encode

from .config import GatewayConfig

log = logging.getLogger(__name__)


def _airtime_seconds(payload_len: int, cfg: radio.RadioConfig | None) -> float:
    if cfg is None:
        return 1.0
    sf = cfg.spreading_factor
    bw = cfg.bandwidth_hz
    cr = cfg.coding_rate
    preamble = 8
    crc_on = 1
    ih = 0
    de = 1 if sf >= 11 else 0
    pl = payload_len
    t_sym = (2**sf) / bw
    t_preamble = (preamble + 4.25) * t_sym
    num = 8 * pl - 4 * sf + 28 + 16 * crc_on - 20 * ih
    den = 4 * (sf - 2 * de)
    payload_symb_nb = 8 + max((num + den - 1) // den * (cr + 4), 0)
    t_payload = payload_symb_nb * t_sym
    return max(t_preamble + t_payload, 0.001)


def _write_set_hardware(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Write a KISS SetHardware frame (type byte 0x06) to the modem."""
    frame = encode(KissFrame(port=0, command=KissCommand.SET_HARDWARE, data=payload))
    writer.write(frame)


async def run(config: GatewayConfig) -> None:
    serial_backoff = 1.0
    while True:
        try:
            log.info("opening serial %s @ %d baud", config.serial_port, config.baud)
            reader, writer = await serial_asyncio.open_serial_connection(
                url=config.serial_port,
                baudrate=config.baud,
            )
            break
        except SerialException as exc:
            log.warning(
                "failed to open serial %s (%s); retrying in %.1fs",
                config.serial_port,
                exc,
                serial_backoff,
            )
            await asyncio.sleep(serial_backoff)
            serial_backoff = min(serial_backoff * 2, 30.0)
        except Exception as exc:  # pragma: no cover - defensive guard
            log.warning(
                "unexpected serial error opening %s (%s); retrying in %.1fs",
                config.serial_port,
                exc,
                serial_backoff,
            )
            await asyncio.sleep(serial_backoff)
            serial_backoff = min(serial_backoff * 2, 30.0)
    decoder = KissDecoder()
    backoff = 1.0
    try:
        while True:
            try:
                async with config.mqtt.client() as mqtt:
                    m = config.mqtt
                    log.info("connected to MQTT %s:%d (tls=%s)", m.host, m.port, m.use_tls)
                    backoff = 1.0

                    radio_cfg = config.radio_config
                    if radio_cfg is not None:
                        log.info(
                            "configuring radio: name=%s freq=%d Hz bw=%d Hz sf=%d cr=%d",
                            radio_cfg.name,
                            radio_cfg.frequency_hz,
                            radio_cfg.bandwidth_hz,
                            radio_cfg.spreading_factor,
                            radio_cfg.coding_rate,
                        )
                        _write_set_hardware(writer, radio.build_set_radio_frame(radio_cfg))
                    if config.tx_power_dbm is not None:
                        log.info("configuring TX power: %d dBm", config.tx_power_dbm)
                        _write_set_hardware(writer, radio.build_set_tx_power_frame(config.tx_power_dbm))
                    await writer.drain()

                    try:
                        await mqtt.publish(
                            config.status_topic,
                            json.dumps(
                                {
                                    "state": "up",
                                    "radio_preset": config.radio_preset,
                                    "tx_power_dbm": config.tx_power_dbm,
                                }
                            ).encode(),
                            retain=True,
                        )
                    except MqttError as exc:
                        log.warning("failed to publish status (up): %s", exc)
                        raise

                    async def serial_to_mqtt() -> None:
                        while True:
                            chunk = await reader.read(256)
                            if not chunk:
                                log.warning("serial EOF; exiting RX loop")
                                return
                            for frame in decoder.feed(chunk):
                                if frame.command == KissCommand.DATA:
                                    log.debug("rx %d bytes: %s", len(frame.data), frame.data.hex())
                                    try:
                                        await mqtt.publish(config.rx_topic, frame.data)
                                    except MqttError as exc:
                                        log.warning("publish to RX topic failed: %s", exc)
                                        raise
                                else:
                                    log.debug("non-data KISS frame cmd=0x%02x", frame.command)

                    async def mqtt_to_serial() -> None:
                        await mqtt.subscribe(config.tx_topic)
                        radio_cfg = config.radio_config
                        window_s = 60.0
                        budget_s = window_s * config.duty_cycle
                        used = 0.0
                        usage: deque[tuple[float, float]] = deque()
                        queues: dict[str, deque[bytes]] = {}
                        order: deque[str] = deque()

                        async def flush() -> None:
                            nonlocal used
                            while order:
                                now = time.monotonic()
                                while usage and now - usage[0][0] >= window_s:
                                    _, a = usage.popleft()
                                    used = max(0.0, used - a)

                                sid = order[0]
                                q = queues.get(sid)
                                if not q:
                                    order.popleft()
                                    queues.pop(sid, None)
                                    continue
                                payload = q[0]
                                a = _airtime_seconds(len(payload), radio_cfg)
                                if used + a > budget_s:
                                    wait = window_s - (now - usage[0][0]) if usage else window_s
                                    await asyncio.sleep(max(wait, 0.01))
                                    continue
                                q.popleft()
                                order.rotate(-1)
                                if not q:
                                    queues.pop(sid, None)
                                    order.remove(sid)
                                log.debug("tx %d bytes: %s", len(payload), payload.hex())
                                writer.write(data_frame(payload))
                                await writer.drain()
                                ts = time.monotonic()
                                usage.append((ts, a))
                                used += a

                        async for msg in mqtt.messages:
                            payload = bytes(msg.payload) if isinstance(msg.payload, (bytes, bytearray)) else b""
                            if not payload:
                                continue
                            sid = hashlib.sha256(msg.topic.value.encode()).hexdigest()[:12]
                            if sid not in queues:
                                queues[sid] = deque()
                                order.append(sid)
                            queues[sid].append(payload)
                            await flush()

                    try:
                        async with asyncio.TaskGroup() as tg:
                            tg.create_task(serial_to_mqtt(), name="serial_to_mqtt")
                            tg.create_task(mqtt_to_serial(), name="mqtt_to_serial")
                    finally:
                        with contextlib.suppress(MqttError):
                            await mqtt.publish(
                                config.status_topic,
                                json.dumps({"state": "down"}).encode(),
                                retain=True,
                            )
            except MqttError as exc:
                log.warning("MQTT error; reconnecting in %.1fs (%s)", backoff, exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            break
    finally:
        writer.close()
