"""Entry point for `mesh-gateway`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from .config import GatewayConfig
from .gateway import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="mesh-gateway", description=__doc__)
    parser.add_argument(
        "--serial", help="USB serial device (overrides MESH_GATEWAY_SERIAL)", default=None
    )
    parser.add_argument(
        "--mqtt-url",
        help="mqtt://[user:pass@]host[:port] (overrides MESH_GATEWAY_MQTT_URL)",
        default=None,
    )
    parser.add_argument("--baud", type=int, default=None)
    parser.add_argument(
        "--region",
        choices=["NL", "NL_LEGACY_SF8", "EU_UK_NARROW"],
        default=None,
        help="apply a radio preset (frequency/BW/SF/CR) to the modem at startup",
    )
    parser.add_argument(
        "--tx-power",
        type=int,
        default=None,
        help="set TX power in dBm at startup",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="increase logging verbosity"
    )
    args = parser.parse_args()

    level = logging.WARNING - 10 * args.verbose
    logging.basicConfig(
        level=max(level, logging.DEBUG),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.serial:
        os.environ["MESH_GATEWAY_SERIAL"] = args.serial
    if args.mqtt_url:
        os.environ["MESH_GATEWAY_MQTT_URL"] = args.mqtt_url
    if args.baud:
        os.environ["MESH_GATEWAY_BAUD"] = str(args.baud)
    if args.region:
        os.environ["MESH_GATEWAY_RADIO_PRESET"] = args.region
    if args.tx_power is not None:
        os.environ["MESH_GATEWAY_TX_POWER"] = str(args.tx_power)

    config = GatewayConfig.from_env()
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
