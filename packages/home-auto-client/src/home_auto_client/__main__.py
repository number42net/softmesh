"""Entry point for `home-auto-client`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from .config import EchoConfig
from .echo_server import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="home-auto-client", description=__doc__)
    parser.add_argument(
        "--mqtt-url", help="mqtt://[user:pass@]host[:port] (overrides HOMEAUTO_MQTT_URL)"
    )
    parser.add_argument("--name", help="display name to advertise (overrides HOMEAUTO_NAME)")
    parser.add_argument(
        "--identity",
        help="path to the identity file (overrides HOMEAUTO_IDENTITY); created on first run",
    )
    parser.add_argument(
        "--advert-interval",
        type=float,
        help="seconds between ADVERT broadcasts (overrides HOMEAUTO_ADVERT_INTERVAL_S)",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=max(logging.WARNING - 10 * args.verbose, logging.DEBUG),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.mqtt_url:
        os.environ["HOMEAUTO_MQTT_URL"] = args.mqtt_url
    if args.name:
        os.environ["HOMEAUTO_NAME"] = args.name
    if args.identity:
        os.environ["HOMEAUTO_IDENTITY"] = args.identity
    if args.advert_interval is not None:
        os.environ["HOMEAUTO_ADVERT_INTERVAL_S"] = str(args.advert_interval)

    try:
        asyncio.run(run(EchoConfig.from_env()))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
