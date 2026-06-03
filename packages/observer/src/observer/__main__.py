"""Entry point for the observer service."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from .config import ObserverConfig
from .reporter import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="observer", description=__doc__)
    parser.add_argument("--mqtt-url", help="local bus mqtt://[user:pass@]host[:port]")
    parser.add_argument("--corn-mqtt-url", help="override Cornmeister MQTT URL")
    parser.add_argument("--radar-mqtt-url", help="override mc-radar MQTT URL")
    parser.add_argument("--identity", help="path to the identity file")
    parser.add_argument("--iata", help="IATA region code for topic construction")
    parser.add_argument(
        "--token-audience",
        help="JWT 'aud' claim required by the collector brokers (if any)",
    )
    parser.add_argument("--name", help="observer display name (advert + status origin)")
    parser.add_argument("--lat", type=float, help="observer latitude for the self-advert")
    parser.add_argument("--lon", type=float, help="observer longitude for the self-advert")
    parser.add_argument(
        "--advert-interval",
        type=int,
        help="seconds between self-advert broadcasts (0 = disabled)",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()

    logging.basicConfig(
        level=max(logging.WARNING - 10 * args.verbose, logging.DEBUG),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.mqtt_url:
        os.environ["OBSERVER_MQTT_URL"] = args.mqtt_url
    if args.corn_mqtt_url:
        os.environ["OBSERVER_CORN_MQTT_URL"] = args.corn_mqtt_url
    if args.radar_mqtt_url:
        os.environ["OBSERVER_RADAR_MQTT_URL"] = args.radar_mqtt_url
    if args.identity:
        os.environ["OBSERVER_IDENTITY"] = args.identity
    if args.iata:
        os.environ["OBSERVER_IATA"] = args.iata
    if args.token_audience:
        os.environ["OBSERVER_TOKEN_AUDIENCE"] = args.token_audience
    if args.name:
        os.environ["OBSERVER_NAME"] = args.name
    if args.lat is not None:
        os.environ["OBSERVER_LAT"] = str(args.lat)
    if args.lon is not None:
        os.environ["OBSERVER_LON"] = str(args.lon)
    if args.advert_interval is not None:
        os.environ["OBSERVER_ADVERT_INTERVAL"] = str(args.advert_interval)

    try:
        asyncio.run(run(ObserverConfig.from_env()))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())