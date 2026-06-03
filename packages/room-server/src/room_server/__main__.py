"""Entry point for `room-server`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from .config import RoomConfig
from .protocol import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="room-server", description=__doc__)
    parser.add_argument(
        "--mqtt-url", help="mqtt://[user:pass@]host[:port] (overrides ROOM_MQTT_URL)"
    )
    parser.add_argument("--name", help="display name to advertise (overrides ROOM_NAME)")
    parser.add_argument("--room-name", help="room title (overrides ROOM_TITLE)")
    parser.add_argument("--identity", help="identity file path (overrides ROOM_IDENTITY)")
    parser.add_argument("--db", help="SQLite database path (overrides ROOM_DB)")
    parser.add_argument(
        "--advert-interval",
        type=float,
        help="seconds between ADVERT broadcasts (overrides ROOM_ADVERT_INTERVAL_S)",
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
        os.environ["ROOM_MQTT_URL"] = args.mqtt_url
    if args.name:
        os.environ["ROOM_NAME"] = args.name
    if args.room_name:
        os.environ["ROOM_TITLE"] = args.room_name
    if args.identity:
        os.environ["ROOM_IDENTITY"] = args.identity
    if args.db:
        os.environ["ROOM_DB"] = args.db
    if args.advert_interval is not None:
        os.environ["ROOM_ADVERT_INTERVAL_S"] = str(args.advert_interval)

    try:
        asyncio.run(run(RoomConfig.from_env()))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
