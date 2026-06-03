# softmesh

Python microservices stack for the [MeshCore](https://meshcore.co.uk) LoRa mesh
network, built on top of a Heltec v3 running the KISS modem firmware.

The radio is used as a dumb LoRa transport (raw KISS type-0x00 frames). All
MeshCore protocol logic — identities, packet construction, encryption,
routing — runs on the host. Each service has its own Ed25519 keypair and
appears as a distinct node on the mesh. Services share the single radio via a
broker-agnostic MQTT bus.

## Packages

- **`softmesh-stack`** — shared library: KISS framing, packet codec, crypto,
  identity storage, MQTT transport helpers.
- **`mesh-gateway`** — owns the USB serial link to the Heltec; bridges raw
  LoRa frames to and from MQTT.
- **`home-auto-client`** — first real service. Initial scope: an echo server
  that replies to every direct message.
- **`observer`** — captures mesh traffic from the local bus and republishes it
  to external collectors (Cornmeister, mc-radar).
- **`room-server`** — password-gated, store-and-forward room (SQLite).

Each deployable service installs a console script of the same name
(`mesh-gateway`, `home-auto-client`, `observer`, `room-server`).

## Development

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run pytest
```

## Running

The services talk to each other over an MQTT bus, so you need a broker running
first (e.g. a local [Mosquitto](https://mosquitto.org/)). By default each
service connects to `mqtt://localhost`; override with `<PREFIX>_MQTT_URL` (see
[Configuration](#configuration)).

Bring the radio online by pointing the gateway at the Heltec's serial device
and applying a regional preset:

```sh
uv run mesh-gateway --serial /dev/ttyUSB0 --region NL --tx-power 22 -v
```

Then start whichever services you need, e.g.:

```sh
uv run home-auto-client -v
uv run room-server --room-name "My Room" -v
uv run observer -v
```

### Tools

- **`mesh-sniff`** — subscribe to the gateway's `mesh/rx` topic and print
  decoded packets; handy for checking the codec against real on-air traffic.
- **`tools/echo_loopback.py`** — exercise the echo server over MQTT only (no
  radio): `uv run python tools/echo_loopback.py`.
- **`tools/room_loopback.py`** — drive the full room login/post/push flow over
  MQTT only: start the room with `ROOM_GUEST_PASSWORD=guestpw uv run room-server`,
  then `uv run python tools/room_loopback.py --password guestpw`.

### Containers

A single multi-service `Dockerfile` builds any deployable service via the
`SERVICE` build arg. `build.sh` wraps `docker buildx` to build (and optionally
push) images for each service:

```sh
PUSH=false ./build.sh mesh-gateway   # build one service locally
REGISTRY=my-registry.example ./build.sh   # build + push all services
```

## Configuration

Every setting is resolved from environment variables (CLI flags, where present,
just set the matching env var), so the services run unattended in containers /
Kubernetes. Each service uses its own prefix: `MESH_GATEWAY_`, `HOMEAUTO_`,
`ROOM_`, `OBSERVER_`.

### Identity (keypair)

A node's identity is a 32-byte Ed25519 seed (the public key is derived). Provide
it as hex via `<PREFIX>_IDENTITY_SEED` — ideal for a Kubernetes Secret — and
nothing is read from or written to disk. Without it, the service loads
`<PREFIX>_IDENTITY` (a file path) or generates and saves a new identity there.

```sh
# Generate a seed for a Secret:
uv run python -c "import os; print(os.urandom(32).hex())"
```

`ROOM_IDENTITY_SEED`, `HOMEAUTO_IDENTITY_SEED`, `OBSERVER_IDENTITY_SEED` (the
gateway has no mesh identity).

### MQTT (shared across services)

Set a base URL and/or discrete overrides; discrete vars win, so the password can
come from its own Secret rather than being embedded in a URL.

| Var (per prefix) | Meaning |
|---|---|
| `<PREFIX>_MQTT_URL` | `mqtt://` / `mqtts://` / `ws://` / `wss://[user:pass@]host[:port][/path]` |
| `<PREFIX>_MQTT_HOST` / `_PORT` | override host / port |
| `<PREFIX>_MQTT_USERNAME` / `_PASSWORD` | auth (password → Secret) |
| `<PREFIX>_MQTT_TLS` | `true` to force TLS (implied by `mqtts://` / `wss://`) |
| `<PREFIX>_MQTT_WS_PATH` | override WebSocket path (use URL path otherwise) |
| `<PREFIX>_MQTT_CA_CERT` | CA bundle to verify the broker |
| `<PREFIX>_MQTT_CLIENT_CERT` / `_CLIENT_KEY` | client cert/key for mTLS |
| `<PREFIX>_MQTT_TLS_INSECURE` | `true` to skip cert/hostname checks |

### Radio (`mesh-gateway`)

`MESH_GATEWAY_SERIAL`, `MESH_GATEWAY_BAUD`, `MESH_GATEWAY_TX_POWER`, and either a
named preset `MESH_GATEWAY_RADIO_PRESET` (`NL`, `NL_LEGACY_SF8`, `EU_UK_NARROW`)
or a full custom set: `MESH_GATEWAY_FREQ_HZ`, `MESH_GATEWAY_BW_HZ`,
`MESH_GATEWAY_SF`, `MESH_GATEWAY_CR` (all four override the preset).
`MESH_GATEWAY_DUTY_CYCLE` (default `0.10`) caps transmit airtime as a fraction
of each 60-second window to stay within regional duty-cycle limits.

### Other per-service settings

Topics (`<PREFIX>_RX_TOPIC` / `_TX_TOPIC` / `_STATUS_TOPIC`), advert cadence
(`<PREFIX>_ADVERT_INTERVAL[_S]`, `<PREFIX>_ADVERT_FLOOD`), and service specifics:
`ROOM_DB` (SQLite path — mount a writable volume), `ROOM_TITLE`,
`ROOM_ADMIN_PASSWORD` / `ROOM_GUEST_PASSWORD`, `ROOM_PUSH_*`, `HOMEAUTO_ECHO_PREFIX`,
`HOMEAUTO_CONTACT_CACHE`, etc. See each package's `config.py` for the full list
and defaults.

> On a read-only root filesystem, supply the identity via `*_IDENTITY_SEED` and
> point `ROOM_DB` / `HOMEAUTO_CONTACT_CACHE` at a mounted writable volume.

## License

Released under the [MIT License](./LICENSE), the same license as the upstream
[MeshCore](https://github.com/meshcore-dev/MeshCore) firmware.
