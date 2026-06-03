"""Shared, env-driven MQTT connection config for all services.

Every service resolves its broker connection the same way via
``MqttConfig.from_env(PREFIX)``. Settings come from a base URL plus discrete
overrides, so secrets (notably the password) can be injected as their own env
vars from a Kubernetes Secret rather than embedded in a URL string.

For prefix ``ROOM`` the recognised variables are:

    ROOM_MQTT_URL          mqtt(s):// or ws(s)://[user:pass@]host[:port][/path]
    ROOM_MQTT_HOST         override host
    ROOM_MQTT_PORT         override port
    ROOM_MQTT_USERNAME     override username
    ROOM_MQTT_PASSWORD     override password  (put this in a Secret)
    ROOM_MQTT_TLS          true/false — enable TLS (implied by mqtts:// scheme)
    ROOM_MQTT_WS_PATH      override WebSocket path (ws(s):// URL path otherwise)
    ROOM_MQTT_CA_CERT      path to a CA bundle to verify the broker
    ROOM_MQTT_CLIENT_CERT  path to a client cert (mTLS)
    ROOM_MQTT_CLIENT_KEY   path to the client key (mTLS)
    ROOM_MQTT_TLS_INSECURE true/false — skip broker cert/hostname verification
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    import aiomqtt


def _parse_bool(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True, slots=True)
class MqttConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    use_tls: bool
    transport: Literal["tcp", "websockets"] = "tcp"
    websocket_path: str | None = None
    tls_ca_cert: str | None = None
    tls_certfile: str | None = None
    tls_keyfile: str | None = None
    tls_insecure: bool = False

    @classmethod
    def from_env(cls, prefix: str, *, default_url: str = "mqtt://localhost") -> MqttConfig:
        env = os.environ
        url = env.get(f"{prefix}_MQTT_URL", default_url)
        parsed = urlparse(url)
        if parsed.scheme not in ("mqtt", "mqtts", "ws", "wss"):
            raise ValueError(
                f"unsupported MQTT scheme {parsed.scheme!r}; use mqtt(s):// or ws(s)://"
            )

        transport: Literal["tcp", "websockets"]
        if parsed.scheme in ("ws", "wss"):
            transport = "websockets"
        else:
            transport = "tcp"

        use_tls = _parse_bool(
            env.get(f"{prefix}_MQTT_TLS"), default=parsed.scheme in ("mqtts", "wss")
        )
        host = env.get(f"{prefix}_MQTT_HOST") or parsed.hostname or "localhost"
        if transport == "websockets":
            default_port = 443 if use_tls else 80
        else:
            default_port = 8883 if use_tls else 1883

        port = int(env.get(f"{prefix}_MQTT_PORT") or parsed.port or default_port)
        username = env.get(f"{prefix}_MQTT_USERNAME", parsed.username) or None
        password = env.get(f"{prefix}_MQTT_PASSWORD", parsed.password) or None
        websocket_path = env.get(f"{prefix}_MQTT_WS_PATH") or (parsed.path or None)
        return cls(
            host=host,
            port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            transport=transport,
            websocket_path=websocket_path,
            tls_ca_cert=env.get(f"{prefix}_MQTT_CA_CERT") or None,
            tls_certfile=env.get(f"{prefix}_MQTT_CLIENT_CERT") or None,
            tls_keyfile=env.get(f"{prefix}_MQTT_CLIENT_KEY") or None,
            tls_insecure=_parse_bool(env.get(f"{prefix}_MQTT_TLS_INSECURE"), default=False),
        )

    def tls_params(self) -> aiomqtt.TLSParameters | None:
        if not self.use_tls:
            return None
        import ssl

        import aiomqtt

        return aiomqtt.TLSParameters(
            ca_certs=self.tls_ca_cert,
            certfile=self.tls_certfile,
            keyfile=self.tls_keyfile,
            cert_reqs=ssl.CERT_NONE if self.tls_insecure else ssl.CERT_REQUIRED,
        )

    def client(self, **overrides: Any) -> aiomqtt.Client:
        """Build an ``aiomqtt.Client`` for this broker. Extra kwargs override."""
        import aiomqtt

        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "tls_params": self.tls_params(),
            "transport": self.transport,
        }
        if self.use_tls and self.tls_insecure:
            kwargs["tls_insecure"] = True
        if self.transport == "websockets" and self.websocket_path:
            kwargs["websocket_path"] = self.websocket_path
        kwargs.update(overrides)
        return aiomqtt.Client(**kwargs)
