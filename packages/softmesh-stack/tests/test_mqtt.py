"""Tests for the shared env-driven MqttConfig."""

from __future__ import annotations

from softmesh_stack.mqtt import MqttConfig

PREFIX = "TESTSVC"


def _clear(monkeypatch) -> None:
    for suffix in (
        "URL",
        "HOST",
        "PORT",
        "USERNAME",
        "PASSWORD",
        "TLS",
        "WS_PATH",
        "CA_CERT",
        "CLIENT_CERT",
        "CLIENT_KEY",
        "TLS_INSECURE",
    ):
        monkeypatch.delenv(f"{PREFIX}_MQTT_{suffix}", raising=False)


def test_defaults(monkeypatch) -> None:
    _clear(monkeypatch)
    cfg = MqttConfig.from_env(PREFIX)
    assert (cfg.host, cfg.port, cfg.use_tls) == ("localhost", 1883, False)
    assert cfg.username is None and cfg.password is None


def test_url_with_auth(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_URL", "mqtt://user:pass@broker:1884")
    cfg = MqttConfig.from_env(PREFIX)
    assert (cfg.host, cfg.port, cfg.username, cfg.password) == ("broker", 1884, "user", "pass")


def test_mqtts_scheme_implies_tls_and_port(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_URL", "mqtts://broker")
    cfg = MqttConfig.from_env(PREFIX)
    assert cfg.use_tls is True and cfg.port == 8883


def test_discrete_overrides_take_precedence(monkeypatch) -> None:
    # Password from its own var (as it would be from a K8s Secret) overrides the URL.
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_URL", "mqtt://urluser:urlpass@urlhost:1883")
    monkeypatch.setenv(f"{PREFIX}_MQTT_HOST", "real-broker")
    monkeypatch.setenv(f"{PREFIX}_MQTT_PORT", "1885")
    monkeypatch.setenv(f"{PREFIX}_MQTT_USERNAME", "svc")
    monkeypatch.setenv(f"{PREFIX}_MQTT_PASSWORD", "secret-from-k8s")
    cfg = MqttConfig.from_env(PREFIX)
    assert cfg.host == "real-broker"
    assert cfg.port == 1885
    assert cfg.username == "svc"
    assert cfg.password == "secret-from-k8s"


def test_tls_flag_and_certs(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_TLS", "true")
    monkeypatch.setenv(f"{PREFIX}_MQTT_CA_CERT", "/etc/ssl/ca.pem")
    monkeypatch.setenv(f"{PREFIX}_MQTT_CLIENT_CERT", "/etc/ssl/client.pem")
    monkeypatch.setenv(f"{PREFIX}_MQTT_CLIENT_KEY", "/etc/ssl/client.key")
    monkeypatch.setenv(f"{PREFIX}_MQTT_TLS_INSECURE", "yes")
    cfg = MqttConfig.from_env(PREFIX)
    assert cfg.use_tls is True
    assert cfg.port == 8883  # TLS implies the default secure port
    assert cfg.tls_ca_cert == "/etc/ssl/ca.pem"
    assert cfg.tls_certfile == "/etc/ssl/client.pem"
    assert cfg.tls_keyfile == "/etc/ssl/client.key"
    assert cfg.tls_insecure is True
    # tls_params() should build real aiomqtt TLS params when TLS is on.
    assert cfg.tls_params() is not None


def test_wss_websocket(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_URL", "wss://broker/ingest")
    cfg = MqttConfig.from_env(PREFIX)
    assert cfg.transport == "websockets"
    assert cfg.use_tls is True
    assert cfg.port == 443
    assert cfg.websocket_path == "/ingest"


def test_websocket_path_override(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv(f"{PREFIX}_MQTT_URL", "wss://broker/default")
    monkeypatch.setenv(f"{PREFIX}_MQTT_WS_PATH", "/override")
    cfg = MqttConfig.from_env(PREFIX)
    assert cfg.websocket_path == "/override"
