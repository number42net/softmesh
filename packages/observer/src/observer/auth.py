"""MeshCore JWT-style authentication for the public collector brokers.

The DutchMeshCore / Let's Mesh collector brokers (Cornmeister, mc-radar)
authenticate observers with a self-signed token that proves ownership of the
observer's Ed25519 public key:

* **username** ``v1_<PUBLIC_KEY_HEX_UPPER>``
* **password** a JWT-style token ``base64url(header).base64url(payload).hex(sig)``
  where the signature is Ed25519 over the ASCII ``"header.payload"`` signing
  input. (Note: the signature segment is hex, not base64url — this matches the
  MeshCore reference implementation, ``agessaman/meshcore-packet-capture``.)

The broker ACL only grants publish rights to ``meshcore/<IATA>/<PUBLIC_KEY>/…``
for the key carried in the token, so a self-signed token is sufficient — no
pre-registration step beyond the broker recognising the key.
"""

from __future__ import annotations

import base64
import json
import time

from softmesh_stack.identity import Identity


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def auth_username(identity: Identity) -> str:
    """The MQTT username the collector brokers expect for this identity."""
    return f"v1_{identity.pub_key.hex().upper()}"


# The collector brokers reject tokens without an expiry; the reference
# implementation defaults to a 24h lifetime.
DEFAULT_TOKEN_LIFETIME_S = 86400


def build_auth_token(
    identity: Identity,
    *,
    aud: str | None = None,
    exp: int | None = None,
    iat: int | None = None,
    lifetime_seconds: int = DEFAULT_TOKEN_LIFETIME_S,
) -> str:
    """Build a MeshCore JWT-style token signed by ``identity``.

    An ``exp`` claim is always emitted (``iat + lifetime_seconds`` unless ``exp``
    is given explicitly) — the brokers reject tokens with no expiry.
    """
    issued = int(time.time()) if iat is None else iat
    header = {"alg": "Ed25519", "typ": "JWT"}
    payload: dict[str, object] = {
        "publicKey": identity.pub_key.hex().upper(),
        "iat": issued,
        "exp": (issued + lifetime_seconds) if exp is None else exp,
    }
    if aud is not None:
        payload["aud"] = aud

    header_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode("ascii")
    signature = identity.sign(signing_input)
    return f"{header_enc}.{payload_enc}.{signature.hex()}"
