from __future__ import annotations

import base64
import json

from softmesh_stack.identity import Identity
from observer.auth import auth_username, build_auth_token


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_auth_username_format() -> None:
    ident = Identity.from_seed(bytes.fromhex("33" * 32), name="obs")
    assert auth_username(ident) == f"v1_{ident.pub_key.hex().upper()}"


def test_build_auth_token_structure_and_signature() -> None:
    ident = Identity.from_seed(bytes.fromhex("33" * 32), name="obs")
    token = build_auth_token(ident, iat=1_700_000_000)

    header_enc, payload_enc, sig_hex = token.split(".")

    header = json.loads(_b64url_decode(header_enc))
    assert header == {"alg": "Ed25519", "typ": "JWT"}

    payload = json.loads(_b64url_decode(payload_enc))
    assert payload["publicKey"] == ident.pub_key.hex().upper()
    assert payload["iat"] == 1_700_000_000
    # An expiry claim is always present (brokers reject tokens without one).
    assert payload["exp"] == 1_700_000_000 + 86400

    # Signature is hex over the ASCII "header.payload" signing input and must
    # verify against the observer's public key.
    signing_input = f"{header_enc}.{payload_enc}".encode("ascii")
    assert ident.verify(bytes.fromhex(sig_hex), signing_input)
