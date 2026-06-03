"""MeshCore node identity: 32-byte Ed25519 seed + display name.

Persisted to disk in the official MeshCore layout:
  offset 0..31  : 32-byte private seed
  offset 32..63 : 32-byte Ed25519 public key
  offset 64..95 : up to 32 bytes UTF-8 display name (NUL-padded)
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path

from . import crypto

IDENTITY_NAME_SIZE = 32


@dataclass(slots=True)
class Identity:
    seed: bytes
    pub_key: bytes
    name: str = ""

    def __post_init__(self) -> None:
        if len(self.seed) != crypto.SEED_SIZE:
            raise ValueError(f"seed must be {crypto.SEED_SIZE} bytes")
        if len(self.pub_key) != crypto.PUB_KEY_SIZE:
            raise ValueError(f"pub_key must be {crypto.PUB_KEY_SIZE} bytes")

    @classmethod
    def generate(cls, name: str = "") -> Identity:
        seed, pub_key = crypto.generate_keypair()
        return cls(seed=seed, pub_key=pub_key, name=name)

    @classmethod
    def from_seed(cls, seed: bytes, name: str = "") -> Identity:
        return cls(seed=seed, pub_key=crypto.derive_pub_key(seed), name=name)

    @classmethod
    def load(cls, path: Path | str) -> Identity:
        data = Path(path).read_bytes()
        if len(data) < crypto.SEED_SIZE + crypto.PUB_KEY_SIZE:
            raise ValueError(f"identity file too short: {len(data)} bytes")
        seed = data[: crypto.SEED_SIZE]
        pub_key = data[crypto.SEED_SIZE : crypto.SEED_SIZE + crypto.PUB_KEY_SIZE]
        # Recompute pub_key to detect file corruption.
        expected_pub = crypto.derive_pub_key(seed)
        if pub_key != expected_pub:
            raise ValueError("identity file pub_key does not match seed")
        name = ""
        name_off = crypto.SEED_SIZE + crypto.PUB_KEY_SIZE
        if len(data) > name_off:
            name_bytes = data[name_off : name_off + IDENTITY_NAME_SIZE]
            name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return cls(seed=seed, pub_key=pub_key, name=name)

    def save(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        out = bytearray(self.seed + self.pub_key)
        if self.name:
            name_bytes = self.name.encode("utf-8")[: IDENTITY_NAME_SIZE - 1]
            out += name_bytes.ljust(IDENTITY_NAME_SIZE, b"\x00")
        p.write_bytes(bytes(out))
        # Best-effort tighten permissions: identity files contain the private seed.
        with contextlib.suppress(OSError):
            p.chmod(0o600)

    @property
    def address(self) -> int:
        """Routing-layer 1-byte short address (first byte of the public key)."""
        return crypto.path_hash(self.pub_key)

    def sign(self, message: bytes) -> bytes:
        return crypto.sign(self.seed, message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        return crypto.verify(self.pub_key, signature, message)

    def calc_shared_secret(self, peer_pub_key: bytes) -> bytes:
        return crypto.calc_shared_secret(self.seed, peer_pub_key)


def resolve_identity(
    seed_hex: str | None,
    path: Path | str,
    name: str = "",
) -> tuple[Identity, str]:
    """Resolve a service's node identity for flexible deployment.

    Priority:
      1. ``seed_hex`` — a 32-byte hex private seed, e.g. injected from a
         Kubernetes Secret as an env var. The public key is derived; nothing is
         read from or written to disk (works on a read-only filesystem).
      2. an existing identity file at ``path``.
      3. a freshly generated identity, persisted to ``path``.

    Returns ``(identity, source)`` where source is ``"env"``, ``"file"``, or
    ``"generated"``. Raises ``ValueError`` on a malformed seed so misconfiguration
    fails fast at startup rather than silently using a random key.
    """
    if seed_hex and seed_hex.strip():
        cleaned = seed_hex.strip().removeprefix("0x")
        try:
            seed = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError("identity seed must be hex (64 chars for a 32-byte seed)") from exc
        return Identity.from_seed(seed, name=name), "env"

    p = Path(path)
    if p.exists():
        return Identity.load(p), "file"
    ident = Identity.generate(name=name)
    ident.save(p)
    return ident, "generated"
