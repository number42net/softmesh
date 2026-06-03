"""Cryptographic primitives used by MeshCore.

MeshCore identities are Ed25519 keypairs. The same keypair is also used for
ECDH key agreement by transposing the Ed25519 keys onto the X25519 (Curve25519)
form — the libsodium convention. We use the `cryptography` package for
Ed25519 sign/verify, AES-128-CBC, HMAC-SHA256, and SHA-256, and `pynacl`
(libsodium bindings) for the Ed25519 -> X25519 transposition and ECDH.
"""

from __future__ import annotations

import nacl.bindings
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PUB_KEY_SIZE = 32
SEED_SIZE = 32
SIGNATURE_SIZE = 64
SHARED_SECRET_SIZE = 32

CIPHER_KEY_SIZE = 16  # AES-128
CIPHER_BLOCK_SIZE = 16
CIPHER_MAC_SIZE = 2  # truncated HMAC-SHA256 (per MeshCore's `#define CIPHER_MAC_SIZE 2`)

PATH_HASH_SIZE = 1


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (seed, pub_key) where seed is 32 bytes and pub_key is 32 bytes."""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes_raw()
    pub_key = sk.public_key().public_bytes_raw()
    return seed, pub_key


def derive_pub_key(seed: bytes) -> bytes:
    """Derive the Ed25519 public key from a 32-byte seed."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def sign(seed: bytes, message: bytes) -> bytes:
    """Ed25519-sign `message` with the private key derived from `seed`."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def verify(pub_key: bytes, signature: bytes, message: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature on `message`."""
    if len(pub_key) != PUB_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed25519_seed_to_x25519_priv(seed: bytes) -> bytes:
    """Transpose an Ed25519 seed to an X25519 (Curve25519) private key."""
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    _, expanded_sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(expanded_sk)


def ed25519_pub_to_x25519_pub(pub_key: bytes) -> bytes:
    """Transpose an Ed25519 public key to an X25519 (Curve25519) public key."""
    if len(pub_key) != PUB_KEY_SIZE:
        raise ValueError(f"pub_key must be {PUB_KEY_SIZE} bytes, got {len(pub_key)}")
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(pub_key)


def calc_shared_secret(seed: bytes, peer_pub_key: bytes) -> bytes:
    """ECDH between our Ed25519 seed and a peer's Ed25519 pub key, via X25519."""
    x_priv = ed25519_seed_to_x25519_priv(seed)
    x_pub = ed25519_pub_to_x25519_pub(peer_pub_key)
    return nacl.bindings.crypto_scalarmult(x_priv, x_pub)


def aes128_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Raw AES-128-ECB. Plaintext length must be a multiple of the block size."""
    if len(key) != CIPHER_KEY_SIZE:
        raise ValueError(f"key must be {CIPHER_KEY_SIZE} bytes")
    if len(plaintext) % CIPHER_BLOCK_SIZE != 0:
        raise ValueError("plaintext length must be a multiple of the AES block size")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes128_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(key) != CIPHER_KEY_SIZE:
        raise ValueError(f"key must be {CIPHER_KEY_SIZE} bytes")
    if len(ciphertext) % CIPHER_BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a multiple of the AES block size")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_then_mac(shared_secret: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-ECB then prepend a truncated HMAC-SHA256.

    Matches `Utils::encryptThenMAC` in MeshCore (`src/Utils.cpp`).

    - AES key   = shared_secret[:CIPHER_KEY_SIZE]  (16 bytes)
    - HMAC key  = shared_secret[:PUB_KEY_SIZE]     (32 bytes)
    - MAC bytes = HMAC-SHA256(ciphertext)[:CIPHER_MAC_SIZE]  (2 bytes)
    - Plaintext is zero-padded to the next 16-byte boundary.
    - Output layout: MAC(2) || ciphertext
    """
    padded_len = ((len(plaintext) + CIPHER_BLOCK_SIZE - 1) // CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE
    padded = plaintext.ljust(padded_len, b"\x00")
    if padded_len == 0:
        # encrypt() in MeshCore returns 0 for empty input; mirror that.
        return b""
    ciphertext = aes128_ecb_encrypt(shared_secret[:CIPHER_KEY_SIZE], padded)
    mac = hmac_sha256(shared_secret[:PUB_KEY_SIZE], ciphertext)[:CIPHER_MAC_SIZE]
    return mac + ciphertext


def mac_then_decrypt(shared_secret: bytes, sealed: bytes) -> bytes | None:
    """Verify the MAC then AES-128-ECB decrypt. Returns None on MAC mismatch.

    Matches `Utils::MACThenDecrypt` in MeshCore. Note that the returned
    plaintext is the full zero-padded block; the caller is responsible for
    trimming trailing padding using its knowledge of the inner format.
    """
    if len(sealed) <= CIPHER_MAC_SIZE:
        return None
    mac = sealed[:CIPHER_MAC_SIZE]
    ciphertext = sealed[CIPHER_MAC_SIZE:]
    if len(ciphertext) % CIPHER_BLOCK_SIZE != 0:
        return None
    expected = hmac_sha256(shared_secret[:PUB_KEY_SIZE], ciphertext)[:CIPHER_MAC_SIZE]
    if mac != expected:
        return None
    return aes128_ecb_decrypt(shared_secret[:CIPHER_KEY_SIZE], ciphertext)


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Raw AES-128-CBC. The caller is responsible for any padding."""
    if len(key) != CIPHER_KEY_SIZE:
        raise ValueError(f"key must be {CIPHER_KEY_SIZE} bytes")
    if len(iv) != CIPHER_BLOCK_SIZE:
        raise ValueError(f"iv must be {CIPHER_BLOCK_SIZE} bytes")
    if len(plaintext) % CIPHER_BLOCK_SIZE != 0:
        raise ValueError("plaintext length must be a multiple of the AES block size")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != CIPHER_KEY_SIZE:
        raise ValueError(f"key must be {CIPHER_KEY_SIZE} bytes")
    if len(iv) != CIPHER_BLOCK_SIZE:
        raise ValueError(f"iv must be {CIPHER_BLOCK_SIZE} bytes")
    if len(ciphertext) % CIPHER_BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a multiple of the AES block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def path_hash(pub_key: bytes) -> int:
    """Routing-layer 1-byte address: the first byte of the public key."""
    if not pub_key:
        raise ValueError("pub_key is empty")
    return pub_key[0]
