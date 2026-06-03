"""Tests for crypto primitives."""

from __future__ import annotations

import os

import pytest
from softmesh_stack import crypto


def test_generate_keypair_sizes() -> None:
    seed, pub_key = crypto.generate_keypair()
    assert len(seed) == crypto.SEED_SIZE == 32
    assert len(pub_key) == crypto.PUB_KEY_SIZE == 32


def test_derive_pub_key_matches_generate() -> None:
    seed, expected_pub = crypto.generate_keypair()
    assert crypto.derive_pub_key(seed) == expected_pub


def test_sign_and_verify_round_trip() -> None:
    seed, pub_key = crypto.generate_keypair()
    msg = b"meshcore message"
    sig = crypto.sign(seed, msg)
    assert len(sig) == crypto.SIGNATURE_SIZE
    assert crypto.verify(pub_key, sig, msg) is True


def test_verify_rejects_tampered_message() -> None:
    seed, pub_key = crypto.generate_keypair()
    sig = crypto.sign(seed, b"original")
    assert crypto.verify(pub_key, sig, b"tampered") is False


def test_verify_rejects_wrong_signature_size() -> None:
    _, pub_key = crypto.generate_keypair()
    assert crypto.verify(pub_key, b"\x00" * 32, b"x") is False


def test_calc_shared_secret_is_symmetric() -> None:
    a_seed, a_pub = crypto.generate_keypair()
    b_seed, b_pub = crypto.generate_keypair()
    s1 = crypto.calc_shared_secret(a_seed, b_pub)
    s2 = crypto.calc_shared_secret(b_seed, a_pub)
    assert s1 == s2
    assert len(s1) == crypto.SHARED_SECRET_SIZE


def test_aes128_cbc_round_trip() -> None:
    key = os.urandom(crypto.CIPHER_KEY_SIZE)
    iv = os.urandom(crypto.CIPHER_BLOCK_SIZE)
    plaintext = b"sixteenbyteblock" * 3  # 48 bytes, exact multiple of 16
    ct = crypto.aes128_cbc_encrypt(key, iv, plaintext)
    pt = crypto.aes128_cbc_decrypt(key, iv, ct)
    assert pt == plaintext


def test_aes128_cbc_rejects_unaligned_input() -> None:
    key = os.urandom(crypto.CIPHER_KEY_SIZE)
    iv = os.urandom(crypto.CIPHER_BLOCK_SIZE)
    with pytest.raises(ValueError):
        crypto.aes128_cbc_encrypt(key, iv, b"not 16 bytes")


def test_hmac_sha256_known_size_and_deterministic() -> None:
    key = b"k" * 32
    mac1 = crypto.hmac_sha256(key, b"data")
    mac2 = crypto.hmac_sha256(key, b"data")
    assert mac1 == mac2
    assert len(mac1) == 32


def test_sha256_known_value() -> None:
    # echo -n "" | sha256sum
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert crypto.sha256(b"").hex() == empty


def test_path_hash_is_first_byte() -> None:
    assert crypto.path_hash(bytes([0xAB, 0xCD])) == 0xAB
