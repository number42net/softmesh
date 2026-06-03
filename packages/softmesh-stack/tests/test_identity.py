"""Tests for Identity (generate, save, load, sign, verify, shared secret)."""

from __future__ import annotations

import pytest
from softmesh_stack import crypto
from softmesh_stack.identity import IDENTITY_NAME_SIZE, Identity, resolve_identity


class TestResolveIdentity:
    def test_from_seed_hex_writes_nothing(self, tmp_path) -> None:
        seed, pub = crypto.generate_keypair()
        path = tmp_path / "room.identity"
        ident, source = resolve_identity(seed.hex(), path, name="py-room")
        assert source == "env"
        assert ident.seed == seed
        assert ident.pub_key == pub
        assert ident.name == "py-room"
        assert not path.exists()  # nothing read from or written to disk

    def test_seed_hex_tolerates_0x_prefix(self, tmp_path) -> None:
        seed, _ = crypto.generate_keypair()
        ident, source = resolve_identity("0x" + seed.hex(), tmp_path / "id", name="x")
        assert source == "env" and ident.seed == seed

    def test_generate_then_load_from_file(self, tmp_path) -> None:
        path = tmp_path / "id"
        first, source = resolve_identity(None, path, name="gen")
        assert source == "generated" and path.exists()
        second, source2 = resolve_identity(None, path, name="ignored")
        assert source2 == "file" and second.seed == first.seed

    def test_bad_seed_fails_fast(self, tmp_path) -> None:
        with pytest.raises(ValueError):
            resolve_identity("nothex!!", tmp_path / "id", name="x")


def test_generate_and_self_sign_round_trip() -> None:
    ident = Identity.generate(name="echo-bot")
    sig = ident.sign(b"hello")
    assert ident.verify(sig, b"hello")


def test_address_is_first_byte_of_pub_key() -> None:
    ident = Identity.generate()
    assert ident.address == ident.pub_key[0]


def test_save_load_round_trip(tmp_path) -> None:
    ident = Identity.generate(name="some-service")
    ident.save(tmp_path / "id.bin")
    loaded = Identity.load(tmp_path / "id.bin")
    assert loaded.seed == ident.seed
    assert loaded.pub_key == ident.pub_key
    assert loaded.name == "some-service"


def test_save_without_name_omits_padding(tmp_path) -> None:
    ident = Identity.generate()
    path = tmp_path / "id.bin"
    ident.save(path)
    data = path.read_bytes()
    assert len(data) == crypto.SEED_SIZE + crypto.PUB_KEY_SIZE


def test_save_with_long_name_truncates(tmp_path) -> None:
    name = "x" * 100
    ident = Identity.generate(name=name)
    path = tmp_path / "id.bin"
    ident.save(path)
    loaded = Identity.load(path)
    assert len(loaded.name) <= IDENTITY_NAME_SIZE - 1


def test_load_rejects_pubkey_seed_mismatch(tmp_path) -> None:
    ident = Identity.generate(name="x")
    path = tmp_path / "id.bin"
    # Corrupt the pub_key portion.
    data = bytearray(ident.seed + ident.pub_key)
    data[crypto.SEED_SIZE] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="pub_key does not match"):
        Identity.load(path)


def test_shared_secret_between_two_identities() -> None:
    a = Identity.generate()
    b = Identity.generate()
    s1 = a.calc_shared_secret(b.pub_key)
    s2 = b.calc_shared_secret(a.pub_key)
    assert s1 == s2


def test_from_seed_derives_consistent_pub_key() -> None:
    a = Identity.generate(name="x")
    b = Identity.from_seed(a.seed, name="x")
    assert b.pub_key == a.pub_key
