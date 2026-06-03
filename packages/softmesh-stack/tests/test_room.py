"""Tests for the room-server codecs: ANON_REQ login, RESPONSE, and post pushes."""

from __future__ import annotations

from softmesh_stack import crypto
from softmesh_stack.room import (
    RESP_SERVER_LOGIN_OK,
    build_anon_login_packet,
    build_login_response_payload,
    build_room_push_payload,
    room_push_ack_hash,
    try_decrypt_login,
    try_decrypt_login_response,
    try_decrypt_room_push,
)


class TestLogin:
    def test_login_round_trip(self) -> None:
        c_seed, c_pub = crypto.generate_keypair()  # client
        r_seed, r_pub = crypto.generate_keypair()  # room
        shared = crypto.calc_shared_secret(c_seed, r_pub)  # client side

        pkt = build_anon_login_packet(
            shared_secret=shared,
            room_hash=r_pub[0],
            client_pub_key=c_pub,
            timestamp=100,
            sync_since=50,
            password="guestpw",
        )
        req = try_decrypt_login(pkt.payload, r_seed)
        assert req is not None
        assert req.client_pub_key == c_pub
        assert req.timestamp == 100
        assert req.sync_since == 50
        assert req.password == "guestpw"

    def test_login_wrong_room_seed_returns_none(self) -> None:
        c_seed, c_pub = crypto.generate_keypair()
        _, r_pub = crypto.generate_keypair()
        other_seed, _ = crypto.generate_keypair()
        shared = crypto.calc_shared_secret(c_seed, r_pub)
        pkt = build_anon_login_packet(
            shared_secret=shared,
            room_hash=r_pub[0],
            client_pub_key=c_pub,
            timestamp=1,
            sync_since=0,
            password="x",
        )
        # A different room identity must not be able to decrypt the login.
        assert try_decrypt_login(pkt.payload, other_seed) is None


class TestLoginResponse:
    def test_response_round_trip(self) -> None:
        c_seed, c_pub = crypto.generate_keypair()
        r_seed, r_pub = crypto.generate_keypair()
        shared_room = crypto.calc_shared_secret(r_seed, c_pub)

        payload = build_login_response_payload(
            shared_secret=shared_room,
            dest_hash=c_pub[0],
            src_hash=r_pub[0],
            server_ts=200,
            is_admin=True,
            permissions=0,
        )
        resp = try_decrypt_login_response(payload, crypto.calc_shared_secret(c_seed, r_pub))
        assert resp is not None
        assert resp.server_ts == 200
        assert resp.status == RESP_SERVER_LOGIN_OK
        assert resp.is_admin is True

    def test_response_guest_flag(self) -> None:
        c_seed, c_pub = crypto.generate_keypair()
        r_seed, r_pub = crypto.generate_keypair()
        shared_room = crypto.calc_shared_secret(r_seed, c_pub)
        payload = build_login_response_payload(
            shared_secret=shared_room,
            dest_hash=c_pub[0],
            src_hash=r_pub[0],
            server_ts=1,
            is_admin=False,
        )
        resp = try_decrypt_login_response(payload, crypto.calc_shared_secret(c_seed, r_pub))
        assert resp is not None
        assert resp.is_admin is False


class TestRoomPush:
    def test_push_round_trip(self) -> None:
        c_seed, c_pub = crypto.generate_keypair()
        r_seed, r_pub = crypto.generate_keypair()
        _, author_pub = crypto.generate_keypair()
        shared_room = crypto.calc_shared_secret(r_seed, c_pub)

        payload = build_room_push_payload(
            shared_secret=shared_room,
            dest_hash=c_pub[0],
            room_hash=r_pub[0],
            post_ts=300,
            author_pub_key=author_pub,
            text="hello room",
            attempt=0,
        )
        push = try_decrypt_room_push(payload, crypto.calc_shared_secret(c_seed, r_pub))
        assert push is not None
        assert push.post_ts == 300
        assert push.text == "hello room"
        assert push.author_prefix == author_pub[:4]

    def test_push_ack_depends_on_dest_key(self) -> None:
        # MeshCore hashes the pushed-post ACK with the recipient client's pubkey
        # (not the room's), so a different recipient yields a different ACK.
        _, client_a = crypto.generate_keypair()
        _, client_b = crypto.generate_keypair()
        _, author_pub = crypto.generate_keypair()
        ack_a = room_push_ack_hash(300, 0, author_pub, "hello", client_a)
        ack_b = room_push_ack_hash(300, 0, author_pub, "hello", client_b)
        assert len(ack_a) == 4
        assert ack_a != ack_b
