from __future__ import annotations

import queue
import socket
import ssl
import time
from pathlib import Path

import pytest

from chatrex.client import ChatClient, ChatClientError, TrustError
from chatrex.protocol import Mode, make_message, send_frame
from chatrex.relay import RelayServer

ROOT = Path(__file__).resolve().parents[1]
CA = ROOT / "certs" / "ca.crt"
CERT = ROOT / "certs" / "server.crt"
KEY = ROOT / "certs" / "server.key"


@pytest.fixture
def relay(tmp_path):
    server = RelayServer(
        host="0.0.0.0",
        plain_port=0,
        secure_port=0,
        cert_file=str(CERT),
        key_file=str(KEY),
        keylog_file=str(tmp_path / "server-tls.keys"),
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


def port_for(relay: RelayServer, mode: Mode) -> int:
    return relay.plaintext_port if mode is Mode.PLAINTEXT else relay.secure_port_actual


def make_client(
    relay: RelayServer,
    mode: Mode,
    username: str,
    tmp_path: Path,
    **kwargs,
) -> ChatClient:
    return ChatClient(
        "127.0.0.1",
        username,
        "correct horse battery staple",
        mode,
        port=port_for(relay, mode),
        ca_file=CA,
        keylog_file=tmp_path / f"{username}.keys",
        **kwargs,
    )


def connected_pair(relay: RelayServer, mode: Mode, tmp_path: Path):
    alice = make_client(relay, mode, "alice", tmp_path)
    alice.connect(room_name="network-security", start_listener=False)
    bob = make_client(relay, mode, "bob", tmp_path)
    bob.connect(room_code=alice.room_code, start_listener=False)
    # Alice's next frame is the roster announcing Bob.
    roster = alice.receive_once()
    assert roster is not None and roster["kind"] == "roster"
    if mode is Mode.E2E:
        assert alice.verify_peer("bob", bob.own_fingerprint)
        assert bob.verify_peer("alice", alice.own_fingerprint)
    return alice, bob


@pytest.mark.parametrize("mode", list(Mode))
def test_real_two_client_round_trip(relay, tmp_path, mode):
    alice, bob = connected_pair(relay, mode, tmp_path)
    try:
        message_id = alice.send_payload(b"routed secret payload\x00\xff", "bob")
        incoming = bob.wait_for_message(message_id)
        assert incoming["from"] == "alice"
        assert incoming["payload"] == b"routed secret payload\x00\xff"

        response_id = bob.send_payload(incoming["payload"], "alice", message_id=message_id)
        response = alice.wait_for_message(response_id)
        assert response["from"] == "bob"
        assert response["payload"] == incoming["payload"]

        if mode is not Mode.PLAINTEXT:
            assert isinstance(alice.socket, ssl.SSLSocket)
            assert alice.socket.version() == "TLSv1.3"
            assert not alice.socket.session_reused
    finally:
        alice.close()
        bob.close()

    if mode is not Mode.PLAINTEXT:
        keylog = (tmp_path / "alice.keys").read_text()
        assert "CLIENT_TRAFFIC_SECRET_0" in keylog
        assert "SERVER_TRAFFIC_SECRET_0" in keylog


def test_e2e_requires_explicit_and_correct_verification(relay, tmp_path):
    alice = make_client(relay, Mode.E2E, "alice", tmp_path)
    alice.connect(room_name="trust", start_listener=False)
    bob = make_client(relay, Mode.E2E, "bob", tmp_path)
    bob.connect(room_code=alice.room_code, start_listener=False)
    alice.receive_once()
    try:
        with pytest.raises(TrustError):
            alice.send_payload(b"blocked", "bob")
        assert not alice.verify_peer("bob", alice.own_fingerprint)
        with pytest.raises(TrustError):
            alice.send_payload(b"still blocked", "bob")
        assert alice.verify_peer("bob", bob.own_fingerprint)
        assert bob.verify_peer("alice", alice.own_fingerprint)
        message_id = alice.send_payload(b"verified", "bob")
        assert bob.wait_for_message(message_id)["payload"] == b"verified"
    finally:
        alice.close()
        bob.close()


def test_tls_rejects_untrusted_ca_before_registration(relay, tmp_path):
    client = ChatClient(
        "127.0.0.1",
        "mallory",
        "password",
        Mode.TLS,
        port=relay.secure_port_actual,
        ca_file=CERT,  # A server leaf certificate is not the trusted CA.
    )
    with pytest.raises(ssl.SSLError):
        client.connect(room_name="not-created", start_listener=False)
    client.close()


def test_tls_rejects_hostname_mismatch(relay, tmp_path):
    # 127.0.0.2 has no SAN even though it reaches the same loopback listener.
    client = ChatClient(
        "127.0.0.2",
        "mallory",
        "password",
        Mode.TLS,
        port=relay.secure_port_actual,
        ca_file=CA,
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        client.connect(room_name="not-created", start_listener=False)
    client.close()


def test_secure_listener_never_accepts_plaintext_registration(relay):
    raw = socket.create_connection(("127.0.0.1", relay.secure_port_actual), timeout=2)
    raw.settimeout(2)
    try:
        registration = make_message(
            "register",
            action="create",
            mode="tls",
            username="mallory",
            password="password",
            room_name="plaintext-first",
        )
        with pytest.raises((ConnectionError, OSError, ssl.SSLError)):
            send_frame(raw, registration)
            response = raw.recv(1024)
            if response:
                # A TLS alert is binary, never a protocol welcome frame.
                assert b"welcome" not in response
    finally:
        raw.close()


def test_wrong_room_password_and_duplicate_username(relay, tmp_path):
    alice = make_client(relay, Mode.TLS, "alice", tmp_path)
    alice.connect(room_name="authentication", start_listener=False)
    try:
        wrong = ChatClient(
            "127.0.0.1",
            "bob",
            "wrong password",
            Mode.TLS,
            port=relay.secure_port_actual,
            ca_file=CA,
        )
        with pytest.raises(ChatClientError, match="authentication_failed"):
            wrong.connect(room_code=alice.room_code, start_listener=False)

        duplicate = make_client(relay, Mode.TLS, "alice", tmp_path)
        with pytest.raises(ChatClientError, match="username_taken"):
            duplicate.connect(room_code=alice.room_code, start_listener=False)
    finally:
        alice.close()


def test_plaintext_broadcast_does_not_return_to_sender(relay, tmp_path):
    alice, bob = connected_pair(relay, Mode.PLAINTEXT, tmp_path)
    try:
        message_id = alice.send_text("hello room")[0]
        incoming = bob.wait_for_message(message_id)
        assert incoming["payload"] == b"hello room"
        assert incoming["from"] == "alice"
    finally:
        alice.close()
        bob.close()


def test_unverified_incoming_e2e_does_not_disconnect_listener(relay, tmp_path):
    events = queue.Queue()
    alice = make_client(relay, Mode.E2E, "alice", tmp_path, on_event=events.put)
    alice.connect(room_name="listener-trust", start_listener=True)
    bob = make_client(relay, Mode.E2E, "bob", tmp_path)
    bob.connect(room_code=alice.room_code, start_listener=False)
    try:
        deadline = time.monotonic() + 2
        while "bob" not in alice.peers and time.monotonic() < deadline:
            time.sleep(0.01)
        assert "bob" in alice.peers
        assert bob.verify_peer("alice", alice.own_fingerprint)

        # Bob may send because he verified Alice. Alice has not verified Bob yet,
        # so her client must reject only this message and remain connected.
        bob.send_payload(b"reject me", "alice")
        while True:
            event = events.get(timeout=2)
            if event.get("kind") == "error":
                assert event["code"] == "message_rejected"
                break
        assert alice.connected

        # After explicit verification, the same background listener accepts E2E.
        assert alice.confirm_peer("bob")
        accepted_id = bob.send_payload(b"now trusted", "alice")
        while True:
            event = events.get(timeout=2)
            if event.get("kind") == "message":
                assert event["id"] == accepted_id
                assert event["payload"] == b"now trusted"
                break
        assert alice.connected

        response_id = alice.send_payload(b"both directions work", "bob")
        assert bob.wait_for_message(response_id)["payload"] == b"both directions work"
        assert alice.connected
    finally:
        alice.close()
        bob.close()
