"""Synchronous client core shared by the CLI, GUI, and benchmarks."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .protocol import (
    Mode,
    ProtocolError,
    b64decode,
    b64encode,
    make_message,
    recv_frame,
    send_frame,
    validate_username,
)
from .security import E2EError, Identity, TrustStore, create_client_context, fingerprint
from .security import open as open_e2e
from .security import seal

Event = dict[str, Any]
EventCallback = Callable[[Event], None]


class ChatClientError(ConnectionError):
    """A connection or protocol operation failed safely."""


class TrustError(ChatClientError):
    """An E2E operation requires explicit peer-key verification."""


@dataclass(frozen=True)
class SetupTiming:
    """Wall-clock setup phases measured at the client."""

    tcp_connect_ms: float
    tls_handshake_ms: float | None
    registration_ms: float
    e2e_keygen_ms: float | None
    total_setup_ms: float

    def as_dict(self) -> dict[str, float | None]:
        return {
            "tcp_connect_ms": self.tcp_connect_ms,
            "tls_handshake_ms": self.tls_handshake_ms,
            "registration_ms": self.registration_ms,
            "e2e_keygen_ms": self.e2e_keygen_ms,
            "total_setup_ms": self.total_setup_ms,
        }


@dataclass(frozen=True)
class Peer:
    """A room member and, in E2E mode, its untrusted advertised key."""

    username: str
    public_key: bytes | None = None

    @property
    def fingerprint(self) -> str | None:
        if self.public_key is None:
            return None
        return fingerprint(self.username, self.public_key)


class ChatClient:
    """One room connection with immediate TLS and explicit E2E trust.

    Set ``start_listener=False`` to drive :meth:`receive_once` synchronously;
    this is useful for deterministic benchmark request/response exchanges.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        mode: Mode | str,
        *,
        port: int | None = None,
        ca_file: str | Path = "certs/ca.crt",
        keylog_file: str | Path | None = None,
        identity: Identity | None = None,
        trust_store: TrustStore | None = None,
        on_event: EventCallback | None = None,
        timeout: float = 10.0,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.mode = Mode(mode)
        self.port = port
        self.ca_file = Path(ca_file)
        self.keylog_file = keylog_file
        self.identity = identity
        self.trust_store = trust_store or TrustStore()
        self.on_event = on_event
        self.timeout = timeout

        self.room_code: str | None = None
        self.room_name: str | None = None
        self.peers: dict[str, Peer] = {}
        self.setup_timing: SetupTiming | None = None
        self.socket: socket.socket | ssl.SSLSocket | None = None

        self._connected = False
        self._listener: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._seen_ids: dict[str, set[str]] = {}
        self._seen_order: dict[str, deque[str]] = {}
        self._max_replay_ids = 2048

    @property
    def connected(self) -> bool:
        with self._state_lock:
            return self._connected

    @property
    def own_fingerprint(self) -> str | None:
        if self.identity is None:
            return None
        return self.identity.fingerprint(self.username)

    def connect(
        self,
        *,
        room_name: str | None = None,
        room_code: str | None = None,
        start_listener: bool = True,
    ) -> SetupTiming:
        """Create or join a room and complete TLS/registration before chatting."""

        if self.socket is not None:
            raise ChatClientError("client is already connected")
        if (room_name is None) == (room_code is None):
            raise ValueError("provide exactly one of room_name or room_code")
        if not validate_username(self.username):
            raise ValueError("invalid username")
        if not self.password or len(self.password) > 256:
            raise ValueError("password must contain 1-256 characters")

        total_started = time.perf_counter_ns()
        keygen_ms: float | None = None
        if self.mode is Mode.E2E and self.identity is None:
            started = time.perf_counter_ns()
            self.identity = Identity.generate()
            keygen_ms = self._elapsed_ms(started)
        elif self.mode is Mode.E2E:
            keygen_ms = 0.0

        selected_port = self.port
        if selected_port is None:
            selected_port = 8080 if self.mode is Mode.PLAINTEXT else 8443

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(self.timeout)
        active_socket: socket.socket | ssl.SSLSocket = raw_socket
        try:
            started = time.perf_counter_ns()
            raw_socket.connect((self.host, selected_port))
            tcp_ms = self._elapsed_ms(started)

            tls_ms: float | None = None
            if self.mode is not Mode.PLAINTEXT:
                context = create_client_context(self.ca_file, self.keylog_file)
                started = time.perf_counter_ns()
                active_socket = context.wrap_socket(
                    raw_socket, server_hostname=self.host
                )
                tls_ms = self._elapsed_ms(started)
                if active_socket.version() != "TLSv1.3":
                    raise ChatClientError("server did not negotiate TLS 1.3")

            action = "create" if room_name is not None else "join"
            registration = make_message(
                "register",
                action=action,
                mode=self.mode.value,
                username=self.username,
                password=self.password,
            )
            if room_name is not None:
                registration["room_name"] = room_name
            else:
                registration["room_code"] = room_code
            if self.mode is Mode.E2E:
                assert self.identity is not None
                registration["public_key"] = b64encode(self.identity.public_key)

            started = time.perf_counter_ns()
            send_frame(active_socket, registration)
            welcome = recv_frame(active_socket)
            if welcome is None:
                raise ChatClientError("relay closed during registration")
            if welcome.get("type") == "error":
                raise ChatClientError(
                    f"{welcome.get('code', 'registration_failed')}: "
                    f"{welcome.get('message', 'registration rejected')}"
                )
            if welcome.get("type") != "welcome":
                raise ChatClientError("relay did not send a welcome frame")
            self._accept_welcome(welcome)

            first_roster = recv_frame(active_socket)
            if first_roster is None or first_roster.get("type") != "roster":
                raise ChatClientError("relay did not send the initial roster")
            self._update_roster(first_roster, emit=False)
            registration_ms = self._elapsed_ms(started)

            active_socket.settimeout(None)
            self.socket = active_socket
            with self._state_lock:
                self._connected = True
            self.setup_timing = SetupTiming(
                tcp_connect_ms=tcp_ms,
                tls_handshake_ms=tls_ms,
                registration_ms=registration_ms,
                e2e_keygen_ms=keygen_ms,
                total_setup_ms=self._elapsed_ms(total_started),
            )
            if start_listener:
                self._listener = threading.Thread(
                    target=self._listen,
                    name=f"chatrex-listener-{self.username}",
                    daemon=True,
                )
                self._listener.start()
            return self.setup_timing
        except Exception:
            active_socket.close()
            raise

    def send_text(self, text: str, recipients: list[str] | None = None) -> list[str]:
        """Send UTF-8 text, encrypting separately for each E2E recipient."""

        payload = text.encode("utf-8")
        if self.mode is not Mode.E2E:
            targets = recipients or ["*"]
            return [self.send_payload(payload, target) for target in targets]

        targets = recipients or sorted(self.peers)
        if not targets:
            raise TrustError("there are no other room members")
        return [self.send_payload(payload, target) for target in targets]

    def send_payload(
        self, payload: bytes, recipient: str, *, message_id: str | None = None
    ) -> str:
        """Send one binary application payload and return its message ID."""

        if not self.connected or self.socket is None:
            raise ChatClientError("client is not connected")
        if not isinstance(payload, bytes) or len(payload) > 65_536:
            raise ValueError("payload must be bytes of at most 65536 bytes")
        if not validate_username(recipient) and recipient != "*":
            raise ValueError("invalid recipient")
        if recipient == self.username:
            raise ValueError("cannot send to yourself")
        message_id = message_id or uuid.uuid4().hex
        if not message_id or len(message_id) > 64:
            raise ValueError("invalid message ID")

        if self.mode is Mode.E2E:
            if recipient == "*":
                raise ValueError("E2E messages require individual recipients")
            peer = self.peers.get(recipient)
            if peer is None or peer.public_key is None or self.room_code is None:
                raise TrustError(f"{recipient} is not in the room")
            peer_key = self.trust_store.key_for(self.room_code, recipient)
            if peer_key is None or not self.trust_store.is_verified(
                self.room_code, recipient, peer.public_key
            ):
                raise TrustError(
                    f"verify {recipient}'s fingerprint before sending messages"
                )
            assert self.identity is not None
            nonce, ciphertext = seal(
                self.identity,
                self.username,
                recipient,
                peer_key,
                message_id,
                payload,
            )
            frame = make_message(
                "e2e_send",
                to=recipient,
                id=message_id,
                nonce=b64encode(nonce),
                ciphertext=b64encode(ciphertext),
            )
        else:
            frame = make_message(
                "send", to=recipient, id=message_id, data=b64encode(payload)
            )

        with self._write_lock:
            send_frame(self.socket, frame)
        return message_id

    def verify_peer(self, username: str, expected_fingerprint: str) -> bool:
        """Pin a peer only after comparing its out-of-band fingerprint."""

        peer = self.peers.get(username)
        if (
            self.mode is not Mode.E2E
            or self.room_code is None
            or peer is None
            or peer.public_key is None
        ):
            return False
        return self.trust_store.verify(
            self.room_code, username, peer.public_key, expected_fingerprint
        )

    def confirm_peer(self, username: str) -> bool:
        """Confirm that the displayed fingerprint was compared out-of-band."""

        peer = self.peers.get(username)
        if peer is None or peer.fingerprint is None:
            return False
        return self.verify_peer(username, peer.fingerprint)

    def is_peer_verified(self, username: str) -> bool:
        peer = self.peers.get(username)
        if (
            self.room_code is None
            or peer is None
            or peer.public_key is None
        ):
            return False
        return self.trust_store.is_verified(
            self.room_code, username, peer.public_key
        )

    def receive_once(self) -> Event | None:
        """Receive one frame in synchronous mode and return its safe event."""

        if not self.connected or self.socket is None:
            raise ChatClientError("client is not connected")
        if self._listener is not None:
            raise ChatClientError("receive_once is unavailable with a listener")
        frame = recv_frame(self.socket)
        if frame is None:
            self.close()
            return None
        return self._dispatch_safely(frame)

    def wait_for_message(self, message_id: str, timeout: float = 30.0) -> Event:
        """Wait synchronously for a specific echoed/application message."""

        if self.socket is None:
            raise ChatClientError("client is not connected")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"message {message_id} was not received")
            self.socket.settimeout(remaining)
            event = self.receive_once()
            if event is None:
                raise ChatClientError("relay closed while waiting for a message")
            if event.get("kind") == "error":
                raise ChatClientError(str(event.get("message", "relay error")))
            if event.get("kind") == "message" and event.get("id") == message_id:
                return event

    def close(self) -> None:
        with self._state_lock:
            was_connected = self._connected
            self._connected = False
            active_socket = self.socket
            self.socket = None
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            active_socket.close()
        if was_connected:
            self._emit({"kind": "disconnected"})

    def _listen(self) -> None:
        try:
            while self.connected:
                frame = recv_frame(self.socket) if self.socket is not None else None
                if frame is None:
                    break
                self._dispatch_safely(frame)
        except (OSError, ssl.SSLError, ProtocolError, ChatClientError) as exc:
            if self.connected:
                self._emit({"kind": "error", "message": str(exc)})
        finally:
            self.close()

    def _dispatch_safely(self, frame: Event) -> Event:
        """Reject a bad application message without dropping the connection."""

        try:
            return self._dispatch(frame)
        except (TrustError, E2EError, ProtocolError) as exc:
            event = {
                "kind": "error",
                "code": "message_rejected",
                "message": str(exc),
            }
            self._emit(event)
            return event

    def _accept_welcome(self, frame: Event) -> None:
        if frame.get("mode") != self.mode.value:
            raise ChatClientError("relay changed the requested security mode")
        if frame.get("username") != self.username:
            raise ChatClientError("relay changed the requested username")
        room_code = frame.get("room_code")
        room_name = frame.get("room_name")
        if not isinstance(room_code, str) or not isinstance(room_name, str):
            raise ChatClientError("welcome frame is missing room metadata")
        self.room_code = room_code
        self.room_name = room_name

    def _update_roster(self, frame: Event, *, emit: bool = True) -> Event:
        raw_peers = frame.get("peers")
        if not isinstance(raw_peers, list):
            raise ProtocolError("roster peers must be a list")
        updated: dict[str, Peer] = {}
        for raw_peer in raw_peers:
            if not isinstance(raw_peer, dict):
                raise ProtocolError("roster peer must be an object")
            username = raw_peer.get("username")
            if not validate_username(username):
                raise ProtocolError("roster contains an invalid username")
            if username == self.username:
                continue
            public_key: bytes | None = None
            if self.mode is Mode.E2E:
                try:
                    public_key = b64decode(raw_peer.get("public_key"))
                except ValueError as exc:
                    raise ProtocolError("roster contains an invalid public key") from exc
                if len(public_key) != 32:
                    raise ProtocolError("roster public key must contain 32 bytes")
            updated[username] = Peer(username, public_key)

        if self.room_code is not None:
            for departed in set(self.peers) - set(updated):
                self.trust_store.remove(self.room_code, departed)
        self.peers = updated
        event = {"kind": "roster", "peers": dict(self.peers)}
        if emit:
            self._emit(event)
        return event

    def _dispatch(self, frame: Event) -> Event:
        frame_type = frame.get("type")
        if frame_type == "roster":
            return self._update_roster(frame)
        if frame_type == "error":
            event = {
                "kind": "error",
                "code": frame.get("code"),
                "message": frame.get("message", "relay error"),
            }
            self._emit(event)
            return event
        if frame_type == "deliver" and self.mode is not Mode.E2E:
            event = self._plain_delivery(frame)
        elif frame_type == "e2e_deliver" and self.mode is Mode.E2E:
            event = self._e2e_delivery(frame)
        else:
            raise ProtocolError("unexpected frame for the current mode")
        self._emit(event)
        return event

    def _plain_delivery(self, frame: Event) -> Event:
        sender = frame.get("from")
        recipient = frame.get("to")
        message_id = frame.get("id")
        if (
            not validate_username(sender)
            or recipient != self.username
            or not isinstance(message_id, str)
        ):
            raise ProtocolError("invalid delivery metadata")
        try:
            payload = b64decode(frame.get("data"))
        except ValueError as exc:
            raise ProtocolError("delivery contains invalid data") from exc
        self._check_replay(sender, message_id)
        return {
            "kind": "message",
            "from": sender,
            "to": recipient,
            "id": message_id,
            "payload": payload,
        }

    def _e2e_delivery(self, frame: Event) -> Event:
        sender = frame.get("from")
        recipient = frame.get("to")
        message_id = frame.get("id")
        if (
            not validate_username(sender)
            or recipient != self.username
            or not isinstance(message_id, str)
            or self.room_code is None
            or self.identity is None
        ):
            raise ProtocolError("invalid E2E delivery metadata")
        peer = self.peers.get(sender)
        if peer is None or peer.public_key is None:
            raise TrustError(f"no advertised key for {sender}")
        peer_key = self.trust_store.key_for(self.room_code, sender)
        if peer_key is None or not self.trust_store.is_verified(
            self.room_code, sender, peer.public_key
        ):
            raise TrustError(f"discarding message from unverified peer {sender}")
        try:
            nonce = b64decode(frame.get("nonce"))
            ciphertext = b64decode(frame.get("ciphertext"))
            payload = open_e2e(
                self.identity,
                sender,
                self.username,
                peer_key,
                message_id,
                nonce,
                ciphertext,
            )
        except (ValueError, E2EError) as exc:
            raise E2EError(f"discarding invalid E2E message from {sender}") from exc
        self._check_replay(sender, message_id)
        return {
            "kind": "message",
            "from": sender,
            "to": recipient,
            "id": message_id,
            "payload": payload,
        }

    def _check_replay(self, sender: str, message_id: str) -> None:
        seen = self._seen_ids.setdefault(sender, set())
        order = self._seen_order.setdefault(sender, deque())
        if message_id in seen:
            raise ProtocolError(f"replayed message ID from {sender}")
        seen.add(message_id)
        order.append(message_id)
        if len(order) > self._max_replay_ids:
            seen.discard(order.popleft())

    def _emit(self, event: Event) -> None:
        if self.on_event is not None:
            self.on_event(event)

    @staticmethod
    def _elapsed_ms(started_ns: int) -> float:
        return (time.perf_counter_ns() - started_ns) / 1_000_000


__all__ = [
    "ChatClient",
    "ChatClientError",
    "Peer",
    "SetupTiming",
    "TrustError",
]
