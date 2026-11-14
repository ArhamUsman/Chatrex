"""Threaded plaintext, TLS, and end-to-end encrypted room relay."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .protocol import (
    MAX_FRAME_BYTES,
    Mode,
    ProtocolError,
    b64decode,
    make_message,
    recv_frame,
    send_frame,
    validate_room_code,
    validate_room_name,
    validate_username,
)
from .security import create_server_context

_LOGGER = logging.getLogger(__name__)
_LISTEN_BACKLOG = 128
_ACCEPT_TIMEOUT = 0.5
_STOP_TIMEOUT = 5.0
_PASSWORD_ITERATIONS = 200_000
_SALT_BYTES = 16
_PUBLIC_KEY_BYTES = 32
_NONCE_BYTES = 24
_MAX_DATA_BYTES = 65_536
_ROOM_CODE_SPACE = 1_000_000


@dataclass(eq=False)
class _Client:
    """Per-connection state; identity is intentionally based on object identity."""

    sock: socket.socket
    address: tuple[str, int]
    write_lock: threading.Lock = field(default_factory=threading.Lock)
    username: str | None = None
    mode: Mode | None = None
    public_key: str | None = None
    room: _Room | None = None
    ready: bool = False
    closed: bool = False


@dataclass
class _Room:
    """A room and its immutable password verifier."""

    code: str
    name: str
    mode: Mode
    password_salt: bytes
    password_digest: bytes
    clients: dict[str, _Client] = field(default_factory=dict)


class _RegistrationError(Exception):
    """A safe, client-reportable registration failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _MessageError(Exception):
    """A safe, client-reportable message validation failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class RelayServer:
    """Relay chat rooms over explicit plaintext and TLS 1.3 listeners.

    The plaintext listener accepts only ``plaintext`` registrations.  The secure
    listener performs a TLS handshake immediately after accepting a connection
    and accepts only ``tls`` and ``e2e`` registrations.  E2E ciphertext is
    forwarded opaquely; this class has no decryption or private-key operations.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        plain_port: int = 8080,
        secure_port: int = 8443,
        cert_file: str = "certs/server.crt",
        key_file: str = "certs/server.key",
        keylog_file: str | None = None,
    ):
        self.host = host
        self.plain_port = plain_port
        self.secure_port = secure_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.keylog_file = keylog_file

        # This RLock protects the room registry, active set, and lifecycle state.
        self._lock = threading.RLock()
        # Roster mutations are serialized separately so stale snapshots cannot be
        # sent after newer ones.  Socket writes never occur while holding _lock.
        self._roster_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()

        self._rooms: dict[str, _Room] = {}
        self._connections: set[_Client] = set()
        self._client_threads: set[threading.Thread] = set()
        self._accept_threads: list[threading.Thread] = []

        self._plain_listener: socket.socket | None = None
        self._secure_listener: socket.socket | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._running = False
        self._stopped = threading.Event()
        self._stopped.set()

        self._plaintext_port_actual = 0
        self._secure_port_actual = 0

    @property
    def plaintext_port(self) -> int:
        """Return the actual plaintext port, including an OS-assigned port."""

        with self._lock:
            return self._plaintext_port_actual

    @property
    def secure_port_actual(self) -> int:
        """Return the actual secure port, including an OS-assigned port."""

        with self._lock:
            return self._secure_port_actual

    def start(self) -> None:
        """Bind both listeners and launch daemon accept threads without waiting."""

        with self._lifecycle_lock:
            with self._lock:
                if self._running:
                    return

            # Creating the context here makes certificate/key errors synchronous
            # and guarantees TLS 1.3 through the existing security helper.
            tls_context = create_server_context(
                self.cert_file, self.key_file, self.keylog_file
            )
            plain_listener: socket.socket | None = None
            try:
                plain_listener = self._create_listener(self.plain_port)
                secure_listener = self._create_listener(self.secure_port)
            except BaseException:
                if plain_listener is not None:
                    self._close_listener(plain_listener)
                raise

            try:
                with self._lock:
                    self._tls_context = tls_context
                    self._plain_listener = plain_listener
                    self._secure_listener = secure_listener
                    self._plaintext_port_actual = plain_listener.getsockname()[1]
                    self._secure_port_actual = secure_listener.getsockname()[1]
                    self._running = True
                    self._stopped.clear()
                    self._accept_threads = []

                    for listener, secure, name in (
                        (plain_listener, False, "chatrex-plaintext-accept"),
                        (secure_listener, True, "chatrex-secure-accept"),
                    ):
                        thread = threading.Thread(
                            target=self._accept_loop,
                            args=(listener, secure),
                            name=name,
                            daemon=True,
                        )
                        self._accept_threads.append(thread)
                        thread.start()
            except BaseException:
                # Do not leave a partially started server behind on thread errors.
                self.stop()
                raise

    def serve_forever(self) -> None:
        """Start the server if necessary, then block until :meth:`stop` is called."""

        self.start()
        try:
            self._stopped.wait()
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop listeners and clients, wait briefly for threads, and clean rooms.

        Shutdown is idempotent.  Connections are closed outside the registry
        lock, and all worker threads are daemons so a stalled thread cannot
        prevent interpreter exit.
        """

        with self._lifecycle_lock:
            with self._lock:
                self._running = False
                self._stopped.set()

                listeners = (
                    self._plain_listener,
                    self._secure_listener,
                )
                self._plain_listener = None
                self._secure_listener = None
                self._tls_context = None

                connections = tuple(self._connections)
                self._connections.clear()
                self._rooms.clear()
                for client in connections:
                    client.closed = True
                    client.ready = False
                    client.room = None

                accept_threads = tuple(self._accept_threads)
                client_threads = tuple(self._client_threads)

            for listener in listeners:
                if listener is not None:
                    self._close_listener(listener)
            for client in connections:
                self._close_client(client)

            current = threading.current_thread()
            deadline = time.monotonic() + _STOP_TIMEOUT
            for thread in (*accept_threads, *client_threads):
                if thread is current:
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                thread.join(remaining)
                if thread.is_alive():
                    _LOGGER.warning("Thread %s did not stop before timeout", thread.name)

            with self._lock:
                self._accept_threads = [
                    thread for thread in self._accept_threads if thread.is_alive()
                ]

    def _create_listener(self, port: int) -> socket.socket:
        """Create one bound TCP listener, closing it if setup fails."""

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, port))
            listener.listen(_LISTEN_BACKLOG)
            listener.settimeout(_ACCEPT_TIMEOUT)
            return listener
        except BaseException:
            self._close_listener(listener)
            raise

    @staticmethod
    def _close_listener(listener: socket.socket) -> None:
        """Close a listener and retain diagnostics for unusual close failures."""

        try:
            listener.close()
        except OSError as exc:
            _LOGGER.debug("Listener close failed: %s", exc)

    def _accept_loop(self, listener: socket.socket, secure: bool) -> None:
        """Accept clients until shutdown, isolating setup failures per client."""

        failed = False
        while True:
            try:
                conn, address = listener.accept()
            except socket.timeout:
                with self._lock:
                    if not self._running or listener not in (
                        self._plain_listener,
                        self._secure_listener,
                    ):
                        break
                continue
            except OSError as exc:
                with self._lock:
                    expected = not self._running or listener not in (
                        self._plain_listener,
                        self._secure_listener,
                    )
                if expected:
                    break
                failed = True
                _LOGGER.error("Accept loop failed on secure=%s: %s", secure, exc)
                break

            client = _Client(conn, address)
            thread = threading.Thread(
                target=self._client_entry,
                args=(client, secure),
                name=f"chatrex-client-{address[0]}:{address[1]}",
                daemon=True,
            )
            try:
                with self._lock:
                    if not self._running or listener not in (
                        self._plain_listener,
                        self._secure_listener,
                    ):
                        self._close_client(client)
                        break
                    self._connections.add(client)
                    self._client_threads.add(thread)
                    # Starting while holding the lock prevents stop() from
                    # observing and attempting to join an unstarted thread.
                    thread.start()
            except Exception as exc:
                _LOGGER.warning(
                    "Could not start client worker for %s:%s (%s)",
                    address[0],
                    address[1],
                    type(exc).__name__,
                )
                with self._lock:
                    self._connections.discard(client)
                    self._client_threads.discard(thread)
                self._close_client(client)

        if failed:
            self.stop()

    def _client_entry(self, client: _Client, secure: bool) -> None:
        """Run one complete client lifecycle without affecting other clients."""

        try:
            if secure:
                context = self._tls_context
                if context is None:
                    return
                try:
                    # This is deliberately the first operation on an accepted
                    # secure connection; no plaintext application frame precedes it.
                    client.sock = context.wrap_socket(client.sock, server_side=True)
                except (OSError, ssl.SSLError) as exc:
                    _LOGGER.debug(
                        "TLS handshake failed for %s:%s: %s",
                        client.address[0],
                        client.address[1],
                        exc,
                    )
                    return

            with self._lock:
                if not self._running or client.closed:
                    return

            if not self._register(client, secure):
                return

            while True:
                with self._lock:
                    if not self._running or client.closed:
                        break
                message = recv_frame(client.sock)
                if message is None:
                    break
                if not self._handle_message(client, message):
                    break
        except ProtocolError as exc:
            _LOGGER.debug("Protocol error from %s: %s", self._label(client), exc)
            self._send_error(client, "protocol_error", str(exc))
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            _LOGGER.debug("Connection ended for %s: %s", self._label(client), exc)
        except Exception as exc:
            # Do not include exception text here: unexpected parser/library errors
            # must never accidentally log a payload or password.
            _LOGGER.warning(
                "Unexpected client failure for %s (%s)",
                self._label(client),
                type(exc).__name__,
            )
        finally:
            self._unregister(client)
            self._close_client(client)
            with self._lock:
                self._client_threads.discard(threading.current_thread())

    def _register(self, client: _Client, secure: bool) -> bool:
        """Validate the single registration frame and establish room membership."""

        try:
            message = recv_frame(client.sock)
            if message is None:
                return False
            if message.get("type") != "register":
                raise _RegistrationError(
                    "protocol_error", "the first frame must be a registration"
                )

            action = message.get("action")
            if not isinstance(action, str) or action not in ("create", "join"):
                raise _RegistrationError(
                    "invalid_action", "action must be 'create' or 'join'"
                )

            raw_mode = message.get("mode")
            if not isinstance(raw_mode, str):
                raise _RegistrationError("invalid_mode", "invalid room mode")
            try:
                mode = Mode(raw_mode)
            except ValueError as exc:
                raise _RegistrationError("invalid_mode", "invalid room mode") from exc

            if secure:
                if mode not in (Mode.TLS, Mode.E2E):
                    raise _RegistrationError(
                        "mode_mismatch", "the secure listener requires tls or e2e mode"
                    )
            elif mode is not Mode.PLAINTEXT:
                raise _RegistrationError(
                    "mode_mismatch", "the plaintext listener requires plaintext mode"
                )

            username = message.get("username")
            if not validate_username(username):
                raise _RegistrationError("invalid_username", "invalid username")

            password = message.get("password")
            if (
                not isinstance(password, str)
                or not password
                or len(password) > 256
            ):
                raise _RegistrationError(
                    "invalid_password", "password must contain 1-256 characters"
                )
            try:
                password_bytes = password.encode("utf-8")
            except UnicodeError as exc:
                raise _RegistrationError(
                    "invalid_password", "password is not valid Unicode"
                ) from exc

            public_key: str | None = None
            if mode is Mode.E2E:
                encoded_key = message.get("public_key")
                try:
                    raw_key = b64decode(encoded_key)
                except ValueError as exc:
                    raise _RegistrationError(
                        "invalid_public_key", "public_key must be canonical Base64"
                    ) from exc
                if len(raw_key) != _PUBLIC_KEY_BYTES:
                    raise _RegistrationError(
                        "invalid_public_key", "public_key must decode to 32 bytes"
                    )
                public_key = encoded_key

            if action == "create":
                room_name = message.get("room_name")
                if not validate_room_name(room_name):
                    raise _RegistrationError(
                        "invalid_room_name", "invalid room name"
                    )
                salt = secrets.token_bytes(_SALT_BYTES)
                digest = self._password_digest(password_bytes, salt)
                with self._lock:
                    if not self._running or client.closed:
                        return False
                    if len(self._rooms) >= _ROOM_CODE_SPACE:
                        raise _RegistrationError(
                            "room_capacity", "no room codes are available"
                        )
                    while True:
                        room_code = f"{secrets.randbelow(_ROOM_CODE_SPACE):06d}"
                        if room_code not in self._rooms:
                            break
                    room = _Room(
                        code=room_code,
                        name=room_name,
                        mode=mode,
                        password_salt=salt,
                        password_digest=digest,
                    )
                    self._rooms[room_code] = room
                    self._attach_client(client, room, username, mode, public_key)
            else:
                room_code = message.get("room_code")
                if not validate_room_code(room_code):
                    raise _RegistrationError("invalid_room_code", "invalid room code")
                with self._lock:
                    room = self._rooms.get(room_code)
                    if room is None:
                        raise _RegistrationError(
                            "room_not_found", "room does not exist"
                        )
                    if room.mode is not mode:
                        raise _RegistrationError(
                            "mode_mismatch", "room mode does not match registration"
                        )
                    salt = room.password_salt
                    expected_digest = room.password_digest

                # PBKDF2 is intentionally outside the registry lock.  Identity of
                # the room is checked again before membership is changed.
                digest = self._password_digest(password_bytes, salt)
                if not hmac.compare_digest(digest, expected_digest):
                    raise _RegistrationError(
                        "authentication_failed", "incorrect room password"
                    )

                with self._lock:
                    if not self._running or client.closed:
                        return False
                    if self._rooms.get(room_code) is not room:
                        raise _RegistrationError(
                            "room_not_found", "room does not exist"
                        )
                    if username in room.clients:
                        raise _RegistrationError(
                            "username_taken", "username is already present in the room"
                        )
                    self._attach_client(client, room, username, mode, public_key)

            return self._complete_registration(client, room)
        except _RegistrationError as exc:
            _LOGGER.debug(
                "Registration rejected for %s:%s: %s",
                client.address[0],
                client.address[1],
                exc.code,
            )
            self._send_error(client, exc.code, exc.message)
            return False

    @staticmethod
    def _password_digest(password: bytes, salt: bytes) -> bytes:
        """Derive the only password-related value retained by a room."""

        return hashlib.pbkdf2_hmac(
            "sha256", password, salt, _PASSWORD_ITERATIONS
        )

    @staticmethod
    def _attach_client(
        client: _Client,
        room: _Room,
        username: str,
        mode: Mode,
        public_key: str | None,
    ) -> None:
        """Reserve membership before welcome so username checks stay atomic."""

        client.username = username
        client.mode = mode
        client.public_key = public_key
        client.room = room
        client.ready = False
        room.clients[username] = client

    def _complete_registration(self, client: _Client, room: _Room) -> bool:
        """Send welcome first, then publish a roster containing the new member."""

        welcome = make_message(
            "welcome",
            mode=room.mode.value,
            username=client.username,
            room_code=room.code,
            room_name=room.name,
        )
        if not self._send(client, welcome):
            return False

        # Until ready=True, other roster publishers exclude this connection.
        # Thus no roster can overtake its welcome on its serialized socket.
        with self._roster_lock:
            with self._lock:
                if (
                    not self._running
                    or client.closed
                    or client not in self._connections
                    or client.room is not room
                ):
                    return False
                client.ready = True
                targets, roster = self._roster_snapshot(room)

            for target in targets:
                if not self._send(target, roster) and target is client:
                    return False
        return True

    def _roster_snapshot(self, room: _Room) -> tuple[list[_Client], dict[str, Any]]:
        """Build a deterministic roster; caller must hold the registry lock."""

        targets = [
            member
            for member in room.clients.values()
            if member.ready and not member.closed
        ]
        targets.sort(key=lambda member: member.username or "")
        peers: list[dict[str, str]] = []
        for member in targets:
            peer = {"username": member.username or ""}
            if room.mode is Mode.E2E:
                peer["public_key"] = member.public_key or ""
            peers.append(peer)
        return targets, make_message("roster", peers=peers)

    def _unregister(self, client: _Client) -> None:
        """Atomically remove a client and publish the resulting room roster."""

        with self._roster_lock:
            targets: list[_Client] = []
            roster: dict[str, Any] | None = None
            with self._lock:
                self._connections.discard(client)
                was_ready = client.ready
                room = client.room
                username = client.username
                client.ready = False
                client.room = None
                client.closed = True

                if room is not None and username is not None:
                    if room.clients.get(username) is client:
                        del room.clients[username]
                        if not room.clients:
                            if self._rooms.get(room.code) is room:
                                del self._rooms[room.code]
                        elif was_ready:
                            targets, roster = self._roster_snapshot(room)

            if roster is not None:
                for target in targets:
                    self._send(target, roster)

    def _handle_message(self, client: _Client, message: dict[str, Any]) -> bool:
        """Dispatch one post-registration message, rejecting cross-mode frames."""

        message_type = message["type"]
        if message_type == "register":
            self._send_error(
                client, "protocol_error", "registration is allowed only once"
            )
            return False

        if client.mode is Mode.E2E:
            if message_type != "e2e_send":
                return self._send_error(
                    client,
                    "mode_mismatch",
                    "e2e rooms accept only e2e_send messages",
                )
            try:
                return self._forward_e2e(client, message)
            except _MessageError as exc:
                return self._send_error(client, exc.code, exc.message)

        if client.mode in (Mode.PLAINTEXT, Mode.TLS):
            if message_type != "send":
                return self._send_error(
                    client,
                    "mode_mismatch",
                    "plaintext and tls rooms accept only send messages",
                )
            try:
                return self._forward_plaintext(client, message)
            except _MessageError as exc:
                return self._send_error(client, exc.code, exc.message)

        return False

    @staticmethod
    def _validated_id(message: dict[str, Any]) -> str:
        """Return a protocol-valid message identifier."""

        message_id = message.get("id")
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 64
        ):
            raise _MessageError(
                "invalid_id", "id must be a non-empty string of at most 64 characters"
            )
        return message_id

    def _forward_plaintext(
        self, client: _Client, message: dict[str, Any]
    ) -> bool:
        """Validate and forward plaintext/TLS application data."""

        recipient = message.get("to")
        if not isinstance(recipient, str) or not recipient:
            raise _MessageError("invalid_recipient", "invalid recipient")
        if recipient != "*" and not validate_username(recipient):
            raise _MessageError("invalid_recipient", "invalid recipient")
        message_id = self._validated_id(message)

        data = message.get("data")
        try:
            decoded = b64decode(data)
        except ValueError as exc:
            raise _MessageError(
                "invalid_data", "data must be canonical Base64"
            ) from exc
        if len(decoded) > _MAX_DATA_BYTES:
            raise _MessageError(
                "data_too_large", "decoded data exceeds 65536 bytes"
            )

        with self._lock:
            room = client.room
            username = client.username
            if (
                not self._running
                or client.closed
                or not client.ready
                or room is None
                or username is None
            ):
                return False
            if recipient == "*":
                targets = [
                    member
                    for member in room.clients.values()
                    if member is not client and member.ready and not member.closed
                ]
            else:
                target = room.clients.get(recipient)
                if target is None or not target.ready or target.closed:
                    raise _MessageError(
                        "unknown_recipient", "recipient is not in the room"
                    )
                targets = [target]

        for target in targets:
            delivery = make_message(
                "deliver",
                **{
                    "from": username,
                    "to": target.username,
                    "id": message_id,
                    "data": data,
                },
            )
            self._send(target, delivery)
        return True

    def _forward_e2e(self, client: _Client, message: dict[str, Any]) -> bool:
        """Validate and forward opaque E2E envelopes without inspecting content."""

        recipient = message.get("to")
        if (
            not isinstance(recipient, str)
            or recipient == "*"
            or not validate_username(recipient)
            or recipient == client.username
        ):
            raise _MessageError(
                "invalid_recipient", "e2e recipient must be another room member"
            )
        message_id = self._validated_id(message)

        nonce = message.get("nonce")
        try:
            decoded_nonce = b64decode(nonce)
        except ValueError as exc:
            raise _MessageError(
                "invalid_nonce", "nonce must be canonical Base64"
            ) from exc
        if len(decoded_nonce) != _NONCE_BYTES:
            raise _MessageError("invalid_nonce", "nonce must decode to 24 bytes")

        ciphertext = message.get("ciphertext")
        try:
            decoded_ciphertext = b64decode(ciphertext)
        except ValueError as exc:
            raise _MessageError(
                "invalid_ciphertext", "ciphertext must be canonical Base64"
            ) from exc
        if not decoded_ciphertext:
            raise _MessageError(
                "invalid_ciphertext", "ciphertext must not be empty"
            )
        if len(decoded_ciphertext) > MAX_FRAME_BYTES:
            raise _MessageError(
                "ciphertext_too_large", "ciphertext exceeds the relay limit"
            )

        with self._lock:
            room = client.room
            username = client.username
            if (
                not self._running
                or client.closed
                or not client.ready
                or room is None
                or username is None
            ):
                return False
            target = room.clients.get(recipient)
            if target is None or not target.ready or target.closed:
                raise _MessageError(
                    "unknown_recipient", "recipient is not in the room"
                )

        # The decoded ciphertext is used only for validation.  The original
        # canonical strings are forwarded unchanged, and no Box/key API is used.
        delivery = make_message(
            "e2e_deliver",
            **{
                "from": username,
                "to": recipient,
                "id": message_id,
                "nonce": nonce,
                "ciphertext": ciphertext,
            },
        )
        self._send(target, delivery)
        return True

    def _send_error(self, client: _Client, code: str, message: str) -> bool:
        """Best-effort error frame; a failed send closes only that client."""

        return self._send(client, make_message("error", code=code, message=message))

    def _send(self, client: _Client, message: dict[str, Any]) -> bool:
        """Serialize each connection's writes and isolate per-client failures."""

        if client.closed:
            return False
        try:
            with client.write_lock:
                if client.closed:
                    return False
                send_frame(client.sock, message)
            return True
        except (OSError, ssl.SSLError, ProtocolError) as exc:
            _LOGGER.debug("Send failed for %s: %s", self._label(client), exc)
            self._close_client(client)
            return False
        except Exception as exc:
            _LOGGER.warning(
                "Unexpected send failure for %s (%s)",
                self._label(client),
                type(exc).__name__,
            )
            self._close_client(client)
            return False

    def _close_client(self, client: _Client) -> None:
        """Mark and close a connection; repeated cleanup remains harmless."""

        with self._lock:
            client.closed = True
        try:
            client.sock.shutdown(socket.SHUT_RDWR)
        except OSError as exc:
            _LOGGER.debug("Socket shutdown failed for %s: %s", self._label(client), exc)
        try:
            client.sock.close()
        except OSError as exc:
            _LOGGER.debug("Socket close failed for %s: %s", self._label(client), exc)

    @staticmethod
    def _label(client: _Client) -> str:
        """Return a non-sensitive diagnostic label."""

        if client.username is not None:
            return client.username
        return f"{client.address[0]}:{client.address[1]}"


__all__ = ["RelayServer"]
