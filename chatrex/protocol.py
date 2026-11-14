"""Wire framing and validation helpers for the ChatreX protocol."""

from __future__ import annotations

import base64
import binascii
import json
import re
import struct
from enum import Enum
from typing import Any, NoReturn, Protocol

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1_048_576

_HEADER = struct.Struct("!I")
_USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{1,24}\Z")
_ROOM_CODE_RE = re.compile(r"[0-9]{6}\Z")


class ProtocolError(Exception):
    """Raised when a frame is malformed or a connection ends mid-frame."""


class Mode(str, Enum):
    """Application transmission modes."""

    PLAINTEXT = "plaintext"
    TLS = "tls"
    E2E = "e2e"


# The plural spelling is an alias, not a distinct enum type.
Modes = Mode


class _SocketLike(Protocol):
    def recv(self, bufsize: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...


def recv_exact(sock: _SocketLike, size: int) -> bytes | None:
    """Read exactly *size* bytes, tolerating short socket reads.

    ``None`` is returned only for a clean EOF before the first byte.  EOF after
    a partial value is a protocol error.  A zero-length read returns ``b""``.
    """

    if size < 0:
        raise ValueError("size must be non-negative")

    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if not data:
                return None
            raise ProtocolError("connection closed during a partial value")
        data.extend(chunk)
    return bytes(data)


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_frame(frame: object) -> None:
    if not isinstance(frame, dict):
        raise ProtocolError("frame must be a JSON object")
    if any(not isinstance(key, str) for key in frame):
        raise ProtocolError("frame keys must be strings")

    version = frame.get("v")
    if type(version) is not int or version != PROTOCOL_VERSION:
        raise ProtocolError("frame must contain integer v=1")

    message_type = frame.get("type")
    if not isinstance(message_type, str) or not message_type:
        raise ProtocolError("frame must contain a non-empty string type")


def send_frame(sock: _SocketLike, frame: dict[str, Any]) -> None:
    """Validate and send one compact, length-prefixed JSON frame."""

    _validate_frame(frame)
    try:
        payload = json.dumps(
            frame,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("frame is not JSON serializable") from exc

    length = len(payload)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise ProtocolError(f"frame payload exceeds {MAX_FRAME_BYTES} bytes")
    sock.sendall(_HEADER.pack(length) + payload)


def recv_frame(sock: _SocketLike) -> dict[str, Any] | None:
    """Receive and validate one frame.

    A clean EOF before any header byte returns ``None``.  All partial frames,
    invalid lengths, malformed JSON, and invalid protocol envelopes raise
    :class:`ProtocolError`.
    """

    header = recv_exact(sock, _HEADER.size)
    if header is None:
        return None

    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise ProtocolError("zero-length frames are not allowed")
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(f"frame payload exceeds {MAX_FRAME_BYTES} bytes")

    payload = recv_exact(sock, length)
    if payload is None:
        raise ProtocolError("connection closed before the frame payload")

    try:
        text = payload.decode("utf-8")
        frame = json.loads(text, parse_constant=_reject_json_constant)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame is not valid UTF-8 JSON") from exc

    _validate_frame(frame)
    return frame


def b64encode(data: bytes) -> str:
    """Return canonical padded Base64 as ASCII text."""

    return base64.b64encode(data).decode("ascii")


def b64decode(value: str) -> bytes:
    """Decode canonical padded Base64, rejecting whitespace and bad input."""

    if not isinstance(value, str):
        raise ValueError("Base64 value must be text")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise ValueError("invalid Base64 value") from exc

    # validate=True checks the alphabet and padding, but not unused pad bits.
    if b64encode(decoded) != value:
        raise ValueError("Base64 value is not canonical")
    return decoded


def validate_username(username: str) -> bool:
    """Return whether a username is 1-24 ASCII letters, digits, ``_``/``-``."""

    return isinstance(username, str) and _USERNAME_RE.fullmatch(username) is not None


def validate_room_name(room_name: str) -> bool:
    """Return whether a room name is 1-32 printable, non-control characters."""

    return (
        isinstance(room_name, str)
        and 1 <= len(room_name) <= 32
        and room_name.isprintable()
    )


def validate_room_code(room_code: str) -> bool:
    """Return whether a room code consists of exactly six ASCII digits."""

    return (
        isinstance(room_code, str)
        and _ROOM_CODE_RE.fullmatch(room_code) is not None
    )


def make_message(message_type: str, **fields: Any) -> dict[str, Any]:
    """Build an application message with the protocol envelope populated."""

    if not isinstance(message_type, str) or not message_type:
        raise ValueError("message type must be a non-empty string")
    message = dict(fields)
    message["v"] = PROTOCOL_VERSION
    message["type"] = message_type
    return message


__all__ = [
    "MAX_FRAME_BYTES",
    "PROTOCOL_VERSION",
    "Mode",
    "Modes",
    "ProtocolError",
    "b64decode",
    "b64encode",
    "make_message",
    "recv_exact",
    "recv_frame",
    "send_frame",
    "validate_room_code",
    "validate_room_name",
    "validate_username",
]
