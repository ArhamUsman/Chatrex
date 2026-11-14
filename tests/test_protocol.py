from __future__ import annotations

import json
import socket
import struct
from typing import Any

import pytest

from chatrex.protocol import (
    MAX_FRAME_BYTES,
    Mode,
    Modes,
    ProtocolError,
    b64decode,
    b64encode,
    make_message,
    recv_exact,
    recv_frame,
    send_frame,
    validate_room_code,
    validate_room_name,
    validate_username,
)


class ShortReadSocket:
    """Socket wrapper that deliberately returns very short reads."""

    def __init__(self, sock: socket.socket, chunk_size: int = 2):
        self._sock = sock
        self._chunk_size = chunk_size

    def recv(self, size: int) -> bytes:
        return self._sock.recv(min(size, self._chunk_size))

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)


def encoded_frame(frame: dict[str, Any]) -> bytes:
    payload = json.dumps(
        frame, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return struct.pack("!I", len(payload)) + payload


def raw_frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def test_modes_and_message_envelope() -> None:
    assert [mode.value for mode in Mode] == ["plaintext", "tls", "e2e"]
    assert Modes is Mode
    assert make_message(
        "data", text="hello", v=99, type="ignored"
    ) == {"text": "hello", "v": 1, "type": "data"}
    with pytest.raises(ValueError):
        make_message("")


def test_base64_is_strict_and_canonical() -> None:
    for value in (b"", b"\x00", b"chat rex", bytes(range(256))):
        assert b64decode(b64encode(value)) == value

    for malformed in (
        "A",
        "AA=A",
        "A A==",
        "AA==\n",
        "****",
        "AB==",  # Non-zero unused padding bits.
        "é",
    ):
        with pytest.raises(ValueError):
            b64decode(malformed)
    with pytest.raises(ValueError):
        b64decode(b"AA==")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("username", "valid"),
    [
        ("a", True),
        ("A-user_09", True),
        ("a" * 24, True),
        ("", False),
        ("a" * 25, False),
        ("has space", False),
        ("slash/name", False),
        ("é", False),
        ("１２", False),
        (None, False),
    ],
)
def test_username_validation(username: object, valid: bool) -> None:
    assert validate_username(username) is valid  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("room_name", "valid"),
    [
        ("General", True),
        (" spaces are printable ", True),
        ("Salle café \U0001f600", True),
        ("x" * 32, True),
        ("", False),
        ("x" * 33, False),
        ("line\nbreak", False),
        ("tab\tname", False),
        ("control\x7f", False),
        (None, False),
    ],
)
def test_room_name_validation(room_name: object, valid: bool) -> None:
    assert validate_room_name(room_name) is valid  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("room_code", "valid"),
    [
        ("000000", True),
        ("123456", True),
        ("12345", False),
        ("1234567", False),
        ("12345a", False),
        ("١٢٣٤٥٦", False),
        ("123456\n", False),
        (123456, False),
    ],
)
def test_room_code_validation(room_code: object, valid: bool) -> None:
    assert validate_room_code(room_code) is valid  # type: ignore[arg-type]


def test_recv_exact_handles_short_reads() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"abcdef")
        wrapped = ShortReadSocket(right, chunk_size=1)
        assert recv_exact(wrapped, 6) == b"abcdef"
        assert recv_exact(wrapped, 0) == b""
    with pytest.raises(ValueError):
        recv_exact(ShortReadSocket(right), -1)


def test_coalesced_frames_survive_short_reads() -> None:
    left, right = socket.socketpair()
    first = make_message("data", text="first")
    second = make_message("data", text="second", value=2)
    with left, right:
        # One write places both frames in the stream at once.
        left.sendall(encoded_frame(first) + encoded_frame(second))
        wrapped = ShortReadSocket(right, chunk_size=3)
        assert recv_frame(wrapped) == first
        assert recv_frame(wrapped) == second


def test_clean_eof_returns_none() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.shutdown(socket.SHUT_WR)
        assert recv_frame(right) is None


@pytest.mark.parametrize(
    "partial",
    [
        b"\x00",
        b"\x00\x00\x00",
        struct.pack("!I", 5),
        struct.pack("!I", 5) + b"ab",
    ],
)
def test_partial_frames_raise(partial: bytes) -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(partial)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ProtocolError):
            recv_frame(right)


@pytest.mark.parametrize(
    "wire_data",
    [
        struct.pack("!I", 0),
        struct.pack("!I", MAX_FRAME_BYTES + 1),
        raw_frame(b"\xff"),
        raw_frame(b"{"),
        raw_frame(b"[]"),
        raw_frame(b"null"),
        raw_frame(b'{"type":"data"}'),
        raw_frame(b'{"v":1}'),
        raw_frame(b'{"v":0,"type":"data"}'),
        raw_frame(b'{"v":true,"type":"data"}'),
        raw_frame(b'{"v":1.0,"type":"data"}'),
        raw_frame(b'{"v":"1","type":"data"}'),
        raw_frame(b'{"v":1,"type":""}'),
        raw_frame(b'{"v":1,"type":2}'),
        raw_frame(b'{"v":1,"type":"data","value":NaN}'),
    ],
)
def test_malformed_frames_raise(wire_data: bytes) -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(wire_data)
        with pytest.raises(ProtocolError):
            recv_frame(right)


@pytest.mark.parametrize(
    "frame",
    [
        None,
        [],
        {},
        {"v": 1},
        {"type": "data"},
        {"v": True, "type": "data"},
        {"v": 1.0, "type": "data"},
        {"v": 1, "type": ""},
        {"v": 1, "type": None},
        {"v": 1, "type": "data", "bad": {1, 2}},
        {"v": 1, "type": "data", "bad": float("nan")},
    ],
)
def test_send_frame_rejects_invalid_messages(frame: object) -> None:
    left, right = socket.socketpair()
    with left, right:
        with pytest.raises(ProtocolError):
            send_frame(left, frame)  # type: ignore[arg-type]


def test_send_frame_rejects_oversize_payload() -> None:
    left, right = socket.socketpair()
    with left, right:
        frame = make_message("data", text="x" * MAX_FRAME_BYTES)
        with pytest.raises(ProtocolError):
            send_frame(left, frame)


def test_send_frame_uses_big_endian_length_and_compact_utf8_json() -> None:
    left, right = socket.socketpair()
    frame = make_message("data", text="hé")
    expected_payload = b'{"text":"h\xc3\xa9","v":1,"type":"data"}'
    with left, right:
        send_frame(left, frame)
        wire = right.recv(4096)
        assert wire[:4] == struct.pack("!I", len(expected_payload))
        assert wire[4:] == expected_payload
