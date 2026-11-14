"""TLS contexts, persistent identity, explicit trust, and E2E encryption."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, TypeAlias

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random

from .protocol import b64decode, b64encode, validate_room_code, validate_username

StrPath: TypeAlias = str | os.PathLike[str]
PublicKeyLike: TypeAlias = PublicKey | bytes

_FINGERPRINT_DOMAIN = b"chatrex-e2e-v1\0"
_KEY_BYTES = 32
_NONCE_BYTES = 24
_INNER_FIELDS = {"v", "kind", "id", "from", "to", "data"}


class E2EError(Exception):
    """Raised when an E2E message cannot be sealed or safely opened."""


def _apply_keylog_file(
    context: ssl.SSLContext, keylog_file: StrPath | None
) -> None:
    selected = (
        keylog_file
        if keylog_file is not None
        else os.environ.get("SSLKEYLOGFILE")
    )
    if selected is not None:
        context.keylog_filename = os.fspath(selected)


def create_client_context(
    ca_file: StrPath, keylog_file: StrPath | None = None
) -> ssl.SSLContext:
    """Create a TLS 1.3-only client context anchored at *ca_file*."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=os.fspath(ca_file))
    _apply_keylog_file(context, keylog_file)
    return context


def create_server_context(
    cert_file: StrPath,
    key_file: StrPath,
    keylog_file: StrPath | None = None,
) -> ssl.SSLContext:
    """Create a TLS 1.3-only server context using the supplied key pair."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=os.fspath(cert_file), keyfile=os.fspath(key_file))
    _apply_keylog_file(context, keylog_file)
    return context


def _atomic_write(path: Path, data: bytes) -> None:
    """Replace *path* with a 0600 file without exposing partial contents."""

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _public_key_bytes(public_key: PublicKeyLike) -> bytes:
    if isinstance(public_key, PublicKey):
        raw = bytes(public_key)
    elif isinstance(public_key, bytes):
        raw = public_key
    else:
        raise TypeError("public key must be PublicKey or raw bytes")
    if len(raw) != _KEY_BYTES:
        raise ValueError("public key must contain exactly 32 bytes")
    return raw


def fingerprint(username: str, public_key: PublicKeyLike) -> str:
    """Compute the grouped, uppercase SHA-256 fingerprint for a user's key."""

    if not validate_username(username):
        raise ValueError("invalid username")
    raw_key = _public_key_bytes(public_key)
    encoded_username = username.encode("ascii")
    digest = hashlib.sha256(
        _FINGERPRINT_DOMAIN
        + bytes((len(encoded_username),))
        + encoded_username
        + raw_key
    ).hexdigest().upper()
    return "SHA256:" + ":".join(
        digest[offset : offset + 4] for offset in range(0, len(digest), 4)
    )


def _fingerprints_match(left: str, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_bytes = left.encode("ascii")
        right_bytes = right.encode("ascii")
    except UnicodeError:
        return False
    return hmac.compare_digest(left_bytes, right_bytes)


class Identity:
    """An X25519 NaCl private key and its corresponding public identity."""

    def __init__(self, private_key: PrivateKey):
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a NaCl PrivateKey")
        self._private_key = private_key

    @classmethod
    def generate(cls) -> Identity:
        """Generate a fresh random identity."""

        return cls(PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, private_key: bytes) -> Identity:
        """Restore an identity from its raw 32-byte private key."""

        if not isinstance(private_key, bytes) or len(private_key) != _KEY_BYTES:
            raise ValueError("private key must contain exactly 32 bytes")
        return cls(PrivateKey(private_key))

    @property
    def public_key(self) -> bytes:
        """Return the raw 32-byte X25519 public key."""

        return bytes(self._private_key.public_key)

    def save(self, path: StrPath) -> None:
        """Atomically save the raw private key in a 0600 file."""

        _atomic_write(Path(path), bytes(self._private_key))

    @classmethod
    def load(cls, path: StrPath) -> Identity:
        """Load an identity saved by :meth:`save`."""

        return cls.from_private_bytes(Path(path).read_bytes())

    def fingerprint(self, username: str) -> str:
        """Return this identity's fingerprint for *username*."""

        return fingerprint(username, self.public_key)


@dataclass(frozen=True)
class _TrustEntry:
    public_key: bytes
    fingerprint: str


def _validate_scope(room: str, username: str) -> None:
    if not validate_room_code(room):
        raise ValueError("room must be a six-digit ASCII room code")
    if not validate_username(username):
        raise ValueError("invalid username")


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


class TrustStore:
    """Explicitly verified peer keys, scoped by room code and username.

    If *path* is provided, entries are persisted as JSON using atomic 0600
    writes.  Verification is always explicit: observing a key never pins it.
    """

    def __init__(self, path: StrPath | None = None):
        self._path = Path(path) if path is not None else None
        self._entries: dict[str, dict[str, _TrustEntry]] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            raw_document = self._path.read_bytes()
        except FileNotFoundError:
            return

        try:
            document = json.loads(
                raw_document.decode("utf-8"),
                parse_constant=_reject_json_constant,
            )
            if not isinstance(document, dict):
                raise ValueError("trust store root must be an object")

            loaded: dict[str, dict[str, _TrustEntry]] = {}
            for room, users in document.items():
                if not validate_room_code(room) or not isinstance(users, dict):
                    raise ValueError("invalid room entry in trust store")
                loaded_users: dict[str, _TrustEntry] = {}
                for username, record in users.items():
                    _validate_scope(room, username)
                    if not isinstance(record, dict):
                        raise ValueError("invalid user entry in trust store")
                    encoded_key = record.get("key")
                    stored_fingerprint = record.get("fingerprint")
                    if not isinstance(encoded_key, str) or not isinstance(
                        stored_fingerprint, str
                    ):
                        raise ValueError("incomplete user entry in trust store")
                    raw_key = b64decode(encoded_key)
                    if len(raw_key) != _KEY_BYTES:
                        raise ValueError("invalid key length in trust store")
                    computed = fingerprint(username, raw_key)
                    if not _fingerprints_match(computed, stored_fingerprint):
                        raise ValueError("fingerprint mismatch in trust store")
                    loaded_users[username] = _TrustEntry(raw_key, computed)
                loaded[room] = loaded_users
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid trust store") from exc

        self._entries = loaded

    def _save(self) -> None:
        if self._path is None:
            return
        document = {
            room: {
                username: {
                    "key": b64encode(entry.public_key),
                    "fingerprint": entry.fingerprint,
                }
                for username, entry in users.items()
            }
            for room, users in self._entries.items()
        }
        encoded = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        _atomic_write(self._path, encoded)

    def verify(
        self,
        room: str,
        username: str,
        public_key: PublicKeyLike,
        expected_fingerprint: str,
    ) -> bool:
        """Pin a key only when its fingerprint matches explicit verification."""

        _validate_scope(room, username)
        try:
            raw_key = _public_key_bytes(public_key)
        except (TypeError, ValueError):
            return False
        computed = fingerprint(username, raw_key)
        if not _fingerprints_match(computed, expected_fingerprint):
            return False

        self._entries.setdefault(room, {})[username] = _TrustEntry(
            raw_key, computed
        )
        self._save()
        return True

    def is_verified(
        self, room: str, username: str, public_key: PublicKeyLike
    ) -> bool:
        """Return true only for the exact pinned key and a valid fingerprint."""

        _validate_scope(room, username)
        try:
            raw_key = _public_key_bytes(public_key)
        except (TypeError, ValueError):
            return False
        entry = self._entries.get(room, {}).get(username)
        if entry is None:
            return False

        computed = fingerprint(username, raw_key)
        fingerprint_matches = _fingerprints_match(entry.fingerprint, computed)
        key_matches = hmac.compare_digest(entry.public_key, raw_key)
        return key_matches and fingerprint_matches

    def key_for(self, room: str, username: str) -> PublicKey | None:
        """Return the verified key for a peer, or ``None`` if it is not valid."""

        _validate_scope(room, username)
        entry = self._entries.get(room, {}).get(username)
        if entry is None:
            return None
        computed = fingerprint(username, entry.public_key)
        if not _fingerprints_match(computed, entry.fingerprint):
            return None
        return PublicKey(entry.public_key)

    def remove(self, room: str, username: str) -> None:
        """Remove a peer's pin, typically when that peer leaves the roster."""

        _validate_scope(room, username)
        users = self._entries.get(room)
        if users is None or username not in users:
            return
        del users[username]
        if not users:
            del self._entries[room]
        self._save()

    def clear(self) -> None:
        """Remove every persisted and in-memory pin."""

        if not self._entries:
            return
        self._entries.clear()
        self._save()


def _validate_e2e_metadata(
    sender: str, recipient: str, message_id: str
) -> None:
    if not validate_username(sender) or not validate_username(recipient):
        raise E2EError("invalid sender or recipient username")
    if not isinstance(message_id, str) or not message_id:
        raise E2EError("message id must be a non-empty string")


def _box_for(identity: Identity, peer_public_key: PublicKeyLike) -> Box:
    if not isinstance(identity, Identity):
        raise E2EError("identity must be an Identity instance")
    try:
        peer_key = PublicKey(_public_key_bytes(peer_public_key))
    except (TypeError, ValueError) as exc:
        raise E2EError("invalid peer public key") from exc
    return Box(identity._private_key, peer_key)


def seal(
    identity: Identity,
    sender: str,
    recipient: str,
    recipient_public_key: PublicKeyLike,
    message_id: str,
    payload: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt an authenticated E2E data envelope.

    Returns ``(nonce, ciphertext)`` with a fresh 24-byte nonce.  The ciphertext
    excludes the nonce so the two values can be carried separately by clients.
    """

    _validate_e2e_metadata(sender, recipient, message_id)
    if not isinstance(payload, bytes):
        raise E2EError("payload must be bytes")
    box = _box_for(identity, recipient_public_key)
    inner = {
        "v": 1,
        "kind": "data",
        "id": message_id,
        "from": sender,
        "to": recipient,
        "data": b64encode(payload),
    }
    plaintext = json.dumps(
        inner, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    nonce = random(_NONCE_BYTES)
    encrypted = box.encrypt(plaintext, nonce)
    return nonce, bytes(encrypted.ciphertext)


def open(
    identity: Identity,
    sender: str,
    recipient: str,
    sender_public_key: PublicKeyLike,
    message_id: str,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt and strictly validate an E2E envelope, returning its payload.

    Every decryption, decoding, and metadata validation failure raises
    :class:`E2EError`; no unvalidated plaintext is ever returned.
    """

    try:
        _validate_e2e_metadata(sender, recipient, message_id)
        if not isinstance(nonce, bytes) or len(nonce) != _NONCE_BYTES:
            raise E2EError("nonce must contain exactly 24 bytes")
        if not isinstance(ciphertext, bytes):
            raise E2EError("ciphertext must be bytes")

        box = _box_for(identity, sender_public_key)
        try:
            plaintext = box.decrypt(ciphertext, nonce)
        except (CryptoError, TypeError, ValueError) as exc:
            raise E2EError("E2E authentication or decryption failed") from exc

        try:
            inner = json.loads(
                plaintext.decode("utf-8"),
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise E2EError("decrypted envelope is not valid UTF-8 JSON") from exc

        if not isinstance(inner, dict) or set(inner) != _INNER_FIELDS:
            raise E2EError("decrypted envelope has invalid fields")
        version = inner["v"]
        if type(version) is not int or version != 1:
            raise E2EError("decrypted envelope has an invalid version")
        if inner["kind"] != "data":
            raise E2EError("decrypted envelope has an invalid kind")
        if (
            not isinstance(inner["id"], str)
            or not inner["id"]
            or inner["id"] != message_id
            or not isinstance(inner["from"], str)
            or inner["from"] != sender
            or not isinstance(inner["to"], str)
            or inner["to"] != recipient
        ):
            raise E2EError("decrypted envelope metadata does not match")
        if not isinstance(inner["data"], str):
            raise E2EError("decrypted envelope data must be Base64 text")

        try:
            return b64decode(inner["data"])
        except ValueError as exc:
            raise E2EError("decrypted envelope contains invalid Base64") from exc
    except E2EError:
        raise
    except Exception as exc:
        # Keep the public decryption boundary consistent for malformed input.
        raise E2EError("could not open E2E message") from exc


__all__ = [
    "E2EError",
    "Identity",
    "TrustStore",
    "create_client_context",
    "create_server_context",
    "fingerprint",
    "open",
    "seal",
]
