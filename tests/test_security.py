from __future__ import annotations

import hashlib
import json
import re
import ssl
import stat
from pathlib import Path

import pytest
from nacl.public import Box, PrivateKey, PublicKey

from chatrex.protocol import b64encode
from chatrex.security import (
    E2EError,
    Identity,
    TrustStore,
    create_client_context,
    create_server_context,
    fingerprint,
)
from chatrex.security import open as open_message
from chatrex.security import seal

ROOT = Path(__file__).resolve().parents[1]
CA_FILE = ROOT / "ca.crt"
CERT_FILE = ROOT / "server.crt"
KEY_FILE = ROOT / "server.key"


def test_tls_client_context_and_explicit_keylog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keylog = tmp_path / "explicit.keys"
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "environment.keys"))
    context = create_client_context(CA_FILE, keylog)

    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.keylog_filename == str(keylog)


def test_tls_keylog_environment_is_explicitly_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keylog = tmp_path / "environment.keys"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    context = create_client_context(str(CA_FILE))
    assert context.keylog_filename == str(keylog)


def test_tls_server_context_and_path_arguments(tmp_path: Path) -> None:
    keylog = tmp_path / "server.keys"
    context = create_server_context(CERT_FILE, str(KEY_FILE), keylog)

    assert context.protocol == ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.check_hostname is False
    assert context.keylog_filename == str(keylog)


def test_identity_private_bytes_and_atomic_persistence(tmp_path: Path) -> None:
    private_bytes = bytes(range(32))
    identity = Identity.from_private_bytes(private_bytes)
    assert identity.public_key == bytes(PrivateKey(private_bytes).public_key)
    assert Identity.generate().public_key != identity.public_key

    path = tmp_path / "identity.key"
    path.write_bytes(b"old key material")
    path.chmod(0o644)
    identity.save(path)

    assert path.read_bytes() == private_bytes
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = Identity.load(str(path))
    assert loaded.public_key == identity.public_key
    assert list(tmp_path.glob(".identity.key.*.tmp")) == []

    for invalid in (b"", b"x" * 31, b"x" * 33):
        with pytest.raises(ValueError):
            Identity.from_private_bytes(invalid)


def test_fingerprint_is_stable_grouped_and_domain_separated() -> None:
    identity = Identity.from_private_bytes(bytes(range(32)))
    result = identity.fingerprint("alice")

    digest = hashlib.sha256(
        b"chatrex-e2e-v1\0" + b"\x05alice" + identity.public_key
    ).hexdigest().upper()
    expected = "SHA256:" + ":".join(
        digest[index : index + 4] for index in range(0, 64, 4)
    )
    assert result == expected
    assert fingerprint("alice", PublicKey(identity.public_key)) == result
    assert re.fullmatch(r"SHA256:(?:[0-9A-F]{4}:){15}[0-9A-F]{4}", result)
    assert len(result.removeprefix("SHA256:").replace(":", "")) == 64
    assert result != identity.fingerprint("bob")
    assert result != Identity.generate().fingerprint("alice")

    with pytest.raises(ValueError):
        fingerprint("bad name", identity.public_key)
    with pytest.raises(ValueError):
        fingerprint("alice", b"short")


def test_trust_requires_explicit_match_and_rotates_only_after_verification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trust.json"
    store = TrustStore(path)
    room = "123456"
    old_identity = Identity.from_private_bytes(bytes(range(32)))
    new_identity = Identity.from_private_bytes(bytes(range(1, 33)))
    old_fingerprint = old_identity.fingerprint("alice")
    new_fingerprint = new_identity.fingerprint("alice")

    for malformed in ("", "SHA256:wrong", old_fingerprint.lower(), None, "é"):
        assert not store.verify(
            room,
            "alice",
            old_identity.public_key,
            malformed,  # type: ignore[arg-type]
        )
    assert not path.exists()
    assert store.key_for(room, "alice") is None

    assert store.verify(
        room, "alice", old_identity.public_key, old_fingerprint
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.is_verified(room, "alice", old_identity.public_key)
    assert store.is_verified(
        room, "alice", PublicKey(old_identity.public_key)
    )
    assert bytes(store.key_for(room, "alice")) == old_identity.public_key  # type: ignore[arg-type]

    # A changed or unverified key never inherits the previous pin.
    assert not store.is_verified(room, "alice", new_identity.public_key)
    assert not store.verify(
        room, "alice", new_identity.public_key, old_fingerprint
    )
    assert store.is_verified(room, "alice", old_identity.public_key)
    assert not store.is_verified(room, "alice", new_identity.public_key)

    assert store.verify(
        room, "alice", new_identity.public_key, new_fingerprint
    )
    assert not store.is_verified(room, "alice", old_identity.public_key)
    assert store.is_verified(room, "alice", new_identity.public_key)


def test_trust_persistence_reads_do_not_write_and_removal_is_scoped(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trust.json"
    identity = Identity.from_private_bytes(bytes(range(32)))
    expected = identity.fingerprint("alice")
    store = TrustStore(path)
    assert store.verify("123456", "alice", identity.public_key, expected)
    assert store.verify("654321", "alice", identity.public_key, expected)

    before_content = path.read_bytes()
    before_mtime = path.stat().st_mtime_ns
    reloaded = TrustStore(str(path))
    assert reloaded.is_verified("123456", "alice", identity.public_key)
    assert reloaded.key_for("654321", "alice") is not None
    assert path.read_bytes() == before_content
    assert path.stat().st_mtime_ns == before_mtime

    reloaded.remove("123456", "alice")
    assert reloaded.key_for("123456", "alice") is None
    assert reloaded.key_for("654321", "alice") is not None
    reloaded.clear()
    assert reloaded.key_for("654321", "alice") is None
    assert json.loads(path.read_text(encoding="utf-8")) == {}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_trust_rejects_malformed_persisted_keys(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(
        '{"123456":{"alice":{"key":"****","fingerprint":"SHA256:bad"}}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        TrustStore(path)


def test_seal_open_roundtrip_and_fresh_nonces() -> None:
    alice = Identity.from_private_bytes(bytes(range(32)))
    bob = Identity.from_private_bytes(bytes(range(32, 64)))
    payload = b"\x00binary payload\xff"

    nonce, ciphertext = seal(
        alice,
        "alice",
        "bob",
        PublicKey(bob.public_key),
        "message-1",
        payload,
    )
    assert len(nonce) == 24
    assert open_message(
        bob,
        "alice",
        "bob",
        alice.public_key,
        "message-1",
        nonce,
        ciphertext,
    ) == payload

    second_nonce, second_ciphertext = seal(
        alice, "alice", "bob", bob.public_key, "message-1", payload
    )
    assert second_nonce != nonce
    assert second_ciphertext != ciphertext


@pytest.mark.parametrize(
    ("sender", "recipient", "message_id"),
    [
        ("mallory", "bob", "message-1"),
        ("alice", "mallory", "message-1"),
        ("alice", "bob", "message-2"),
    ],
)
def test_open_rejects_authenticated_metadata_mismatch(
    sender: str, recipient: str, message_id: str
) -> None:
    alice = Identity.from_private_bytes(bytes(range(32)))
    bob = Identity.from_private_bytes(bytes(range(32, 64)))
    nonce, ciphertext = seal(
        alice, "alice", "bob", bob.public_key, "message-1", b"secret"
    )

    with pytest.raises(E2EError):
        open_message(
            bob,
            sender,
            recipient,
            alice.public_key,
            message_id,
            nonce,
            ciphertext,
        )


def test_open_rejects_tampering_and_wrong_keys() -> None:
    alice = Identity.from_private_bytes(bytes(range(32)))
    bob = Identity.from_private_bytes(bytes(range(32, 64)))
    nonce, ciphertext = seal(
        alice, "alice", "bob", bob.public_key, "message-1", b"secret"
    )

    tampered = bytes((ciphertext[0] ^ 1,)) + ciphertext[1:]
    with pytest.raises(E2EError):
        open_message(
            bob,
            "alice",
            "bob",
            alice.public_key,
            "message-1",
            nonce,
            tampered,
        )
    with pytest.raises(E2EError):
        open_message(
            bob,
            "alice",
            "bob",
            Identity.generate().public_key,
            "message-1",
            nonce,
            ciphertext,
        )
    with pytest.raises(E2EError):
        open_message(
            bob,
            "alice",
            "bob",
            alice.public_key,
            "message-1",
            nonce[:-1],
            ciphertext,
        )
    with pytest.raises(E2EError):
        open_message(
            bob,
            "alice",
            "bob",
            alice.public_key,
            "message-1",
            nonce,
            b"",
        )


def encrypt_inner(plaintext: bytes, nonce: bytes = b"n" * 24) -> bytes:
    sender_private = PrivateKey(bytes(range(32)))
    recipient_public = PublicKey(
        bytes(PrivateKey(bytes(range(32, 64))).public_key)
    )
    return bytes(
        Box(sender_private, recipient_public).encrypt(plaintext, nonce).ciphertext
    )


def open_inner(ciphertext: bytes, nonce: bytes = b"n" * 24) -> bytes:
    bob = Identity.from_private_bytes(bytes(range(32, 64)))
    alice_public = bytes(PrivateKey(bytes(range(32))).public_key)
    return open_message(
        bob,
        "alice",
        "bob",
        alice_public,
        "message-1",
        nonce,
        ciphertext,
    )


@pytest.mark.parametrize("plaintext", [b"\xff", b"{", b"[]", b"null"])
def test_open_rejects_non_object_or_invalid_json(plaintext: bytes) -> None:
    with pytest.raises(E2EError):
        open_inner(encrypt_inner(plaintext))


def test_open_strictly_validates_every_inner_field() -> None:
    valid = {
        "v": 1,
        "kind": "data",
        "id": "message-1",
        "from": "alice",
        "to": "bob",
        "data": b64encode(b"payload"),
    }
    invalid_envelopes = [
        {**valid, "v": 2},
        {**valid, "v": True},
        {**valid, "v": 1.0},
        {**valid, "kind": "control"},
        {**valid, "id": "message-2"},
        {**valid, "from": "mallory"},
        {**valid, "to": "mallory"},
        {**valid, "data": 7},
        {**valid, "data": "not base64!"},
        {**valid, "data": "AB=="},
        {**valid, "extra": "not allowed"},
        {key: value for key, value in valid.items() if key != "id"},
    ]

    for inner in invalid_envelopes:
        plaintext = json.dumps(inner, separators=(",", ":")).encode("utf-8")
        with pytest.raises(E2EError):
            open_inner(encrypt_inner(plaintext))


def test_seal_rejects_malformed_metadata_and_payload() -> None:
    alice = Identity.generate()
    bob = Identity.generate()

    for sender, recipient, message_id in (
        ("bad name", "bob", "id"),
        ("alice", "bad name", "id"),
        ("alice", "bob", ""),
        ("alice", "bob", None),
    ):
        with pytest.raises(E2EError):
            seal(
                alice,
                sender,
                recipient,
                bob.public_key,
                message_id,  # type: ignore[arg-type]
                b"payload",
            )
    with pytest.raises(E2EError):
        seal(alice, "alice", "bob", b"short", "id", b"payload")
    with pytest.raises(E2EError):
        seal(
            alice,
            "alice",
            "bob",
            bob.public_key,
            "id",
            "text",  # type: ignore[arg-type]
        )
