"""Interactive command-line client for ChatreX."""

from __future__ import annotations

import argparse
import getpass
import queue
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from chatrex.client import ChatClient, ChatClientError, TrustError
from chatrex.protocol import (
    Mode,
    ProtocolError,
    validate_room_code,
    validate_room_name,
    validate_username,
)
from chatrex.security import E2EError, Identity, TrustStore

try:
    import readline as _readline
except ImportError:  # pragma: no cover - readline is platform-dependent
    _readline = None

PROJECT_ROOT = Path(__file__).resolve().parent
Event = dict[str, Any]
EventQueue = queue.Queue[Event | None]


class Console:
    """Serialize event output and restore the current input prompt when possible."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._interactive = sys.stdin.isatty() and sys.stdout.isatty()
        self._reading = False

    def write(self, text: str) -> None:
        with self._lock:
            if not self._interactive:
                print(text, flush=True)
                return
            line_buffer = self._line_buffer() if self._reading else ""
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.write(f"{text}\n")
            if self._reading:
                sys.stdout.write(f"> {line_buffer}")
            sys.stdout.flush()

    def read_line(self) -> str | None:
        if not self._interactive:
            line = sys.stdin.readline()
            return line if line else None

        with self._lock:
            self._reading = True
            sys.stdout.write("> ")
            sys.stdout.flush()
        try:
            return input()
        except EOFError:
            return None
        finally:
            with self._lock:
                self._reading = False

    def stop(self) -> None:
        with self._lock:
            self._reading = False

    @staticmethod
    def _line_buffer() -> str:
        if _readline is None:
            return ""
        return _readline.get_line_buffer()


def _client_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _room_code(value: str) -> str:
    if not validate_room_code(value):
        raise argparse.ArgumentTypeError("room code must contain exactly six digits")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or join a ChatreX room from the command line."
    )
    parser.add_argument("--host", default="10.0.3.10", help="relay hostname or address")
    parser.add_argument("--username", required=True, help="room display name")
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in Mode],
        default=Mode.TLS.value,
        help="security mode (default: tls)",
    )
    room = parser.add_mutually_exclusive_group(required=True)
    room.add_argument("--create", metavar="ROOM_NAME", help="create a new room")
    room.add_argument(
        "--join", type=_room_code, metavar="SIX_DIGIT_CODE", help="join a room"
    )
    parser.add_argument(
        "--password", help="room password (prompted securely when omitted)"
    )
    parser.add_argument(
        "--port",
        type=_client_port,
        help="relay port (default: 8080 for plaintext, 8443 otherwise)",
    )
    parser.add_argument("--ca", default="certs/ca.crt", help="trusted CA certificate")
    parser.add_argument("--keylog", help="optional TLS key log file for debugging")
    parser.add_argument(
        "--identity",
        help="E2E identity path (default: user_data/USERNAME/identity.key)",
    )
    parser.add_argument(
        "--trust-store",
        help="persistent trust path (default: user_data/USERNAME/trust.json)",
    )
    return parser


def _prepare_e2e_state(
    username: str, identity_arg: str | None, trust_arg: str | None
) -> tuple[Identity, TrustStore]:
    default_directory = PROJECT_ROOT / "user_data" / username
    identity_path = (
        Path(identity_arg).expanduser()
        if identity_arg is not None
        else default_directory / "identity.key"
    )
    trust_path = (
        Path(trust_arg).expanduser()
        if trust_arg is not None
        else default_directory / "trust.json"
    )

    identity_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    trust_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        identity = Identity.load(identity_path)
    except FileNotFoundError:
        identity = Identity.generate()
        identity.save(identity_path)
    else:
        # Loading does not change an existing file, so enforce the same private
        # permissions that Identity.save() uses for newly generated identities.
        identity_path.chmod(0o600)
    return identity, TrustStore(trust_path)


def _listen(client: ChatClient, events: EventQueue) -> None:
    """Run the synchronous receive API in a background thread.

    In addition to normal core events, this boundary turns E2E authentication
    and trust failures into visible safe error events instead of thread traces.
    """

    try:
        while client.connected:
            if client.receive_once() is None:
                break
    except (ChatClientError, E2EError, ProtocolError, OSError) as exc:
        if client.connected:
            events.put({"kind": "error", "message": str(exc)})
    finally:
        client.close()


def _print_event(console: Console, event: Event, mode: Mode) -> None:
    kind = event.get("kind")
    if kind == "message":
        payload = event.get("payload")
        if isinstance(payload, bytes):
            text = payload.decode("utf-8", errors="replace")
            console.write(f"{event.get('from', '?')}: {text}")
        return

    if kind == "roster":
        peers = event.get("peers", {})
        names = ", ".join(sorted(peers)) if isinstance(peers, dict) else ""
        console.write(f"[roster] Other room members: {names or 'none'}")
        if mode is Mode.E2E:
            console.write(
                "[roster] No key is trusted automatically. Use /peers and compare "
                "fingerprints out of band before /verify NAME."
            )
        return

    if kind == "error":
        code = event.get("code")
        suffix = f" ({code})" if code else ""
        console.write(f"[error]{suffix} {event.get('message', 'unknown error')}")
        return

    if kind == "disconnected":
        console.write("[disconnected] Connection to the relay closed.")


def _event_printer(console: Console, events: EventQueue, mode: Mode) -> None:
    while True:
        event = events.get()
        if event is None:
            return
        _print_event(console, event, mode)


def _show_help(console: Console) -> None:
    console.write(
        "Commands:\n"
        "  /peers          list peers, full E2E fingerprints, and trust status\n"
        "  /verify NAME    confirm that you independently compared NAME's full\n"
        "                  fingerprint out of band, then persistently trust it\n"
        "  /fingerprint    show your own full E2E fingerprint\n"
        "  /help           show this help\n"
        "  /quit, /exit    close the connection and exit\n"
        "Any other input is sent as a chat message. In E2E mode, sending targets\n"
        "all room peers and is blocked if a recipient is unverified."
    )


def _show_peers(console: Console, client: ChatClient) -> None:
    peers = dict(client.peers)
    if not peers:
        console.write("No other room members.")
        return

    lines = [f"Other room members ({len(peers)}):"]
    for name in sorted(peers):
        peer = peers[name]
        if client.mode is Mode.E2E:
            status = "VERIFIED" if client.is_peer_verified(name) else "UNVERIFIED"
            lines.append(f"  {name}  [{status}]\n    {peer.fingerprint}")
        else:
            lines.append(f"  {name}")
    console.write("\n".join(lines))


def _command_loop(client: ChatClient, console: Console) -> int:
    while True:
        raw_line = console.read_line()
        if raw_line is None:
            console.write("Input closed; leaving the room.")
            return 0 if client.connected else 1
        text = raw_line.rstrip("\r\n")
        if not text:
            if not client.connected:
                return 1
            continue

        if text.lstrip().startswith("/"):
            parts = text.strip().split()
            command = parts[0].lower()
            if command in ("/quit", "/exit"):
                return 0
            if command == "/help":
                _show_help(console)
                continue
            if command == "/peers":
                _show_peers(console, client)
                continue
            if command == "/fingerprint":
                if client.mode is Mode.E2E:
                    console.write(f"Your full E2E fingerprint:\n{client.own_fingerprint}")
                else:
                    console.write("Fingerprints are available only in E2E mode.")
                continue
            if command == "/verify":
                if client.mode is not Mode.E2E:
                    console.write("Peer verification is available only in E2E mode.")
                    continue
                if len(parts) != 2:
                    console.write("Usage: /verify NAME")
                    continue
                name = parts[1]
                try:
                    verified = client.confirm_peer(name)
                except (OSError, ValueError) as exc:
                    console.write(f"Could not persist verification for {name}: {exc}")
                    continue
                if verified:
                    console.write(
                        f"Verified {name} based on your independent out-of-band "
                        "comparison; the trust pin was saved."
                    )
                else:
                    console.write(
                        f"Could not verify {name}. Check the name and full fingerprint "
                        "with /peers; no new key was trusted."
                    )
                continue

            console.write("Unknown command. Use /help for available commands.")
            continue

        try:
            client.send_text(text)
        except TrustError as exc:
            console.write(
                f"[E2E] Message not sent: {exc}\n"
                "Use /peers to inspect every recipient and /verify NAME only after "
                "an independent out-of-band fingerprint comparison."
            )
        except (ValueError, E2EError) as exc:
            console.write(f"Message not sent: {exc}")
        except (ChatClientError, ProtocolError, OSError) as exc:
            console.write(f"Send failed: {exc}")
            return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not validate_username(args.username):
        parser.error("username must be 1-24 ASCII letters, digits, '_' or '-'")
    if args.create is not None and not validate_room_name(args.create):
        parser.error("room name must be 1-32 printable, non-control characters")

    password = args.password
    if password is None:
        try:
            password = getpass.getpass("Room password: ")
        except KeyboardInterrupt:
            print("\nInterrupted.", file=sys.stderr)
            return 130
        except EOFError:
            print("No room password was provided.", file=sys.stderr)
            return 2
    if not password or len(password) > 256:
        parser.error("password must contain 1-256 characters")

    mode = Mode(args.mode)
    console = Console()
    if mode is Mode.PLAINTEXT:
        console.write(
            "WARNING: Plaintext is an insecure baseline for testing/comparison only. "
            "Room credentials and chat content can be observed or modified on the "
            "network; do not use it for sensitive communication."
        )

    identity: Identity | None = None
    trust_store: TrustStore | None = None
    if mode is Mode.E2E:
        try:
            identity, trust_store = _prepare_e2e_state(
                args.username, args.identity, args.trust_store
            )
        except (OSError, ValueError) as exc:
            print(f"Could not initialize E2E state: {exc}", file=sys.stderr)
            return 1

    events: EventQueue = queue.Queue()
    client = ChatClient(
        host=args.host,
        username=args.username,
        password=password,
        mode=mode,
        port=args.port,
        ca_file=args.ca,
        keylog_file=args.keylog,
        identity=identity,
        trust_store=trust_store,
        on_event=events.put,
    )
    try:
        client.connect(
            room_name=args.create,
            room_code=args.join,
            start_listener=False,
        )
    except (ChatClientError, ProtocolError, OSError, ValueError) as exc:
        client.close()
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 1

    printer = threading.Thread(
        target=_event_printer,
        args=(console, events, mode),
        name="chatrex-cli-events",
        daemon=True,
    )
    listener = threading.Thread(
        target=_listen,
        args=(client, events),
        name=f"chatrex-cli-listener-{args.username}",
        daemon=True,
    )
    printer.start()

    console.write(
        f"Connected as {args.username} to room '{client.room_name}' "
        f"(code: {client.room_code}) in {mode.value} mode."
    )
    if mode is Mode.E2E:
        console.write(f"Your full E2E fingerprint:\n{client.own_fingerprint}")
        console.write(
            "Share your fingerprint with peers and compare each /peers fingerprint "
            "with that peer's own /fingerprint over an independent, authenticated "
            "out-of-band channel. Never verify a fingerprint supplied only through "
            "this chat. Run /verify NAME only after you have compared it yourself."
        )
        console.write(
            "E2E sending targets all room peers; any unverified recipient blocks "
            "the send. Use /peers to review verification status."
        )
    console.write("Type /help for commands and /quit to leave.")
    listener.start()

    try:
        return _command_loop(client, console)
    except KeyboardInterrupt:
        console.write("Interrupted; leaving the room.")
        return 130
    finally:
        console.stop()
        client.close()
        events.put(None)
        printer.join(timeout=2.0)
        listener.join(timeout=2.0)


if __name__ == "__main__":
    raise SystemExit(main())
