"""Command-line entry point for the ChatreX relay server."""

from __future__ import annotations

import argparse
import logging
import signal
from collections.abc import Sequence

from chatrex.relay import RelayServer


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def _log_level(value: str) -> str:
    level = value.upper()
    if level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        raise argparse.ArgumentTypeError(
            "log level must be CRITICAL, ERROR, WARNING, INFO, or DEBUG"
        )
    return level


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the ChatreX room relay.")
    parser.add_argument("--host", default="0.0.0.0", help="listener address")
    parser.add_argument(
        "--plain-port", type=_port, default=8080, help="plaintext TCP port"
    )
    parser.add_argument(
        "--secure-port", type=_port, default=8443, help="TLS 1.3 TCP port"
    )
    parser.add_argument(
        "--cert", default="certs/server.crt", help="server certificate chain"
    )
    parser.add_argument(
        "--key", default="certs/server.key", help="server private key file"
    )
    parser.add_argument(
        "--keylog", help="optional TLS key log file (intended for debugging only)"
    )
    parser.add_argument(
        "--log-level", type=_log_level, default="INFO", help="logging verbosity"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("chatrex.server")

    relay = RelayServer(
        host=args.host,
        plain_port=args.plain_port,
        secure_port=args.secure_port,
        cert_file=args.cert,
        key_file=args.key,
        keylog_file=args.keylog,
    )

    previous_handlers = {}

    def handle_signal(signum: int, _frame: object) -> None:
        logger.info("Received %s; shutting down.", signal.Signals(signum).name)
        relay.stop()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, handle_signal)

        # Start once up front so the startup messages contain the actual bound
        # ports (including OS-assigned ports).  serve_forever() is idempotent
        # with respect to an already-started RelayServer.
        relay.start()
        logger.info(
            "Plaintext listener on %s:%d",
            args.host,
            relay.plaintext_port,
        )
        logger.info(
            "TLS 1.3 listener on %s:%d (TLS and E2E modes)",
            args.host,
            relay.secure_port_actual,
        )
        logger.warning(
            "Plaintext is an insecure baseline only; do not use it for "
            "sensitive rooms or credentials."
        )
        relay.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted; shutting down.")
    except Exception as exc:
        logger.error("Relay failed: %s", exc)
        return 1
    finally:
        relay.stop()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
