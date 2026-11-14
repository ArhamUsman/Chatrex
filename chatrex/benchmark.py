"""Resumable, two-client Project 2 benchmark pipeline.

The relay only routes protocol frames.  A separate echo ChatClient creates each
room and returns every payload with its original message ID; the sender is a
second real ChatClient.  Lab processes are placed in the existing namespaces,
never in an implicitly created topology.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import random
import re
import resource
import select
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import nacl

from .client import ChatClient
from .pcap import convert_pcap_to_pcapng, wire_statistics
from .protocol import PROTOCOL_VERSION

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
CA_FILE = ROOT / "certs" / "ca.crt"
CERT_FILE = ROOT / "certs" / "server.crt"
KEY_FILE = ROOT / "certs" / "server.key"
DEFAULT_MODES = ("plaintext", "tls", "e2e")
DEFAULT_SIZES = (64, 1024, 16384)
DEFAULT_LAB_RTTS = (20, 100, 200)
PROJECT_MESSAGES = 1000
PROJECT_RUNS = 3
SCHEMA_VERSION = 1
SETUP_TIMEOUT_SECONDS = 120.0
CAPTURE_TIMEOUT_SECONDS = 15.0
LATENCY_FIELDS = (
    "run_id",
    "seq",
    "send_monotonic_ns",
    "recv_monotonic_ns",
    "latency_ms",
    "echo_ok",
)


class BenchmarkError(RuntimeError):
    """A benchmark configuration, coordination, or measurement failure."""


@dataclass(frozen=True)
class Settings:
    environment: str
    modes: tuple[str, ...]
    sizes: tuple[int, ...]
    rtts: tuple[int, ...]
    messages: int
    runs: int
    seed: int
    output: Path
    resume: bool
    capture: bool
    capture_reason: str | None

    def config_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "environment": self.environment,
            "modes": list(self.modes),
            "sizes": list(self.sizes),
            "rtts_ms": list(self.rtts),
            "messages": self.messages,
            "runs": self.runs,
            "seed": self.seed,
            "capture": self.capture,
            "capture_reason": self.capture_reason,
            "reduced_from_project_defaults": {
                "messages": self.messages < PROJECT_MESSAGES,
                "runs": self.runs < PROJECT_RUNS,
            },
        }

    @property
    def signature(self) -> str:
        encoded = json.dumps(
            self.config_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Condition:
    rtt_ms: int
    mode: str
    size_bytes: int

    @property
    def name(self) -> str:
        return f"rtt-{self.rtt_ms}ms_{self.mode}_{self.size_bytes}B"


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    log: Any


@dataclass
class CaptureProcess:
    process: subprocess.Popen[bytes]
    classic_path: Path
    log_path: Path
    stderr_prefix: bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_bytes(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _write_json(path: Path, document: Any) -> None:
    encoded = json.dumps(
        document, indent=2, sort_keys=True, allow_nan=False
    ).encode("utf-8") + b"\n"
    _atomic_bytes(path, encoded)


def _read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise BenchmarkError(f"expected a JSON object in {path}")
    return document


def _process_cpu_seconds() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def proc_cpu_time(pid: int) -> float:
    """Read exactly one PID's user+system CPU, without pgrep or process scans."""

    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    try:
        _prefix, _comm, tail = stat.rpartition(") ")
        fields = tail.split()
        ticks = int(fields[11]) + int(fields[12])
    except (IndexError, ValueError) as exc:
        raise BenchmarkError(f"could not parse /proc/{pid}/stat") from exc
    return ticks / os.sysconf("SC_CLK_TCK")


def generate_payloads(
    seed: int, size_bytes: int, message_count: int, run_id: str
) -> list[bytes]:
    """Precompute deterministic, unique payloads with a sequence prefix."""

    if size_bytes <= 0 or size_bytes > 65_536:
        raise ValueError("payload size must be between 1 and 65536 bytes")
    if message_count <= 0:
        raise ValueError("message count must be positive")
    prefix_bytes = min(
        size_bytes, max(1, ((message_count - 1).bit_length() + 7) // 8)
    )
    if message_count > 256**prefix_bytes:
        raise ValueError("payload size is too small for unique message payloads")
    run_seed = int.from_bytes(
        hashlib.sha256(f"{seed}:{run_id}".encode("utf-8")).digest()[:8], "big"
    )
    rng = random.Random(run_seed)
    payloads = []
    for sequence in range(message_count):
        prefix = sequence.to_bytes(prefix_bytes, "big")
        payloads.append(prefix + rng.randbytes(size_bytes - prefix_bytes))
    if len(set(payloads)) != message_count:
        raise BenchmarkError("internal error: generated payloads are not unique")
    return payloads


def _percentile(sorted_values: Sequence[float], fraction: float) -> float:
    if not sorted_values:
        raise ValueError("percentile requires at least one value")
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def latency_stats(latencies_ms: Sequence[float]) -> dict[str, Any]:
    if not latencies_ms:
        raise ValueError("cannot calculate statistics for zero messages")
    if any(not math.isfinite(value) or value < 0 for value in latencies_ms):
        raise ValueError("latencies must be finite and non-negative")
    ordered = sorted(latencies_ms)
    return {
        "count": len(ordered),
        "mean_ms": statistics.fmean(ordered),
        "sample_sd_ms": statistics.stdev(ordered) if len(ordered) > 1 else None,
        "median_ms": statistics.median(ordered),
        "p95_ms": _percentile(ordered, 0.95),
        "p99_ms": _percentile(ordered, 0.99),
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
    }


def _message_id(run_id: str, sequence: int) -> str:
    message_id = f"{run_id}-{sequence:06d}"
    if len(message_id) > 64:
        raise BenchmarkError("run ID is too long for protocol message IDs")
    return message_id


def _write_latencies(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    lines: list[list[Any]] = []
    for row in rows:
        lines.append([row[field] for field in LATENCY_FIELDS])
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent,
        prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as stream:
        temporary_name = stream.name
        writer = csv.writer(stream)
        writer.writerow(LATENCY_FIELDS)
        writer.writerows(lines)
    try:
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _tls_details(client: ChatClient) -> dict[str, Any]:
    if client.mode.value == "plaintext":
        return {"version": None, "session_reused": None}
    if not isinstance(client.socket, ssl.SSLSocket):
        raise BenchmarkError("secure ChatClient did not create a TLS socket")
    version = client.socket.version()
    reused = client.socket.session_reused
    if version != "TLSv1.3":
        raise BenchmarkError(f"expected TLS 1.3, negotiated {version}")
    if reused:
        raise BenchmarkError("TLS session reuse is forbidden in benchmark runs")
    return {"version": version, "session_reused": reused}


def _wait_for_file(path: Path, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        if path.exists():
            return _read_json(path)
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.05)


def _wait_for_flag(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.05)


def _receive_until_message(client: ChatClient, deadline: float) -> dict[str, Any]:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for an application message")
        if client.socket is None:
            raise BenchmarkError("client socket closed while waiting")
        client.socket.settimeout(remaining)
        event = client.receive_once()
        if event is None:
            raise BenchmarkError("relay closed while waiting for an application message")
        if event.get("kind") == "error":
            raise BenchmarkError(str(event.get("message", "relay error")))
        if event.get("kind") == "message":
            return event
        if event.get("kind") != "roster":
            raise BenchmarkError(f"unexpected client event: {event.get('kind')}")


def _wait_for_peer(client: ChatClient, username: str, deadline: float) -> None:
    while username not in client.peers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for roster peer {username}")
        if client.socket is None:
            raise BenchmarkError("client socket closed while waiting for roster")
        client.socket.settimeout(remaining)
        event = client.receive_once()
        if event is None:
            raise BenchmarkError("relay closed while waiting for roster")
        if event.get("kind") != "roster":
            raise BenchmarkError("application message arrived before peer verification")


def _new_client(args: argparse.Namespace, username: str, keylog_name: str) -> ChatClient:
    return ChatClient(
        args.host,
        username,
        "chatrex-benchmark-room-password",
        args.mode,
        port=args.port,
        ca_file=CA_FILE,
        keylog_file=args.keylog or args.run_dir / keylog_name,
        timeout=30.0,
    )


def _echo_worker(args: argparse.Namespace) -> None:
    worker_cpu_start = _process_cpu_seconds()
    payloads = generate_payloads(args.seed, args.size, args.messages, args.run_id)
    client = _new_client(args, "echo", "echo-tls.keys")
    setup_cpu_start = _process_cpu_seconds()
    setup_started_ns = time.perf_counter_ns()
    try:
        chat_timing = client.connect(room_name="benchmark", start_listener=False)
        tls = _tls_details(client)
        client.password = ""
        setup_cpu_end = _process_cpu_seconds()
        echo_ready = {
            "status": "ready",
            "run_id": args.run_id,
            "room_code": client.room_code,
            "mode": args.mode,
            "echo_fingerprint": client.own_fingerprint,
            "chat_client_setup": chat_timing.as_dict(),
            "setup_wall_ms": (time.perf_counter_ns() - setup_started_ns) / 1e6,
            "echo_setup_cpu_seconds": setup_cpu_end - setup_cpu_start,
            "tls": tls,
        }
        if args.mode == "e2e" and client.own_fingerprint is None:
            raise BenchmarkError("echo E2E identity was not created")
        _write_json(args.run_dir / "echo_ready.json", echo_ready)

        if args.mode == "e2e":
            sender_info = _wait_for_file(
                args.run_dir / "sender_info.json", SETUP_TIMEOUT_SECONDS
            )
            if (
                sender_info.get("run_id") != args.run_id
                or sender_info.get("room_code") != client.room_code
                or sender_info.get("mode") != args.mode
                or not isinstance(sender_info.get("sender_fingerprint"), str)
            ):
                raise BenchmarkError("sender_info.json failed E2E validation")
            _wait_for_peer(
                client, "sender", time.monotonic() + SETUP_TIMEOUT_SECONDS
            )
            if not client.verify_peer("sender", sender_info["sender_fingerprint"]):
                raise BenchmarkError("explicit sender fingerprint verification failed")
            _write_json(
                args.run_dir / "echo_verified.json",
                {
                    "status": "verified",
                    "run_id": args.run_id,
                    "room_code": client.room_code,
                    "sender_fingerprint": sender_info["sender_fingerprint"],
                    "verified": True,
                },
            )

        message_cpu_start = _process_cpu_seconds()
        deadline = time.monotonic() + args.wait_timeout
        echoed = 0
        for sequence in range(args.messages):
            event = _receive_until_message(client, deadline)
            expected_id = _message_id(args.run_id, sequence)
            if (
                event.get("from") != "sender"
                or event.get("to") != "echo"
                or event.get("id") != expected_id
                or event.get("payload") != payloads[sequence]
            ):
                raise BenchmarkError(
                    f"echo received an invalid request at sequence {sequence}"
                )
            returned_id = client.send_payload(
                event["payload"], "sender", message_id=expected_id
            )
            if returned_id != expected_id:
                raise BenchmarkError("echo changed the request message ID")
            echoed += 1
        message_cpu_end = _process_cpu_seconds()
        client.close()
        total_cpu_end = _process_cpu_seconds()
        _write_json(
            args.run_dir / "echo_done.json",
            {
                "status": "success",
                "run_id": args.run_id,
                "echoed_messages": echoed,
                "same_message_ids": True,
                "payloads_validated": True,
                "cpu": {
                    "setup_seconds": setup_cpu_end - setup_cpu_start,
                    "message_seconds": message_cpu_end - message_cpu_start,
                    "total_seconds": total_cpu_end - worker_cpu_start,
                    "message_ms_per_message": (
                        (message_cpu_end - message_cpu_start) * 1000 / args.messages
                    ),
                },
            },
        )
    finally:
        client.close()


def _sender_worker(args: argparse.Namespace) -> None:
    worker_cpu_start = _process_cpu_seconds()
    payloads = generate_payloads(args.seed, args.size, args.messages, args.run_id)
    echo_ready = _wait_for_file(
        args.run_dir / "echo_ready.json", SETUP_TIMEOUT_SECONDS
    )
    if echo_ready.get("run_id") != args.run_id or echo_ready.get("mode") != args.mode:
        raise BenchmarkError("echo_ready.json does not match this run")
    if not isinstance(echo_ready.get("room_code"), str):
        raise BenchmarkError("echo readiness did not provide a room code")

    client = _new_client(args, "sender", "sender-tls.keys")
    setup_cpu_start = _process_cpu_seconds()
    setup_started_ns = time.perf_counter_ns()
    rows: list[dict[str, Any]] = []
    try:
        chat_timing = client.connect(
            room_code=echo_ready["room_code"], start_listener=False
        )
        tls = _tls_details(client)
        client.password = ""
        sender_info = {
            "run_id": args.run_id,
            "room_code": client.room_code,
            "mode": args.mode,
            "sender_fingerprint": client.own_fingerprint,
        }
        _write_json(args.run_dir / "sender_info.json", sender_info)

        verification_started_ns: int | None = None
        if args.mode == "e2e":
            expected = echo_ready.get("echo_fingerprint")
            if not isinstance(expected, str) or client.own_fingerprint is None:
                raise BenchmarkError("E2E fingerprints are missing")
            verification_started_ns = time.perf_counter_ns()
            if "echo" not in client.peers:
                raise BenchmarkError("sender roster does not contain the echo client")
            if not client.verify_peer("echo", expected):
                raise BenchmarkError("explicit echo fingerprint verification failed")
            verified = _wait_for_file(
                args.run_dir / "echo_verified.json", SETUP_TIMEOUT_SECONDS
            )
            if (
                verified.get("verified") is not True
                or verified.get("run_id") != args.run_id
                or verified.get("room_code") != client.room_code
                or verified.get("sender_fingerprint") != client.own_fingerprint
            ):
                raise BenchmarkError("echo did not explicitly verify this sender")

        setup_finished_ns = time.perf_counter_ns()
        setup_cpu_end = _process_cpu_seconds()
        total_setup_ms = (setup_finished_ns - setup_started_ns) / 1e6
        peer_verification_ms = (
            (setup_finished_ns - verification_started_ns) / 1e6
            if verification_started_ns is not None
            else None
        )
        setup = chat_timing.as_dict()
        setup["chat_client_total_setup_ms"] = chat_timing.total_setup_ms
        setup["peer_verification_ms"] = peer_verification_ms
        setup["total_setup_ms"] = total_setup_ms
        setup["setup_rtt_ratio"] = total_setup_ms / args.rtt_ms if args.rtt_ms else None
        _write_json(
            args.run_dir / "sender_setup_done.json",
            {
                "status": "ready",
                "run_id": args.run_id,
                "setup": setup,
                "tls": tls,
                "client_setup_cpu_seconds": setup_cpu_end - setup_cpu_start,
                "e2e_echo_verified_by_sender": args.mode == "e2e",
                "e2e_sender_verified_by_echo": args.mode == "e2e",
            },
        )

        _wait_for_flag(args.run_dir / "start_messages.flag", SETUP_TIMEOUT_SECONDS)
        message_cpu_start = _process_cpu_seconds()
        message_wall_start_ns = time.perf_counter_ns()
        try:
            for sequence, payload in enumerate(payloads):
                message_id = _message_id(args.run_id, sequence)
                send_ns = time.perf_counter_ns()
                client.send_payload(payload, "echo", message_id=message_id)
                event = client.wait_for_message(
                    message_id, timeout=max(30.0, args.rtt_ms / 100.0)
                )
                if (
                    event.get("from") != "echo"
                    or event.get("to") != "sender"
                    or event.get("id") != message_id
                    or event.get("payload") != payload
                ):
                    raise BenchmarkError(
                        f"sender received an invalid echo at sequence {sequence}"
                    )
                recv_ns = time.perf_counter_ns()
                rows.append(
                    {
                        "run_id": args.run_id,
                        "seq": sequence,
                        "send_monotonic_ns": send_ns,
                        "recv_monotonic_ns": recv_ns,
                        "latency_ms": (recv_ns - send_ns) / 1e6,
                        "echo_ok": True,
                    }
                )
        except BaseException:
            _write_latencies(args.run_dir / "latencies.csv", rows)
            raise
        message_wall_end_ns = time.perf_counter_ns()
        message_cpu_end = _process_cpu_seconds()
        if len(rows) != args.messages:
            raise BenchmarkError("sender did not complete every measured message")
        _write_latencies(args.run_dir / "latencies.csv", rows)
        latencies = [float(row["latency_ms"]) for row in rows]
        client.close()
        total_cpu_end = _process_cpu_seconds()
        message_cpu = message_cpu_end - message_cpu_start
        _write_json(
            args.run_dir / "sender_done.json",
            {
                "status": "success",
                "run_id": args.run_id,
                "messages": len(rows),
                "all_echoes_validated": all(row["echo_ok"] for row in rows),
                "latency": latency_stats(latencies),
                "message_wall_seconds": (message_wall_end_ns - message_wall_start_ns) / 1e9,
                "cpu": {
                    "setup_seconds": setup_cpu_end - setup_cpu_start,
                    "message_seconds": message_cpu,
                    "total_seconds": total_cpu_end - worker_cpu_start,
                    "message_ms_per_message": message_cpu * 1000 / args.messages,
                },
            },
        )
    finally:
        client.close()


def _wait_port_worker(host: str, port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise TimeoutError(f"relay port {host}:{port} was not ready: {last_error}")


def _internal_main(args: argparse.Namespace) -> int:
    try:
        if args.internal_role == "wait-port":
            _wait_port_worker(args.host, args.port, args.wait_timeout)
        elif args.internal_role == "echo":
            _echo_worker(args)
        elif args.internal_role == "sender":
            _sender_worker(args)
        else:
            raise BenchmarkError(f"unsupported internal role {args.internal_role}")
        return 0
    except BaseException as exc:
        if args.run_dir is not None and args.internal_role in {"echo", "sender"}:
            _write_json(
                args.run_dir / f"{args.internal_role}_error.json",
                {
                    "status": "failed",
                    "run_id": args.run_id,
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                },
            )
        if isinstance(exc, KeyboardInterrupt):
            raise
        print(f"{args.internal_role} worker failed: {exc}", file=sys.stderr)
        return 1


def _comma_values(raw: str, allowed: Iterable[Any] | None = None) -> list[str]:
    values = [part.strip() for part in raw.split(",")]
    if not raw or any(not value for value in values):
        raise BenchmarkError("comma lists must contain non-empty values")
    if len(set(values)) != len(values):
        raise BenchmarkError(f"duplicate comma-list value in {raw!r}")
    if allowed is not None:
        allowed_values = {str(value) for value in allowed}
        unknown = [value for value in values if value not in allowed_values]
        if unknown:
            raise BenchmarkError(f"unsupported value(s): {', '.join(unknown)}")
    return values


def _integer_list(raw: str, *, maximum: int | None = None) -> tuple[int, ...]:
    result = []
    for value in _comma_values(raw):
        try:
            number = int(value, 10)
        except ValueError as exc:
            raise BenchmarkError(f"expected an integer, got {value!r}") from exc
        if number < 0 or (maximum is not None and not 0 < number <= maximum):
            requirement = f"1-{maximum}" if maximum is not None else "non-negative"
            raise BenchmarkError(f"{value!r} is outside the {requirement} range")
        result.append(number)
    return tuple(result)


def _default_output(environment: str) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return ROOT / "results" / f"{timestamp}-{environment}"


def _resolve_settings(args: argparse.Namespace) -> Settings:
    modes = tuple(_comma_values(args.modes, DEFAULT_MODES))
    sizes = _integer_list(args.sizes, maximum=65_536)
    rtts = _integer_list(args.rtts) if args.rtts is not None else (
        (0,) if args.environment == "local" else DEFAULT_LAB_RTTS
    )
    if args.environment == "local" and any(rtts):
        raise BenchmarkError("local environment permits only --rtts 0; localhost is never delayed")
    if args.messages <= 0:
        raise BenchmarkError("--messages must be positive")
    if args.runs <= 0:
        raise BenchmarkError("--runs/--repetitions must be positive")
    if args.output is not None and args.resume is not None:
        raise BenchmarkError("use either --output for a new suite or --resume OUTPUT, not both")
    if args.environment == "lab" and os.geteuid() != 0:
        raise BenchmarkError(
            "lab environment requires EUID 0; rerun as root with "
            ".venv/bin/python benchmark.py --environment lab (no sudo is invoked by this tool)"
        )
    if not PYTHON.is_file():
        raise BenchmarkError(f"required project interpreter is missing: {PYTHON}")

    tcpdump_available = shutil.which("tcpdump") is not None
    if args.environment == "local" and args.capture is True:
        raise BenchmarkError(
            "--capture is lab-only: loopback duplicates flows, so local wire ratios are null"
        )
    if args.capture is True and not tcpdump_available:
        raise BenchmarkError("--capture requested but tcpdump is not available")
    capture = args.capture is True or (
        args.capture is None and args.environment == "lab" and tcpdump_available
    )
    if args.environment == "local":
        capture_reason = "loopback capture disabled; duplicate flows make wire ratios invalid"
    elif args.capture is False:
        capture_reason = "capture disabled by --no-capture"
    elif not tcpdump_available:
        capture_reason = "tcpdump unavailable; capture disabled"
    else:
        capture_reason = None
    output = args.resume or args.output or _default_output(args.environment)
    return Settings(
        environment=args.environment,
        modes=modes,
        sizes=sizes,
        rtts=rtts,
        messages=args.messages,
        runs=args.runs,
        seed=args.seed,
        output=output.resolve(),
        resume=args.resume is not None,
        capture=capture,
        capture_reason=capture_reason,
    )


def _namespace_prefix(settings: Settings, namespace: str) -> list[str]:
    return ["ip", "netns", "exec", namespace] if settings.environment == "lab" else []


def _worker_command(
    settings: Settings, namespace: str, role: str, run_dir: Path,
    run_id: str, condition: Condition
) -> list[str]:
    host = "10.0.3.10" if settings.environment == "lab" else "127.0.0.1"
    port = 8080 if condition.mode == "plaintext" else 8443
    overall_timeout = max(
        120.0, settings.messages * (0.5 + 4 * condition.rtt_ms / 1000.0) + 120.0
    )
    return _namespace_prefix(settings, namespace) + [
        str(PYTHON), str(ROOT / "benchmark.py"),
        "--internal-role", role,
        "--run-dir", str(run_dir),
        "--run-id", run_id,
        "--host", host,
        "--port", str(port),
        "--mode", condition.mode,
        "--keylog", str(run_dir / f"{role}-tls.keys"),
        "--size", str(condition.size_bytes),
        "--messages", str(settings.messages),
        "--seed", str(settings.seed),
        "--rtt-ms", str(condition.rtt_ms),
        "--wait-timeout", str(overall_timeout),
    ]


def _start_logged(
    name: str, command: Sequence[str], log_path: Path
) -> ManagedProcess:
    log = log_path.open("wb")
    try:
        process = subprocess.Popen(
            list(command), cwd=ROOT, stdout=log, stderr=subprocess.STDOUT
        )
    except BaseException:
        log.close()
        raise
    return ManagedProcess(name=name, process=process, log=log)


def _stop_managed(managed: ManagedProcess | None) -> None:
    if managed is None:
        return
    process = managed.process
    try:
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                # The process exited between poll() and terminate(); reap it now.
                process.wait(timeout=0)
            try:
                process.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10.0)
                raise BenchmarkError(f"{managed.name} PID {process.pid} required SIGKILL")
        else:
            process.wait(timeout=0)
    finally:
        managed.log.close()


def _wait_relay_ready(settings: Settings, relay: ManagedProcess) -> None:
    host = "10.0.3.10" if settings.environment == "lab" else "127.0.0.1"
    if settings.environment == "local":
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if relay.process.poll() is not None:
                raise BenchmarkError(
                    f"relay PID {relay.process.pid} exited with {relay.process.returncode}; see relay.log"
                )
            try:
                _wait_port_worker(host, 8080, 0.2)
                return
            except TimeoutError:
                continue
        raise TimeoutError("relay plaintext port did not become ready")
    command = _namespace_prefix(settings, "server") + [
        str(PYTHON), str(ROOT / "benchmark.py"),
        "--internal-role", "wait-port",
        "--host", host, "--port", "8080", "--wait-timeout", "30",
    ]
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=35.0
    )
    if completed.returncode != 0:
        raise BenchmarkError(
            "relay readiness probe failed: " + (completed.stderr or completed.stdout).strip()
        )
    if relay.process.poll() is not None:
        raise BenchmarkError(f"relay PID {relay.process.pid} exited during readiness")


def _await_run_json(
    path: Path, timeout: float, process: ManagedProcess,
    error_paths: Sequence[Path] = ()
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        if path.exists():
            return _read_json(path)
        for error_path in error_paths:
            if error_path.exists():
                detail = _read_json(error_path)
                raise BenchmarkError(f"{error_path.name}: {detail.get('error')}")
        returncode = process.process.poll()
        if returncode is not None:
            raise BenchmarkError(
                f"{process.name} PID {process.process.pid} exited with {returncode} "
                f"before {path.name}; see {process.name}.log"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {path}")
        time.sleep(0.05)


def _start_capture(run_dir: Path, mode: str) -> CaptureProcess:
    classic_path = run_dir / "capture.pcap"
    log_path = run_dir / "capture.log"
    port = 8080 if mode == "plaintext" else 8443
    capture_filter = f"host 10.0.3.10 and tcp port {port}"
    command = [
        "ip", "netns", "exec", "r1", "tcpdump", "-i", "veth-r1-b",
        "-s", "0", "-U", "-w", str(classic_path), capture_filter,
    ]
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, bufsize=0
    )
    capture = CaptureProcess(process, classic_path, log_path, b"")
    if process.stderr is None:
        process.kill()
        process.wait()
        raise BenchmarkError("could not open tcpdump stderr")
    descriptor = process.stderr.fileno()
    os.set_blocking(descriptor, False)
    deadline = time.monotonic() + CAPTURE_TIMEOUT_SECONDS
    buffer = bytearray()
    try:
        while b"listening on" not in buffer:
            if process.poll() is not None:
                raise BenchmarkError(
                    f"tcpdump exited with {process.returncode} before listening: {buffer.decode(errors='replace')}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("tcpdump did not report listening readiness")
            readable, _writable, _exceptional = select.select(
                [descriptor], [], [], min(0.2, remaining)
            )
            if readable:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    raise BenchmarkError("tcpdump stderr closed before listening readiness")
                buffer.extend(chunk)
        capture.stderr_prefix = bytes(buffer)
        log_path.write_bytes(capture.stderr_prefix)
        return capture
    except BaseException:
        try:
            _stop_capture(capture)
        except Exception as cleanup_exc:
            raise BenchmarkError(f"tcpdump startup and cleanup failed: {cleanup_exc}") from None
        raise


def _stop_capture(capture: CaptureProcess | None) -> None:
    if capture is None:
        return
    process = capture.process
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
        except ProcessLookupError:
            # tcpdump exited between the poll and signal; communicate() reaps it.
            process.wait(timeout=0)
    stderr = b""
    try:
        _stdout, stderr = process.communicate(timeout=10.0)
    except subprocess.TimeoutExpired:
        process.kill()
        _stdout, stderr = process.communicate(timeout=10.0)
        raise BenchmarkError("tcpdump required SIGKILL while flushing its capture")
    finally:
        with capture.log_path.open("ab") as log:
            if stderr:
                log.write(stderr)
    if process.returncode != 0:
        raise BenchmarkError(f"tcpdump exited with status {process.returncode}; see capture.log")


def _run_command(command: Sequence[str], *, timeout: float = 60.0) -> str:
    completed = subprocess.run(
        list(command), cwd=ROOT, capture_output=True, text=True, timeout=timeout
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise BenchmarkError(f"command failed ({' '.join(command)}): {detail}")
    return completed.stdout


def _parse_ping_average(output: str) -> float:
    match = re.search(
        r"^(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", output, re.MULTILINE
    )
    if match is None:
        raise BenchmarkError("could not parse ping average RTT")
    return float(match.group(1))


def _prepare_rtt_block(settings: Settings, rtt_ms: int) -> float:
    block_dir = settings.output / "topology" / f"rtt-{rtt_ms}ms"
    block_dir.mkdir(parents=True, exist_ok=True)
    delay = f"{rtt_ms / 2:g}ms"
    qdisc_outputs = {}
    for namespace, interface in (("r1", "veth-r1-b"), ("r2", "veth-r2-b")):
        _run_command([
            "ip", "netns", "exec", namespace, "tc", "qdisc", "replace",
            "dev", interface, "root", "netem", "delay", delay,
        ])
        qdisc = _run_command([
            "ip", "netns", "exec", namespace, "tc", "-s", "qdisc", "show", "dev", interface,
        ])
        if "netem" not in qdisc:
            raise BenchmarkError(f"netem qdisc missing after configuration on {namespace}/{interface}")
        qdisc_path = block_dir / f"configured_qdisc_{namespace}.txt"
        qdisc_path.write_text(qdisc, encoding="utf-8")
        qdisc_outputs[namespace] = str(qdisc_path.relative_to(settings.output))

    ping_output = _run_command([
        "ip", "netns", "exec", "client", "ping", "-n", "-c", "5", "-W", "2", "10.0.3.10",
    ], timeout=30.0)
    (block_dir / "ping_configured.txt").write_text(ping_output, encoding="utf-8")
    measured_rtt = _parse_ping_average(ping_output)

    environment = os.environ.copy()
    environment["EXPECTED_RTT_MS"] = str(rtt_ms)
    completed = subprocess.run(
        [str(ROOT / "validate_topology.sh"), str(block_dir)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=120.0
    )
    (block_dir / "validate.log").write_text(
        completed.stdout + completed.stderr, encoding="utf-8"
    )
    if completed.returncode != 0:
        raise BenchmarkError(
            f"topology validation failed for configured RTT {rtt_ms} ms; "
            f"see {(block_dir / 'validate.log').relative_to(settings.output)}"
        )
    _write_json(
        block_dir / "rtt.json",
        {
            "configured_added_rtt_ms": rtt_ms,
            "per_router_egress_delay_ms": rtt_ms / 2,
            "measured_ping_average_rtt_ms": measured_rtt,
            "qdiscs": qdisc_outputs,
            "ping_output": "ping_configured.txt",
            "validation": "PASS",
        },
    )
    return measured_rtt


def _software_versions() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "openssl": ssl.OPENSSL_VERSION,
        "pynacl": nacl.__version__,
        "platform": platform.platform(),
        "chatrex_protocol": str(PROTOCOL_VERSION),
    }


def _run_id(condition: Condition, run_number: int) -> str:
    return f"{condition.name}-run-{run_number}"


def _artifact_paths(settings: Settings, run_dir: Path) -> dict[str, str]:
    names = [
        "run.json", "latencies.csv", "relay.log", "echo.log", "sender.log",
        "relay-tls.keys", "echo-tls.keys", "sender-tls.keys",
        "echo_ready.json", "sender_info.json", "sender_setup_done.json",
        "sender_done.json", "echo_done.json", "echo_verified.json",
    ]
    if settings.capture:
        names.extend(["capture.pcapng", "capture.log"])
    return {
        name: str((run_dir / name).relative_to(settings.output))
        for name in names
    }


def _base_run_document(
    settings: Settings, condition: Condition, run_number: int,
    run_dir: Path, measured_rtt: float | None
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "config_signature": settings.signature,
        "config": settings.config_dict(),
        "run_id": _run_id(condition, run_number),
        "status": "running",
        "error": None,
        "condition": {
            "name": condition.name,
            "rtt_ms": condition.rtt_ms,
            "mode": condition.mode,
            "size_bytes": condition.size_bytes,
        },
        "run_number": run_number,
        "messages": settings.messages,
        "requested_runs": settings.runs,
        "seed": settings.seed,
        "reduced_from_project_defaults": {
            "messages": settings.messages < PROJECT_MESSAGES,
            "runs": settings.runs < PROJECT_RUNS,
        },
        "configured_added_rtt_ms": condition.rtt_ms,
        "measured_ping_average_rtt_ms": measured_rtt,
        "started_at_utc": _utc_now(),
        "finished_at_utc": None,
        "setup": None,
        "latency": None,
        "cpu": None,
        "wire_statistics": None,
        "capture": {
            "enabled": settings.capture,
            "reason": settings.capture_reason,
            "interface": "r1/veth-r1-b" if settings.capture else None,
            "filter": (
                f"host 10.0.3.10 and tcp port "
                f"{8080 if condition.mode == 'plaintext' else 8443}"
            ) if settings.capture else None,
            "wire_denominator_bytes": 2 * settings.messages * condition.size_bytes,
        },
        "versions": _software_versions(),
        "artifacts": _artifact_paths(settings, run_dir),
    }


def _validate_worker_results(
    settings: Settings, run_id: str, sender_setup: dict[str, Any],
    sender_done: dict[str, Any], echo_done: dict[str, Any]
) -> None:
    if sender_setup.get("status") != "ready" or sender_setup.get("run_id") != run_id:
        raise BenchmarkError("sender setup artifact is incomplete or mismatched")
    if (
        sender_done.get("status") != "success"
        or sender_done.get("run_id") != run_id
        or sender_done.get("messages") != settings.messages
        or sender_done.get("all_echoes_validated") is not True
    ):
        raise BenchmarkError("sender result is incomplete or mismatched")
    if (
        echo_done.get("status") != "success"
        or echo_done.get("run_id") != run_id
        or echo_done.get("echoed_messages") != settings.messages
        or echo_done.get("same_message_ids") is not True
        or echo_done.get("payloads_validated") is not True
    ):
        raise BenchmarkError("echo result is incomplete or mismatched")


def _execute_run(
    settings: Settings, condition: Condition, run_number: int,
    measured_rtt: float | None
) -> dict[str, Any]:
    run_id = _run_id(condition, run_number)
    run_dir = settings.output / condition.name / f"run-{run_number}"
    run_dir.mkdir(parents=True, exist_ok=False)
    result = _base_run_document(settings, condition, run_number, run_dir, measured_rtt)
    _write_json(run_dir / "run.json", result)
    relay: ManagedProcess | None = None
    echo: ManagedProcess | None = None
    sender: ManagedProcess | None = None
    capture: CaptureProcess | None = None
    cleanup_errors: list[str] = []
    try:
        if settings.capture:
            capture = _start_capture(run_dir, condition.mode)
        relay_keylog = run_dir / "relay-tls.keys"
        relay_command = _namespace_prefix(settings, "server") + [
            str(PYTHON), str(ROOT / "server.py"),
            "--host", "0.0.0.0",
            "--plain-port", "8080", "--secure-port", "8443",
            "--cert", str(CERT_FILE), "--key", str(KEY_FILE),
            "--keylog", str(relay_keylog), "--log-level", "INFO",
        ]
        relay = _start_logged("relay", relay_command, run_dir / "relay.log")
        result["relay_pid"] = relay.process.pid
        relay_total_cpu_start = proc_cpu_time(relay.process.pid)
        _wait_relay_ready(settings, relay)

        echo_namespace = "server" if settings.environment == "lab" else "local"
        echo = _start_logged(
            "echo",
            _worker_command(settings, echo_namespace, "echo", run_dir, run_id, condition),
            run_dir / "echo.log",
        )
        echo_ready = _await_run_json(
            run_dir / "echo_ready.json", SETUP_TIMEOUT_SECONDS, echo,
            [run_dir / "echo_error.json"],
        )
        if echo_ready.get("run_id") != run_id or echo_ready.get("mode") != condition.mode:
            raise BenchmarkError("echo readiness does not match this condition")
        relay_setup_cpu_start = proc_cpu_time(relay.process.pid)

        sender_namespace = "client" if settings.environment == "lab" else "local"
        sender = _start_logged(
            "sender",
            _worker_command(settings, sender_namespace, "sender", run_dir, run_id, condition),
            run_dir / "sender.log",
        )
        sender_setup = _await_run_json(
            run_dir / "sender_setup_done.json", SETUP_TIMEOUT_SECONDS, sender,
            [run_dir / "sender_error.json", run_dir / "echo_error.json"],
        )
        relay_after_setup = proc_cpu_time(relay.process.pid)
        _atomic_bytes(run_dir / "start_messages.flag", b"start\n")

        sender_done = _await_run_json(
            run_dir / "sender_done.json",
            max(120.0, settings.messages * (0.5 + 4 * condition.rtt_ms / 1000.0) + 120.0),
            sender, [run_dir / "sender_error.json", run_dir / "echo_error.json"],
        )
        echo_done = _await_run_json(
            run_dir / "echo_done.json", 60.0, echo, [run_dir / "echo_error.json"],
        )
        relay_after_messages = proc_cpu_time(relay.process.pid)
        _validate_worker_results(settings, run_id, sender_setup, sender_done, echo_done)
        latencies = _read_latency_rows(run_dir / "latencies.csv", settings.messages, run_id)
        computed_latency = latency_stats([row[4] for row in latencies])
        if computed_latency != sender_done["latency"]:
            raise BenchmarkError("sender latency statistics do not match latencies.csv")

        relay_setup_cpu = relay_after_setup - relay_setup_cpu_start
        relay_message_cpu = relay_after_messages - relay_after_setup
        relay_total_cpu = relay_after_messages - relay_total_cpu_start
        if min(relay_setup_cpu, relay_message_cpu, relay_total_cpu) < 0:
            raise BenchmarkError("relay CPU counters moved backwards")
        result["setup"] = sender_setup["setup"]
        result["tls"] = sender_setup["tls"]
        result["e2e_explicit_peer_verification"] = {
            "sender_verified_echo": sender_setup["e2e_echo_verified_by_sender"],
            "echo_verified_sender": sender_setup["e2e_sender_verified_by_echo"],
        }
        result["latency"] = computed_latency
        result["cpu"] = {
            "client": sender_done["cpu"],
            "relay": {
                "pid": relay.process.pid,
                "initialization_seconds": relay_setup_cpu_start - relay_total_cpu_start,
                "setup_seconds": relay_setup_cpu,
                "message_seconds": relay_message_cpu,
                "total_seconds": relay_total_cpu,
                "message_ms_per_message": relay_message_cpu * 1000 / settings.messages,
                "total_ms_per_message": relay_total_cpu * 1000 / settings.messages,
                "source": f"/proc/{relay.process.pid}/stat utime+stime",
            },
            "echo": echo_done["cpu"],
        }
        result["message_wall_seconds"] = sender_done["message_wall_seconds"]
        result["status"] = "success"
    except BaseException as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        (run_dir / "orchestrator-error.log").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
        if isinstance(exc, KeyboardInterrupt):
            raise
    finally:
        for managed in (sender, echo, relay):
            try:
                _stop_managed(managed)
            except Exception as exc:
                cleanup_errors.append(f"{managed.name if managed else 'process'} cleanup: {exc}")
        try:
            _stop_capture(capture)
        except Exception as exc:
            cleanup_errors.append(f"capture cleanup: {exc}")

        if capture is not None and capture.classic_path.exists():
            try:
                wire = None
                if result["status"] == "success":
                    wire = wire_statistics(
                        capture.classic_path, "10.0.1.10", "10.0.3.10",
                        condition.size_bytes, settings.messages,
                    )
                convert_pcap_to_pcapng(capture.classic_path, run_dir / "capture.pcapng")
                capture.classic_path.unlink()
                result["wire_statistics"] = wire
            except Exception as exc:
                cleanup_errors.append(f"capture conversion/statistics: {exc}")
        if cleanup_errors:
            result["status"] = "failed"
            cleanup_text = "; ".join(cleanup_errors)
            result["error"] = (
                f"{result['error']}; {cleanup_text}" if result["error"] else cleanup_text
            )
        result["finished_at_utc"] = _utc_now()
        _write_json(run_dir / "run.json", result)
    return result


def _read_latency_rows(
    path: Path, expected_count: int, run_id: str
) -> list[tuple[str, int, int, int, float, bool]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != LATENCY_FIELDS:
            raise BenchmarkError(f"invalid latency CSV header in {path}")
        rows = []
        for sequence, raw in enumerate(reader):
            try:
                parsed = (
                    raw["run_id"], int(raw["seq"]),
                    int(raw["send_monotonic_ns"]), int(raw["recv_monotonic_ns"]),
                    float(raw["latency_ms"]), raw["echo_ok"].lower() == "true",
                )
            except (TypeError, ValueError) as exc:
                raise BenchmarkError(f"invalid latency row {sequence} in {path}") from exc
            if (
                parsed[0] != run_id or parsed[1] != sequence
                or parsed[3] < parsed[2] or not parsed[5]
                or not math.isfinite(parsed[4]) or parsed[4] < 0
                or not math.isclose(parsed[4], (parsed[3] - parsed[2]) / 1e6, rel_tol=1e-9, abs_tol=1e-9)
            ):
                raise BenchmarkError(f"latency validation failed at row {sequence} in {path}")
            rows.append(parsed)
    if len(rows) != expected_count:
        raise BenchmarkError(f"{path} contains {len(rows)} rows, expected {expected_count}")
    return rows


def _valid_completed_run(
    settings: Settings, condition: Condition, run_number: int
) -> dict[str, Any] | None:
    run_dir = settings.output / condition.name / f"run-{run_number}"
    try:
        document = _read_json(run_dir / "run.json")
        run_id = _run_id(condition, run_number)
        if (
            document.get("status") != "success"
            or document.get("config_signature") != settings.signature
            or document.get("config") != settings.config_dict()
            or document.get("run_id") != run_id
            or document.get("messages") != settings.messages
            or document.get("requested_runs") != settings.runs
            or document.get("condition", {}).get("name") != condition.name
            or document.get("latency", {}).get("count") != settings.messages
            or not isinstance(document.get("setup"), dict)
            or not isinstance(document.get("cpu"), dict)
        ):
            return None
        rows = _read_latency_rows(run_dir / "latencies.csv", settings.messages, run_id)
        if latency_stats([row[4] for row in rows]) != document["latency"]:
            return None
        setup_ms = document["setup"].get("total_setup_ms")
        expected_ratio = setup_ms / condition.rtt_ms if condition.rtt_ms else None
        if (
            not isinstance(setup_ms, (int, float))
            or not math.isfinite(setup_ms)
            or setup_ms < 0
            or document["setup"].get("setup_rtt_ratio") != expected_ratio
        ):
            return None
        sender_done = _read_json(run_dir / "sender_done.json")
        echo_done = _read_json(run_dir / "echo_done.json")
        sender_setup = _read_json(run_dir / "sender_setup_done.json")
        _validate_worker_results(settings, run_id, sender_setup, sender_done, echo_done)
        if condition.mode == "e2e":
            verification = document.get("e2e_explicit_peer_verification", {})
            echo_verified = _read_json(run_dir / "echo_verified.json")
            if (
                verification.get("sender_verified_echo") is not True
                or verification.get("echo_verified_sender") is not True
                or echo_verified.get("verified") is not True
                or echo_verified.get("run_id") != run_id
            ):
                return None
        if condition.mode != "plaintext":
            tls = document.get("tls", {})
            if tls.get("version") != "TLSv1.3" or tls.get("session_reused") is not False:
                return None
        for role in ("client", "relay"): 
            cpu = document["cpu"].get(role)
            if not isinstance(cpu, dict):
                return None
            for phase in ("setup_seconds", "message_seconds", "total_seconds"):
                value = cpu.get(phase)
                if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                    return None
        if settings.capture:
            if not (run_dir / "capture.pcapng").is_file():
                return None
            wire = document.get("wire_statistics")
            if not isinstance(wire, dict):
                return None
            if wire.get("payload_bytes_c2s") != settings.messages * condition.size_bytes:
                return None
            if wire.get("payload_bytes_s2c") != settings.messages * condition.size_bytes:
                return None
        elif document.get("wire_statistics") is not None:
            return None
        if condition.mode != "plaintext":
            for name in ("relay-tls.keys", "echo-tls.keys", "sender-tls.keys"):
                keylog = run_dir / name
                if not keylog.is_file() or keylog.stat().st_size == 0:
                    return None
        return document
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, BenchmarkError):
        return None


def _archive_invalid_run(settings: Settings, condition: Condition, run_number: int) -> None:
    run_dir = settings.output / condition.name / f"run-{run_number}"
    if not run_dir.exists():
        return
    suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    archive = run_dir.with_name(f"run-{run_number}.invalid-{suffix}")
    run_dir.rename(archive)


def _nested(document: dict[str, Any], path: Sequence[str]) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


SUMMARY_METRICS = {
    "setup_ms": ("setup", "total_setup_ms"),
    "message_latency_ms": ("latency", "mean_ms"),
    "client_setup_cpu_seconds": ("cpu", "client", "setup_seconds"),
    "client_message_cpu_seconds": ("cpu", "client", "message_seconds"),
    "client_total_cpu_seconds": ("cpu", "client", "total_seconds"),
    "client_cpu_ms_per_message": ("cpu", "client", "message_ms_per_message"),
    "relay_setup_cpu_seconds": ("cpu", "relay", "setup_seconds"),
    "relay_message_cpu_seconds": ("cpu", "relay", "message_seconds"),
    "relay_total_cpu_seconds": ("cpu", "relay", "total_seconds"),
    "relay_cpu_ms_per_message": ("cpu", "relay", "message_ms_per_message"),
    "wire_ratio": ("wire_statistics", "session_wire_ratio"),
}


def _summary_row(
    condition: Condition, requested_runs: int, documents: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    successful = [document for document in documents if document.get("status") == "success"]
    failed = [document for document in documents if document.get("status") == "failed"]
    running = [document for document in documents if document.get("status") == "running"]
    row: dict[str, Any] = {
        "condition": condition.name,
        "rtt_ms": condition.rtt_ms,
        "mode": condition.mode,
        "size_bytes": condition.size_bytes,
        "requested_runs": requested_runs,
        "successful_runs": len(successful),
        "failed_runs": len(failed),
        "running_runs": len(running),
        "complete": len(successful) == requested_runs and not failed and not running,
    }
    for name, path in SUMMARY_METRICS.items():
        values = [
            float(value) for document in successful
            if isinstance((value := _nested(document, path)), (int, float))
            and math.isfinite(value)
        ]
        row[f"{name}_mean"] = statistics.fmean(values) if values else None
        row[f"{name}_sample_sd"] = statistics.stdev(values) if len(values) > 1 else None
    return row


RUN_CSV_FIELDS = [
    "run_id", "condition", "rtt_ms", "mode", "size_bytes", "run_number",
    "messages", "requested_runs", "reduced_messages", "reduced_runs",
    "status", "error", "started_at_utc", "finished_at_utc", "setup_ms",
    "setup_rtt_ratio", "latency_mean_ms", "latency_sample_sd_ms", "latency_p95_ms",
    "latency_p99_ms", "client_setup_cpu_seconds", "client_message_cpu_seconds",
    "client_total_cpu_seconds", "client_cpu_ms_per_message", "relay_pid",
    "relay_setup_cpu_seconds", "relay_message_cpu_seconds", "relay_total_cpu_seconds",
    "relay_cpu_ms_per_message", "wire_ratio", "configured_added_rtt_ms",
    "measured_ping_average_rtt_ms", "capture_pcapng", "latencies_csv", "resumed",
]


def _run_csv_row(document: dict[str, Any], resumed: bool) -> dict[str, Any]:
    condition = document.get("condition", {})
    artifacts = document.get("artifacts", {})
    return {
        "run_id": document.get("run_id"),
        "condition": condition.get("name"),
        "rtt_ms": condition.get("rtt_ms"),
        "mode": condition.get("mode"),
        "size_bytes": condition.get("size_bytes"),
        "run_number": document.get("run_number"),
        "messages": document.get("messages"),
        "requested_runs": document.get("requested_runs"),
        "reduced_messages": _nested(document, ("reduced_from_project_defaults", "messages")),
        "reduced_runs": _nested(document, ("reduced_from_project_defaults", "runs")),
        "status": document.get("status"),
        "error": document.get("error"),
        "started_at_utc": document.get("started_at_utc"),
        "finished_at_utc": document.get("finished_at_utc"),
        "setup_ms": _nested(document, ("setup", "total_setup_ms")),
        "setup_rtt_ratio": _nested(document, ("setup", "setup_rtt_ratio")),
        "latency_mean_ms": _nested(document, ("latency", "mean_ms")),
        "latency_sample_sd_ms": _nested(document, ("latency", "sample_sd_ms")),
        "latency_p95_ms": _nested(document, ("latency", "p95_ms")),
        "latency_p99_ms": _nested(document, ("latency", "p99_ms")),
        "client_setup_cpu_seconds": _nested(document, ("cpu", "client", "setup_seconds")),
        "client_message_cpu_seconds": _nested(document, ("cpu", "client", "message_seconds")),
        "client_total_cpu_seconds": _nested(document, ("cpu", "client", "total_seconds")),
        "client_cpu_ms_per_message": _nested(document, ("cpu", "client", "message_ms_per_message")),
        "relay_pid": document.get("relay_pid"),
        "relay_setup_cpu_seconds": _nested(document, ("cpu", "relay", "setup_seconds")),
        "relay_message_cpu_seconds": _nested(document, ("cpu", "relay", "message_seconds")),
        "relay_total_cpu_seconds": _nested(document, ("cpu", "relay", "total_seconds")),
        "relay_cpu_ms_per_message": _nested(document, ("cpu", "relay", "message_ms_per_message")),
        "wire_ratio": _nested(document, ("wire_statistics", "session_wire_ratio")),
        "configured_added_rtt_ms": document.get("configured_added_rtt_ms"),
        "measured_ping_average_rtt_ms": document.get("measured_ping_average_rtt_ms"),
        "capture_pcapng": artifacts.get("capture.pcapng"),
        "latencies_csv": artifacts.get("latencies.csv"),
        "resumed": resumed,
    }


def _write_csv(path: Path, fields: Sequence[str], rows: Sequence[dict[str, Any]]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent,
        prefix=f".{path.name}.", suffix=".tmp", delete=False
    ) as stream:
        temporary_name = stream.name
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    try:
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _checkpoint(
    settings: Settings, manifest: dict[str, Any], conditions: Sequence[Condition],
    skipped: set[str], *, final: bool = False
) -> None:
    documents: list[dict[str, Any]] = []
    by_condition: dict[str, list[dict[str, Any]]] = {condition.name: [] for condition in conditions}
    for condition in conditions:
        for run_number in range(1, settings.runs + 1):
            path = settings.output / condition.name / f"run-{run_number}" / "run.json"
            if not path.exists():
                continue
            try:
                document = _read_json(path)
            except (OSError, json.JSONDecodeError) as exc:
                raise BenchmarkError(f"cannot checkpoint invalid run artifact {path}: {exc}") from exc
            documents.append(document)
            by_condition[condition.name].append(document)
    run_rows = [
        _run_csv_row(document, str(document.get("run_id")) in skipped)
        for document in documents
    ]
    _write_csv(settings.output / "runs.csv", RUN_CSV_FIELDS, run_rows)
    summary_rows = [
        _summary_row(condition, settings.runs, by_condition[condition.name])
        for condition in conditions
    ]
    summary_fields = list(summary_rows[0]) if summary_rows else ["condition"]
    _write_csv(settings.output / "summary.csv", summary_fields, summary_rows)
    successful = sum(document.get("status") == "success" for document in documents)
    failed = sum(document.get("status") == "failed" for document in documents)
    running = sum(document.get("status") == "running" for document in documents)
    requested = len(conditions) * settings.runs
    manifest["completion"] = {
        "requested_runs": requested,
        "recorded_runs": len(documents),
        "successful_runs": successful,
        "failed_runs": failed,
        "running_runs": running,
        "remaining_runs": requested - len(documents),
        "resumed_skipped_runs": len(skipped),
        "complete": successful == requested and failed == 0 and running == 0,
    }
    manifest["updated_at_utc"] = _utc_now()
    if final:
        manifest["status"] = "complete" if manifest["completion"]["complete"] else "incomplete"
    _write_json(settings.output / "manifest.json", manifest)


def _new_manifest(settings: Settings, conditions: Sequence[Condition]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "running",
        "created_at_utc": _utc_now(),
        "updated_at_utc": _utc_now(),
        "environment": settings.environment,
        "config": settings.config_dict(),
        "config_signature": settings.signature,
        "software": _software_versions(),
        "seed": settings.seed,
        "intended_matrix": {
            "condition_count": len(conditions),
            "run_count": len(conditions) * settings.runs,
            "conditions": [
                {
                    "name": condition.name,
                    "rtt_ms": condition.rtt_ms,
                    "mode": condition.mode,
                    "size_bytes": condition.size_bytes,
                    "runs": list(range(1, settings.runs + 1)),
                }
                for condition in conditions
            ],
        },
        "network_architecture": {
            "relay": "10.0.3.10" if settings.environment == "lab" else "127.0.0.1",
            "sender": "10.0.1.10" if settings.environment == "lab" else "127.0.0.1",
            "echo_namespace": "server" if settings.environment == "lab" else "local",
            "sender_namespace": "client" if settings.environment == "lab" else "local",
            "relay_plain_port": 8080,
            "relay_secure_port": 8443,
            "echo": "separate ChatClient; same room; same message ID; payload validated",
            "relay_decrypts_e2e": False,
        },
    }


def _load_resume_manifest(settings: Settings, conditions: Sequence[Condition]) -> dict[str, Any]:
    manifest = _read_json(settings.output / "manifest.json")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("config_signature") != settings.signature
        or manifest.get("config") != settings.config_dict()
    ):
        raise BenchmarkError(
            "resume configuration does not match the existing manifest; "
            "reduced smoke results are never reused for a different matrix"
        )
    expected = _new_manifest(settings, conditions)["intended_matrix"]
    if manifest.get("intended_matrix") != expected:
        raise BenchmarkError("resume matrix does not match the existing manifest")
    manifest["status"] = "running"
    manifest["resumed_at_utc"] = _utc_now()
    return manifest


def run_suite(settings: Settings) -> int:
    conditions = [
        Condition(rtt, mode, size)
        for rtt in settings.rtts for mode in settings.modes for size in settings.sizes
    ]
    if settings.resume:
        if not settings.output.is_dir():
            raise BenchmarkError(f"resume output does not exist: {settings.output}")
        manifest = _load_resume_manifest(settings, conditions)
    else:
        settings.output.mkdir(parents=True, exist_ok=False)
        manifest = _new_manifest(settings, conditions)
    skipped: set[str] = set()
    _checkpoint(settings, manifest, conditions, skipped)
    print(f"Output: {settings.output}")
    print(f"Intended runs: {len(conditions) * settings.runs}; capture: {settings.capture}")
    try:
        for rtt in settings.rtts:
            block_conditions = [condition for condition in conditions if condition.rtt_ms == rtt]
            valid: dict[tuple[str, int], dict[str, Any]] = {}
            for condition in block_conditions:
                for run_number in range(1, settings.runs + 1):
                    document = _valid_completed_run(settings, condition, run_number)
                    if document is not None:
                        valid[(condition.name, run_number)] = document
            if len(valid) == len(block_conditions) * settings.runs:
                for document in valid.values():
                    skipped.add(str(document["run_id"]))
                _checkpoint(settings, manifest, conditions, skipped)
                continue

            measured_rtt = _prepare_rtt_block(settings, rtt) if settings.environment == "lab" else None
            for condition in block_conditions:
                for run_number in range(1, settings.runs + 1):
                    key = (condition.name, run_number)
                    if key in valid:
                        document = valid[key]
                        skipped.add(str(document["run_id"]))
                        print(f"SKIP valid {document['run_id']}")
                        _checkpoint(settings, manifest, conditions, skipped)
                        continue
                    _archive_invalid_run(settings, condition, run_number)
                    print(f"RUN {_run_id(condition, run_number)}", flush=True)
                    document = _execute_run(settings, condition, run_number, measured_rtt)
                    print(f"{document['status'].upper()} {document['run_id']}", flush=True)
                    _checkpoint(settings, manifest, conditions, skipped)
        _checkpoint(settings, manifest, conditions, skipped, final=True)
    except BaseException as exc:
        manifest["fatal_error"] = f"{type(exc).__name__}: {exc}"
        _checkpoint(settings, manifest, conditions, skipped, final=True)
        raise
    return 0 if manifest["completion"]["complete"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure ChatreX plaintext, TLS 1.3, and verified E2E messaging.",
        epilog=(
            "Lab prerequisite: create the two-router topology separately with "
            "sudo ./setup_topology.sh 20, then run this command as root. The benchmark "
            "never creates or deletes namespaces. It replaces symmetric netem qdiscs once "
            "per RTT and validates routing before measuring. Defaults: local RTT 0; lab "
            "RTTs 20,100,200; 1000 messages; 3 runs; all modes and sizes. Use --resume "
            "OUTPUT with exactly the original configuration. Local wire ratios are null "
            "because loopback duplicates flows."
        ),
    )
    parser.add_argument("--environment", choices=("local", "lab"), default="local")
    parser.add_argument("--modes", default=",".join(DEFAULT_MODES), help="comma-separated modes")
    parser.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)), help="comma-separated payload bytes")
    parser.add_argument("--rtts", help="comma-separated added RTTs in milliseconds")
    parser.add_argument("--messages", type=int, default=PROJECT_MESSAGES)
    parser.add_argument("--runs", "--repetitions", dest="runs", type=int, default=PROJECT_RUNS)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, help="new output directory")
    parser.add_argument("--resume", type=Path, metavar="OUTPUT", help="resume an exactly matching output directory")
    capture = parser.add_mutually_exclusive_group()
    capture.add_argument("--capture", dest="capture", action="store_true", help="require per-run lab packet captures")
    capture.add_argument("--no-capture", dest="capture", action="store_false", help="disable packet captures")
    parser.set_defaults(capture=None)

    # Internal worker options are intentionally hidden from the public help.
    parser.add_argument("--internal-role", choices=("echo", "sender", "wait-port"), help=argparse.SUPPRESS)
    parser.add_argument("--run-dir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--run-id", default="", help=argparse.SUPPRESS)
    parser.add_argument("--host", default="127.0.0.1", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=8080, help=argparse.SUPPRESS)
    parser.add_argument("--mode", default="plaintext", help=argparse.SUPPRESS)
    parser.add_argument("--keylog", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--size", type=int, default=64, help=argparse.SUPPRESS)
    parser.add_argument("--rtt-ms", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--wait-timeout", type=float, default=120.0, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.internal_role is not None:
        return _internal_main(args)
    try:
        settings = _resolve_settings(args)
        return run_suite(settings)
    except KeyboardInterrupt:
        print("benchmark interrupted", file=sys.stderr)
        return 130
    except (BenchmarkError, OSError, subprocess.SubprocessError, ValueError) as exc:
        parser.exit(1, f"benchmark: error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
