"""Standard-library capture-file and on-the-wire measurement helpers."""

from __future__ import annotations

import ipaddress
import os
import struct
import tempfile
from dataclasses import dataclass
from typing import BinaryIO

__all__ = [
    "PcapError",
    "PcapPacket",
    "convert_pcap_to_pcapng",
    "read_pcap",
    "wire_statistics",
]


class PcapError(ValueError):
    """Raised for malformed or unsupported classic PCAP input."""


@dataclass(frozen=True)
class PcapPacket:
    timestamp_ns: int
    captured_length: int
    original_length: int
    data: bytes


# Reading is intentionally bounded because all returned packet data is retained.
_MAX_CAPTURED_LENGTH = 64 * 1024 * 1024
_GLOBAL_HEADER_LENGTH = 24
_RECORD_HEADER_LENGTH = 16
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise PcapError(f"truncated PCAP {description}")
    return data


def read_pcap(path: str | os.PathLike[str]) -> tuple[list[PcapPacket], int, int]:
    """Read a classic PCAP file into packets, its link type, and its snaplen.

    Both byte orders and microsecond/nanosecond timestamp variants are
    supported. Malformed headers, partial records, and unreasonably large
    captured records raise :class:`PcapError` rather than being silently
    ignored.
    """

    packets: list[PcapPacket] = []
    with open(path, "rb") as stream:
        header = _read_exact(stream, _GLOBAL_HEADER_LENGTH, "global header")
        try:
            byte_order, timestamp_units = _MAGIC[header[:4]]
        except KeyError as exc:
            raise PcapError("invalid or unsupported PCAP magic") from exc

        major, minor, _thiszone, _sigfigs, snaplen, link_type = struct.unpack(
            byte_order + "HHiIII", header[4:]
        )
        if (major, minor) != (2, 4):
            raise PcapError(f"unsupported PCAP version {major}.{minor}")
        if snaplen == 0:
            raise PcapError("PCAP snaplen must be greater than zero")

        while True:
            record_header = stream.read(_RECORD_HEADER_LENGTH)
            if not record_header:
                break
            if len(record_header) != _RECORD_HEADER_LENGTH:
                raise PcapError("truncated PCAP packet header")

            seconds, fraction, captured_length, original_length = struct.unpack(
                byte_order + "IIII", record_header
            )
            if fraction >= timestamp_units:
                raise PcapError("invalid PCAP timestamp fraction")
            if captured_length > _MAX_CAPTURED_LENGTH:
                raise PcapError(
                    f"unsupported PCAP record of {captured_length} captured bytes"
                )
            if captured_length > snaplen:
                raise PcapError("PCAP captured length exceeds snaplen")
            if original_length < captured_length:
                raise PcapError("PCAP original length is smaller than captured length")

            data = _read_exact(stream, captured_length, "packet data")
            if timestamp_units == 1_000_000:
                timestamp_ns = seconds * 1_000_000_000 + fraction * 1_000
            else:
                timestamp_ns = seconds * 1_000_000_000 + fraction
            packets.append(
                PcapPacket(timestamp_ns, captured_length, original_length, data)
            )

    return packets, link_type, snaplen


def convert_pcap_to_pcapng(
    source: str | os.PathLike[str], destination: str | os.PathLike[str]
) -> None:
    """Convert classic PCAP to one-section, one-interface PCAPNG.

    The output is little-endian and uses the Interface Description Block's
    default microsecond timestamp resolution. Nanosecond input is therefore
    truncated to whole microseconds using integer arithmetic, never floats.
    The destination is replaced only after the complete temporary file has
    been written successfully.
    """

    packets, link_type, snaplen = read_pcap(source)
    if link_type > 0xFFFF:
        raise PcapError("PCAP link type cannot be represented in a PCAPNG IDB")

    destination_path = os.fspath(destination)
    destination_dir = os.path.dirname(os.path.abspath(destination_path))
    prefix = "." + os.path.basename(destination_path) + "."
    temporary = tempfile.NamedTemporaryFile(
        mode="wb", dir=destination_dir, prefix=prefix, suffix=".tmp", delete=False
    )
    temporary_path = temporary.name
    try:
        with temporary:
            # Section Header Block: unknown section length, no options.
            temporary.write(
                struct.pack(
                    "<IIIHHqI",
                    0x0A0D0D0A,
                    28,
                    0x1A2B3C4D,
                    1,
                    0,
                    -1,
                    28,
                )
            )
            # Interface Description Block: no if_tsresol option means 10^-6.
            temporary.write(
                struct.pack("<IIHHII", 1, 20, link_type, 0, snaplen, 20)
            )

            for packet in packets:
                timestamp_us = packet.timestamp_ns // 1_000
                padding = b"\x00" * (-packet.captured_length % 4)
                block_length = 32 + packet.captured_length + len(padding)
                temporary.write(
                    struct.pack(
                        "<IIIIIII",
                        6,
                        block_length,
                        0,
                        (timestamp_us >> 32) & 0xFFFFFFFF,
                        timestamp_us & 0xFFFFFFFF,
                        packet.captured_length,
                        packet.original_length,
                    )
                )
                temporary.write(packet.data)
                temporary.write(padding)
                temporary.write(struct.pack("<I", block_length))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination_path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def _parse_ethernet_ipv4_tcp(
    data: bytes,
) -> tuple[bytes, bytes, int, int, int, int] | None:
    """Return addresses, sequence, ACK, flags, and TCP payload length."""

    if len(data) < 14:
        return None
    ether_type = struct.unpack_from("!H", data, 12)[0]
    ip_offset = 14
    if ether_type in _VLAN_ETHERTYPES:
        if len(data) < 18:
            return None
        ether_type = struct.unpack_from("!H", data, 16)[0]
        ip_offset = 18
    if ether_type != 0x0800 or len(data) < ip_offset + 20:
        return None

    version = data[ip_offset] >> 4
    ip_header_length = (data[ip_offset] & 0x0F) * 4
    if version != 4 or ip_header_length < 20:
        return None
    if len(data) < ip_offset + ip_header_length:
        return None
    if data[ip_offset + 9] != 6:  # TCP
        return None

    ip_total_length = struct.unpack_from("!H", data, ip_offset + 2)[0]
    if ip_total_length < ip_header_length + 20:
        return None
    # A non-initial fragment does not start with a TCP header.
    fragment_field = struct.unpack_from("!H", data, ip_offset + 6)[0]
    if fragment_field & 0x1FFF:
        return None

    tcp_offset = ip_offset + ip_header_length
    if len(data) < tcp_offset + 20:
        return None
    tcp_header_length = (data[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or len(data) < tcp_offset + tcp_header_length:
        return None
    if ip_total_length < ip_header_length + tcp_header_length:
        return None

    source = data[ip_offset + 12 : ip_offset + 16]
    destination = data[ip_offset + 16 : ip_offset + 20]
    sequence, acknowledgement = struct.unpack_from("!II", data, tcp_offset + 4)
    flags = data[tcp_offset + 13]
    tcp_payload_length = ip_total_length - ip_header_length - tcp_header_length
    return source, destination, sequence, acknowledgement, flags, tcp_payload_length


def wire_statistics(
    path: str | os.PathLike[str],
    client_ip: str,
    server_ip: str,
    payload_bytes_per_message: int,
    message_count: int,
) -> dict[str, int | float]:
    """Measure directional Ethernet/IPv4/TCP traffic in a classic PCAP.

    Only frames between ``client_ip`` and ``server_ip`` are counted. Frame
    totals use each record's original length, while TCP payload totals are
    derived from IPv4 and TCP header lengths. A single 802.1Q/802.1ad VLAN tag
    is accepted; non-Ethernet, non-IPv4, and non-TCP packets are ignored.

    Retransmissions are a heuristic count of payload segments whose sequence
    starts below the highest previously observed payload end in that direction.
    Duplicate ACKs are repeated empty ACKs with the same sequence and ACK number
    in one direction (SYN, FIN, and RST packets are excluded). These are not a
    substitute for full TCP stream reconstruction.

    Like Wireshark's ``frame.len``, original frame lengths normally exclude the
    Ethernet FCS, preamble, and inter-frame gap. ``session_wire_ratio`` divides
    both echo directions by ``2 * message_count * payload_bytes_per_message``.
    It consequently includes connection setup/teardown, link/IP/TCP headers,
    ACKs, TLS records, application framing, and retransmissions.
    """

    if payload_bytes_per_message <= 0 or message_count <= 0:
        raise ValueError("payload size and message count must both be positive")
    client = ipaddress.IPv4Address(client_ip).packed
    server = ipaddress.IPv4Address(server_ip).packed
    if client == server:
        raise ValueError("client and server IPv4 addresses must differ")

    packets, link_type, _snaplen = read_pcap(path)
    c2s_frame_bytes = 0
    s2c_frame_bytes = 0
    c2s_packets = 0
    s2c_packets = 0
    tcp_payload_bytes_c2s = 0
    tcp_payload_bytes_s2c = 0
    retransmission_count = 0
    duplicate_ack_count = 0
    highest_payload_end = {"c2s": 0, "s2c": 0}
    last_ack = {"c2s": None, "s2c": None}

    if link_type == 1:  # LINKTYPE_ETHERNET
        for packet in packets:
            parsed = _parse_ethernet_ipv4_tcp(packet.data)
            if parsed is None:
                continue
            source, destination, sequence, acknowledgement, flags, payload_length = parsed
            if source == client and destination == server:
                direction = "c2s"
                c2s_frame_bytes += packet.original_length
                c2s_packets += 1
                tcp_payload_bytes_c2s += payload_length
            elif source == server and destination == client:
                direction = "s2c"
                s2c_frame_bytes += packet.original_length
                s2c_packets += 1
                tcp_payload_bytes_s2c += payload_length
            else:
                continue

            if payload_length:
                if sequence < highest_payload_end[direction]:
                    retransmission_count += 1
                highest_payload_end[direction] = max(
                    highest_payload_end[direction], sequence + payload_length
                )
            elif flags & 0x10 and not flags & 0x07:  # ACK, but not FIN/SYN/RST
                ack_key = (sequence, acknowledgement)
                if last_ack[direction] == ack_key:
                    duplicate_ack_count += 1
                last_ack[direction] = ack_key

    total_frame_bytes = c2s_frame_bytes + s2c_frame_bytes
    application_payload = message_count * payload_bytes_per_message
    return {
        "total_frame_bytes": total_frame_bytes,
        "packet_count": c2s_packets + s2c_packets,
        "c2s_frame_bytes": c2s_frame_bytes,
        "s2c_frame_bytes": s2c_frame_bytes,
        "c2s_packets": c2s_packets,
        "s2c_packets": s2c_packets,
        "payload_bytes_c2s": application_payload,
        "payload_bytes_s2c": application_payload,
        "tcp_payload_bytes_c2s": tcp_payload_bytes_c2s,
        "tcp_payload_bytes_s2c": tcp_payload_bytes_s2c,
        "retransmission_count": retransmission_count,
        "duplicate_ack_count": duplicate_ack_count,
        "session_wire_ratio": total_frame_bytes / (2 * application_payload),
    }
