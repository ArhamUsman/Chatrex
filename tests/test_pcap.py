from __future__ import annotations

import ipaddress
import struct

import pytest

from chatrex.pcap import (
    PcapError,
    PcapPacket,
    convert_pcap_to_pcapng,
    read_pcap,
    wire_statistics,
)


def global_header(
    magic: bytes = b"\xd4\xc3\xb2\xa1",
    byte_order: str = "<",
    snaplen: int = 65_535,
    link_type: int = 1,
) -> bytes:
    return magic + struct.pack(
        byte_order + "HHiIII", 2, 4, 0, 0, snaplen, link_type
    )


def make_pcap(
    records: list[tuple[int, int, bytes, int | None]],
    *,
    magic: bytes = b"\xd4\xc3\xb2\xa1",
    byte_order: str = "<",
    snaplen: int = 65_535,
    link_type: int = 1,
) -> bytes:
    contents = bytearray(global_header(magic, byte_order, snaplen, link_type))
    for seconds, fraction, data, original_length in records:
        if original_length is None:
            original_length = len(data)
        contents.extend(
            struct.pack(
                byte_order + "IIII",
                seconds,
                fraction,
                len(data),
                original_length,
            )
        )
        contents.extend(data)
    return bytes(contents)


@pytest.mark.parametrize(
    ("magic", "byte_order", "fraction", "expected_ns"),
    [
        (b"\xd4\xc3\xb2\xa1", "<", 123_456, 7_123_456_000),
        (b"\xa1\xb2\xc3\xd4", ">", 123_456, 7_123_456_000),
        (b"\x4d\x3c\xb2\xa1", "<", 123_456_789, 7_123_456_789),
        (b"\xa1\xb2\x3c\x4d", ">", 123_456_789, 7_123_456_789),
    ],
    ids=["little-micro", "big-micro", "little-nano", "big-nano"],
)
def test_read_pcap_byte_orders_and_timestamp_resolutions(
    tmp_path, magic, byte_order, fraction, expected_ns
) -> None:
    path = tmp_path / "input.pcap"
    path.write_bytes(
        make_pcap(
            [(7, fraction, b"abc", 9), (8, 0, b"", 0)],
            magic=magic,
            byte_order=byte_order,
            snaplen=32_768,
            link_type=113,
        )
    )

    packets, link_type, snaplen = read_pcap(path)

    assert link_type == 113
    assert snaplen == 32_768
    assert packets == [
        PcapPacket(expected_ns, 3, 9, b"abc"),
        PcapPacket(8_000_000_000, 0, 0, b""),
    ]


@pytest.mark.parametrize(
    "contents",
    [
        b"",
        b"\xd4\xc3\xb2\xa1" + b"\x00" * 10,
        b"BAD!" + b"\x00" * 20,
        global_header() + b"\x00" * 15,
        global_header()
        + struct.pack("<IIII", 1, 0, 5, 5)
        + b"abc",
        global_header(snaplen=0xFFFFFFFF)
        + struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF),
        global_header()
        + struct.pack("<IIII", 1, 1_000_000, 0, 0),
        global_header() + struct.pack("<IIII", 1, 0, 3, 2) + b"abc",
        global_header(snaplen=2)
        + struct.pack("<IIII", 1, 0, 3, 3)
        + b"abc",
        global_header()[:4]
        + struct.pack("<HHiIII", 3, 4, 0, 0, 65_535, 1),
        global_header(snaplen=0),
    ],
    ids=[
        "empty",
        "short-global-header",
        "bad-magic",
        "short-record-header",
        "short-packet-data",
        "huge-record",
        "invalid-timestamp-fraction",
        "original-smaller-than-captured",
        "captured-larger-than-snaplen",
        "unsupported-version",
        "zero-snaplen",
    ],
)
def test_read_pcap_rejects_malformed_input(tmp_path, contents) -> None:
    path = tmp_path / "malformed.pcap"
    path.write_bytes(contents)
    with pytest.raises(PcapError):
        read_pcap(path)


def test_convert_pcap_to_pcapng_structure_alignment_and_packet_bytes(tmp_path) -> None:
    source = tmp_path / "source.pcap"
    destination = tmp_path / "capture.pcapng"
    source.write_bytes(
        make_pcap(
            [
                (0x20000, 999_999_999, b"abc", 6),
                (9, 1_999, b"12345", 5),
            ],
            magic=b"\x4d\x3c\xb2\xa1",
            snaplen=262_144,
            link_type=1,
        )
    )

    convert_pcap_to_pcapng(source, destination)
    contents = destination.read_bytes()

    block_type, block_length, byte_order_magic = struct.unpack_from("<III", contents)
    assert (block_type, block_length, byte_order_magic) == (0x0A0D0D0A, 28, 0x1A2B3C4D)
    assert struct.unpack_from("<HHq", contents, 12) == (1, 0, -1)
    assert struct.unpack_from("<I", contents, 24)[0] == 28

    assert struct.unpack_from("<IIHHII", contents, 28) == (
        1,
        20,
        1,
        0,
        262_144,
        20,
    )

    expected = [
        (0x20000 * 1_000_000 + 999_999, b"abc", 6),
        (9 * 1_000_000 + 1, b"12345", 5),
    ]
    offset = 48
    for expected_timestamp, expected_data, expected_original_length in expected:
        block_type, block_length = struct.unpack_from("<II", contents, offset)
        assert block_type == 6
        assert block_length % 4 == 0
        assert struct.unpack_from("<I", contents, offset + block_length - 4)[0] == block_length
        interface, high, low, captured, original = struct.unpack_from(
            "<IIIII", contents, offset + 8
        )
        assert interface == 0
        assert (high << 32) | low == expected_timestamp
        assert captured == len(expected_data)
        assert original == expected_original_length
        assert contents[offset + 28 : offset + 28 + captured] == expected_data
        padding = contents[
            offset + 28 + captured : offset + block_length - 4
        ]
        assert len(padding) == -captured % 4
        assert padding == b"\x00" * len(padding)
        offset += block_length

    assert offset == len(contents)


def test_conversion_failure_preserves_existing_destination(tmp_path) -> None:
    source = tmp_path / "bad.pcap"
    destination = tmp_path / "existing.pcapng"
    source.write_bytes(global_header() + b"partial")
    destination.write_bytes(b"keep me")

    with pytest.raises(PcapError):
        convert_pcap_to_pcapng(source, destination)

    assert destination.read_bytes() == b"keep me"
    assert list(tmp_path.glob(".existing.pcapng.*.tmp")) == []


def ethernet_tcp_frame(
    source: str,
    destination: str,
    *,
    sequence: int,
    acknowledgement: int = 0,
    flags: int = 0x18,
    payload: bytes = b"",
    vlan: bool = False,
) -> bytes:
    source_packed = ipaddress.IPv4Address(source).packed
    destination_packed = ipaddress.IPv4Address(destination).packed
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        1,
        0,
        64,
        6,
        0,
        source_packed,
        destination_packed,
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        12_345,
        8_443,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        8_192,
        0,
        0,
    )
    if vlan:
        ethernet = b"\x00" * 12 + struct.pack("!HHH", 0x8100, 7, 0x0800)
    else:
        ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    return ethernet + ip_header + tcp_header + payload


def test_wire_statistics_direction_original_lengths_and_heuristics(tmp_path) -> None:
    client = "10.0.0.1"
    server = "10.0.0.2"
    frames = [
        # Original lengths deliberately differ from captured lengths.
        (ethernet_tcp_frame(client, server, sequence=100, payload=b"abcd"), 64),
        (ethernet_tcp_frame(server, client, sequence=500, payload=b"12345"), 65),
        (ethernet_tcp_frame(client, server, sequence=100, payload=b"abcd"), 64),
        (
            ethernet_tcp_frame(
                server, client, sequence=505, acknowledgement=104, flags=0x10
            ),
            60,
        ),
        (
            ethernet_tcp_frame(
                server, client, sequence=505, acknowledgement=104, flags=0x10
            ),
            60,
        ),
        (
            ethernet_tcp_frame(
                client, server, sequence=104, payload=b"xy", vlan=True
            ),
            62,
        ),
        (ethernet_tcp_frame("192.0.2.1", server, sequence=1, payload=b"ignored"), 100),
        (b"\x00" * 12 + b"\x08\x06" + b"not TCP", 42),
    ]
    path = tmp_path / "wire.pcap"
    path.write_bytes(make_pcap([(index, 0, frame, original) for index, (frame, original) in enumerate(frames)]))

    statistics = wire_statistics(path, client, server, 10, 2)

    assert statistics == {
        "total_frame_bytes": 375,
        "packet_count": 6,
        "c2s_frame_bytes": 190,
        "s2c_frame_bytes": 185,
        "c2s_packets": 3,
        "s2c_packets": 3,
        "payload_bytes_c2s": 20,
        "payload_bytes_s2c": 20,
        "tcp_payload_bytes_c2s": 10,
        "tcp_payload_bytes_s2c": 5,
        "retransmission_count": 1,
        "duplicate_ack_count": 1,
        "session_wire_ratio": 375 / 40,
    }


@pytest.mark.parametrize(("size", "count"), [(0, 1), (-1, 1), (1, 0), (1, -1)])
def test_wire_statistics_validates_payload_accounting(tmp_path, size, count) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(global_header())
    with pytest.raises(ValueError):
        wire_statistics(path, "10.0.0.1", "10.0.0.2", size, count)
