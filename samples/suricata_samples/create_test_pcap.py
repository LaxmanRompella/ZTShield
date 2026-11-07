
import socket
import struct
import time
from pathlib import Path


def checksum(data: bytes) -> int:
    """Calculate the Internet checksum for an IP or ICMP header."""
    if len(data) % 2:
        data += b"\x00"

    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def main() -> None:
    output = Path(__file__).with_name("icmp_test.pcap")

    # Documentation-only IP addresses; no packet is transmitted.
    source_ip = socket.inet_aton("192.0.2.10")
    destination_ip = socket.inet_aton("192.0.2.20")

    payload = b"ZTShield harmless offline ICMP test"

    # ICMP echo request: type 8, code 0.
    icmp_header = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
    icmp_packet = icmp_header + payload

    icmp_checksum = checksum(icmp_packet)
    icmp_packet = (
        struct.pack("!BBHHH", 8, 0, icmp_checksum, 0x1234, 1)
        + payload
    )

    # Build a valid IPv4 header.
    total_length = 20 + len(icmp_packet)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0x1234, 0, 64, 1, 0,
        source_ip, destination_ip,
    )

    ip_checksum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0x1234, 0, 64, 1,
        ip_checksum, source_ip, destination_ip,
    )

    # Ethernet II: destination MAC, source MAC, IPv4 EtherType.
    ethernet_header = bytes.fromhex(
        "0200000000020200000000010800"
    )

    packet = ethernet_header + ip_header + icmp_packet

    # Classic PCAP global header: little-endian, Ethernet link type.
    global_header = struct.pack(
        "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
    )

    packet_header = struct.pack(
        "<IIII", int(time.time()), 0, len(packet), len(packet)
    )

    output.write_bytes(global_header + packet_header + packet)
    print(f"Created one offline ICMP test packet: {output}")


if __name__ == "__main__":
    main()
