#!/usr/bin/env python3
"""Generate a tiny synthetic PCAP in memory; never open a capture socket."""
from __future__ import annotations

import ipaddress
import re
import struct


CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
SERVICE_PORT = 18080
CLIENT_PORT = 40000
EPOCH = 1767225600


def checksum(data):
    data = data + (b"\x00" if len(data) % 2 else b"")
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def payloads(marker):
    if not isinstance(marker, str) or not re.fullmatch(r"[a-f0-9]{24}", marker):
        raise ValueError("synthetic marker must contain 24 lowercase hex characters")
    request = ("GET /durkahelper-smoke/" + marker + " HTTP/1.1\r\n"
               "Host: fixture.invalid\r\nUser-Agent: DurkaHelper-Fixture\r\n"
               "Connection: close\r\n\r\n").encode("ascii")
    body = ("DURKAHELPER_RESPONSE_" + marker + "\n").encode("ascii")
    response = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)) +
                "\r\nConnection: close\r\n\r\n").encode("ascii") + body
    return request, response


def frame(incoming, sequence, acknowledgement, flags, payload=b"", identifier=1):
    source_ip, dest_ip = (CLIENT_IP, SERVER_IP) if incoming else (SERVER_IP, CLIENT_IP)
    source_port, dest_port = (CLIENT_PORT, SERVICE_PORT) if incoming else (SERVICE_PORT, CLIENT_PORT)
    source, dest = ipaddress.ip_address(source_ip).packed, ipaddress.ip_address(dest_ip).packed
    tcp = struct.pack("!HHIIBBHHH", source_port, dest_port, sequence, acknowledgement,
                      5 << 4, flags, 65535, 0, 0)
    pseudo = source + dest + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), identifier,
                     0x4000, 64, 6, 0, source, dest)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    mac_client, mac_server = bytes.fromhex("020000000010"), bytes.fromhex("020000000020")
    ethernet = (mac_server + mac_client if incoming else mac_client + mac_server) + b"\x08\x00"
    return ethernet + ip + tcp + payload


def make_pcap(marker):
    """One complete TCP conversation; linktype Ethernet, microsecond timestamps."""
    request, response = payloads(marker)
    client_end, server_end = 1001 + len(request), 5001 + len(response)
    conversation = [
        (True, 1000, 0, 0x02, b""),
        (False, 5000, 1001, 0x12, b""),
        (True, 1001, 5001, 0x10, b""),
        (True, 1001, 5001, 0x18, request),
        (False, 5001, client_end, 0x18, response),
        (True, client_end, server_end, 0x11, b""),
        (False, server_end, client_end + 1, 0x10, b""),
        (False, server_end, client_end + 1, 0x11, b""),
        (True, client_end + 1, server_end + 1, 0x10, b""),
    ]
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for number, packet in enumerate(conversation):
        data = frame(*packet, identifier=number + 1)
        result.extend(struct.pack("<IIII", EPOCH, number * 10000, len(data), len(data)))
        result.extend(data)
    return bytes(result)
