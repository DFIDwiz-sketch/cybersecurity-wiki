#!/usr/bin/env python3
"""Read the supplied Ethernet PCAP offline and correlate ICMP errors to UDP probes."""

import argparse
import ipaddress
from pathlib import Path
import struct
import sys


ICMP_ROLES = {
    (4, 11, 0): "hop-expired",
    (4, 11, 1): "fragment-reassembly-expired",
    (4, 3, 3): "port-unreachable",
    (6, 3, 0): "hop-expired",
    (6, 3, 1): "fragment-reassembly-expired",
    (6, 1, 4): "port-unreachable",
}


def frames(data):
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("expected the lab's little-endian microsecond PCAP")
    major, minor = struct.unpack_from("<HH", data, 4)
    if (major, minor) != (2, 4) or struct.unpack_from("<I", data, 20)[0] != 1:
        raise ValueError("expected PCAP 2.4 with Ethernet link type")
    offset = 24
    number = 0
    while offset < len(data):
        seconds, useconds, captured, wire = struct.unpack_from("<IIII", data, offset)
        offset += 16
        if useconds >= 1000000 or captured > wire or offset + captured > len(data):
            raise ValueError("invalid PCAP record")
        number += 1
        yield number, seconds * 1000000 + useconds, data[offset:offset + captured]
        offset += captured


def ip_header(packet):
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        offset = (packet[0] & 15) * 4
        total = struct.unpack_from("!H", packet, 2)[0]
        fragment_offset = struct.unpack_from("!H", packet, 6)[0] & 0x1fff
        if offset < 20 or offset > len(packet) or total < offset or fragment_offset:
            return None
        return (4, packet[9], packet[8], str(ipaddress.ip_address(packet[12:16])),
                str(ipaddress.ip_address(packet[16:20])), packet[offset:total])
    if version == 6 and len(packet) >= 40:
        total = 40 + struct.unpack_from("!H", packet, 4)[0]
        return (6, packet[6], packet[7], str(ipaddress.ip_address(packet[8:24])),
                str(ipaddress.ip_address(packet[24:40])), packet[40:total])
    return None


def udp_tuple(header):
    if header is None:
        return None
    version, protocol, _, source, destination, payload = header
    if protocol != 17 or len(payload) < 8:
        return None
    source_port, destination_port = struct.unpack_from("!HH", payload)
    return version, source, destination, source_port, destination_port


def analyze(data):
    recent = {}
    for number, stamp, ethernet in frames(data):
        if len(ethernet) < 14 or ethernet[12:14] not in (b"\x08\x00", b"\x86\xdd"):
            continue
        header = ip_header(ethernet[14:])
        if header is None:
            continue
        version, protocol, limit, source, destination, payload = header
        probe = udp_tuple(header)
        if probe is not None:
            recent.setdefault(probe, []).append((number, stamp))
            print(f"{number:02}: probe IPv{version} limit={limit}")
            continue
        if (version, protocol) not in ((4, 1), (6, 58)) or len(payload) < 8:
            continue
        typ, code = payload[:2]
        role = ICMP_ROLES.get((version, typ, code))
        if role is None:
            continue
        label = f"{number:02}: IPv{version} {typ}/{code} {role} responder={source}"
        if role == "fragment-reassembly-expired":
            print(f"{label} separate-from-hop")
            continue
        quote = udp_tuple(ip_header(payload[8:]))
        if quote is None:
            print(f"{label} quote-incomplete-or-unsupported")
            continue
        candidates = [n for n, t in recent.get(quote, []) if 0 <= stamp - t <= 1000000]
        if len(candidates) == 1:
            print(f"{label} matched={candidates[0]:02}")
        elif candidates:
            print(f"{label} ambiguous={','.join(f'{n:02}' for n in candidates)}")
        else:
            print(f"{label} unmatched")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", type=Path, default=Path(__file__).with_name(
        "icmp-hop-evidence.pcap"
    ))
    args = parser.parse_args()
    try:
        analyze(args.capture.read_bytes())
    except (OSError, ValueError, struct.error) as error:
        print(f"Cannot decode this training capture: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
