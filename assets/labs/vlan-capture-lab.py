"""Generate and compare six offline Ethernet observations. Sends no packets."""

from pathlib import Path
import struct


ETHERNET = bytes.fromhex("020000000020020000000010")
SRC = bytes((192, 0, 2, 12))
DST = bytes((198, 51, 100, 20))
C_TAG = 0x8100
S_TAG = 0x88A8
IPV4 = 0x0800
PCAP = struct.Struct("<IHHIIII")
RECORD = struct.Struct("<IIII")
HEADER = (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def checksum(data):
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(marker, tags):
    payload = f"VLAN-LAB-{marker}".encode("ascii")
    udp = struct.pack("!4H", 55000, 9000, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ord(marker),
                     0, 64, 17, 0, SRC, DST)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    headers = b"".join(
        struct.pack("!HH", tpid, (pcp << 13) | (dei << 12) | vid)
        for tpid, vid, pcp, dei in tags
    )
    return (ETHERNET + headers + struct.pack("!H", IPV4) + ip + udp).ljust(60, b"\0")


def write_pcap(path, frames):
    with path.open("xb") as output:
        output.write(PCAP.pack(*HEADER))
        for second, (full, stored) in enumerate(frames):
            output.write(RECORD.pack(1_700_000_000 + second, 0, len(stored), len(full)))
            output.write(stored)


def observations(path):
    with path.open("rb") as source:
        if PCAP.unpack(source.read(PCAP.size)) != HEADER:
            raise ValueError("Expected the bundled little-endian Ethernet PCAP format")
        while record := source.read(RECORD.size):
            _, _, size, original = RECORD.unpack(record)
            if size > original or size > HEADER[5]:
                raise ValueError("Invalid capture length")
            packet = source.read(size)
            if len(packet) != size:
                raise ValueError("PCAP record ended before its declared length")
            yield decode_frame(packet, original)


def decode_frame(packet, original):
    if len(packet) < original:
        return None, "truncated", None
    offset = 12
    tags = []
    protocol, = struct.unpack_from("!H", packet, offset)
    while protocol in (C_TAG, S_TAG):
        tci, = struct.unpack_from("!H", packet, offset + 2)
        tags.append((protocol, tci & 0xFFF, (tci >> 13) & 7, (tci >> 12) & 1))
        offset += 4
        protocol, = struct.unpack_from("!H", packet, offset)
    ip_start = offset + 2
    udp_start = ip_start + 20
    if protocol != IPV4 or packet[ip_start] != 0x45 or packet[ip_start + 9] != 17:
        raise ValueError("Expected the fixture's simple IPv4/UDP payload")
    if checksum(packet[ip_start:udp_start]):
        raise ValueError("Unexpected IPv4 header checksum")
    sport, dport, length, _ = struct.unpack_from("!4H", packet, udp_start)
    end = udp_start + length
    if length < 8 or end > len(packet):
        raise ValueError("Unexpected UDP length")
    mark = packet[udp_start + 8:end].decode("ascii")
    address_pair = packet[ip_start + 12:ip_start + 20]
    return mark, tuple(tags), (address_pair, sport, dport, 17)


def main():
    root = Path("vlan-lab")
    root.mkdir()
    link = root / "link-view.pcap"
    copy = root / "sensor-copy.pcap"
    cases = [
        ("A", (), ()),
        ("B", ((C_TAG, 20, 0, 0),), ()),
        ("C", ((C_TAG, 30, 0, 0),), ((C_TAG, 30, 0, 0),)),
        ("D", ((S_TAG, 200, 3, 1), (C_TAG, 20, 0, 0)), ((C_TAG, 20, 0, 0),)),
        ("E", ((C_TAG, 0, 5, 0),), ((C_TAG, 0, 5, 0),)),
        ("F", ((C_TAG, 40, 0, 0),), "truncated"),
    ]
    link_frames = []
    sensor_frames = []
    for marker, before, after in cases:
        full = frame(marker, before)
        link_frames.append((full, full))
        captured = full if after == "truncated" else frame(marker, after)
        sensor_frames.append((captured, captured[:15] if after == "truncated" else captured))
    write_pcap(link, link_frames)
    write_pcap(copy, sensor_frames)

    original = list(observations(link))
    sensor = list(observations(copy))
    if len(original) != len(cases) or len(sensor) != len(cases):
        raise ValueError("Unexpected number of observations")
    if original[1][2] != original[2][2]:
        raise ValueError("B and C should share the same tuple")
    for (marker, before, after), left, right in zip(cases, original, sensor):
        match = f"VLAN-LAB-{marker}"
        expected_right = (None, "truncated", None) if after == "truncated" else (match, after, left[2])
        if left[:2] != (match, before) or right != expected_right:
            raise ValueError(f"Unexpected observation for marker {marker}")
        print(f"PASS {marker}: link={left[1]} sensor={right[1]}")
    print(f"Wrote {link} and {copy}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        raise SystemExit(f"Lab failed: {error}") from None
