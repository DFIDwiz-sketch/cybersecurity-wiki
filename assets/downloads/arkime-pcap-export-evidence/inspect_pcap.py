"""Make and inspect harmless classic-PCAP exercise files without network access."""

import argparse
import hashlib
import socket
import struct
import sys
from pathlib import Path


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def ipv4_checksum(header):
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total & 0xFFFF) + (total >> 16)
    return (~(total + (total >> 16))) & 0xFFFF


def packet(reply=False):
    macs = [bytes.fromhex("020000000001"), bytes.fromhex("020000000002")]
    ips = [socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20")]
    ports = [53000, 9000]
    sender, receiver = (1, 0) if reply else (0, 1)
    payload = b"training acknowledgement" if reply else b"training ping"
    udp = struct.pack("!4H", ports[sender], ports[receiver], 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload),
        1, 0, 64, 17, 0, ips[sender], ips[receiver],
    )
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    frame = macs[receiver] + macs[sender] + b"\x08\x00" + ip + udp + payload
    return frame.ljust(60, b"\x00")  # Pad Ethernet without adding an FCS.


def global_header(snaplen):
    return b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, 1)


def record(frame, snaplen, seconds):
    captured = frame[:snaplen]
    return struct.pack("<IIII", seconds, 0, len(captured), len(frame)) + captured


def make_samples(folder):
    folder.mkdir(parents=True, exist_ok=True)
    frames = [packet(), packet(reply=True)]
    stamp = 1_700_000_000  # Fixed fictional timestamp, not a collection time.
    full = global_header(65535) + b"".join(
        record(frame, 65535, stamp + i) for i, frame in enumerate(frames)
    )
    sliced = global_header(48) + b"".join(
        record(frame, 48, stamp + i) for i, frame in enumerate(frames)
    )
    samples = {
        "intact.pcap": full,
        "sliced.pcap": sliced,
        "broken.pcap": full[:-7],
        "header-only.pcap": global_header(65535),
        "response.pcap": b"<!doctype html><title>Fictional export error</title>\n",
    }
    for name, content in samples.items():
        output = folder / name
        with output.open("xb") as handle:
            handle.write(content)
        print(f"Created {output}")


def inspect(path):
    with path.open("rb") as handle:
        prefix = handle.read(24)
        if prefix[:4] == PCAPNG_MAGIC:
            raise ValueError("PCAPNG signature found; use a PCAPNG-capable reader.")
        if prefix.lstrip().lower().startswith((b"<!doctype", b"<html", b"{", b"[")):
            raise ValueError("Looks like HTML or JSON, not a capture file.")
        if prefix[:4] not in MAGIC:
            raise ValueError("Unrecognized classic-PCAP magic.")
        if len(prefix) != 24:
            raise ValueError("Incomplete classic-PCAP global header.")

        order, units = MAGIC[prefix[:4]]
        major, minor, _, _, snaplen, linktype_info = struct.unpack(order + "HHIIII", prefix[4:])
        if (major, minor) != (2, 4) or snaplen == 0:
            raise ValueError("Expected a classic PCAP 2.4 header with nonzero snaplen.")
        linktype = linktype_info & 0xFFFF
        size = handle.seek(0, 2)
        handle.seek(24)
        packets = sliced = 0
        while handle.tell() < size:
            raw = handle.read(16)
            if len(raw) != 16:
                raise ValueError(f"Record {packets + 1}: incomplete packet header.")
            _, fraction, captured, original = struct.unpack(order + "IIII", raw)
            if fraction >= units or captured > snaplen or captured > original:
                raise ValueError(f"Record {packets + 1}: invalid length or timestamp fraction.")
            if captured > size - handle.tell():
                raise ValueError(f"Record {packets + 1}: packet bytes end early.")
            handle.seek(captured, 1)
            packets += 1
            sliced += captured < original

        handle.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"{path}: PCAP 2.4; linktype={linktype}; snaplen={snaplen}; "
          f"packets={packets}; sliced={sliced}; sha256={digest.hexdigest()}")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    subcommands = cli.add_subparsers(dest="command", required=True)
    make = subcommands.add_parser("make", help="write the five generated samples")
    make.add_argument("directory", type=Path)
    check = subcommands.add_parser("check", help="inspect stable classic-PCAP files")
    check.add_argument("files", nargs="+", type=Path)
    args = cli.parse_args()
    if args.command == "make":
        try:
            make_samples(args.directory)
        except OSError as error:
            cli.error(str(error))
        return 0

    failed = False
    for path in args.files:
        try:
            inspect(path)
        except (OSError, ValueError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
