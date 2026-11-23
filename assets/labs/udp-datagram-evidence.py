#!/usr/bin/env python3
"""Verify UDP receive behavior using only Linux IPv4 loopback."""

import socket
import sys


def main():
    if sys.platform != "linux" or not hasattr(socket.socket, "recvmsg") or not hasattr(socket, "MSG_TRUNC"):
        raise SystemExit("This lab needs Linux recvmsg() and MSG_TRUNC support.")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        sender.bind(("127.0.0.1", 0))
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        destination = receiver.getsockname()

        sender.sendto(b"cat", destination)
        sender.sendto(b"bird", destination)
        first, _, flags_first, _ = receiver.recvmsg(64)
        second, _, flags_second, _ = receiver.recvmsg(64)
        if (first, second) != (b"cat", b"bird") or (flags_first | flags_second) & socket.MSG_TRUNC:
            raise RuntimeError("Expected two complete tiny datagrams in sequence.")
        print(f"separate_datagrams: {len(first)}, {len(second)} bytes")

        sent = sender.sendto(b"abcdefghijkl", destination)
        sender.sendto(b"OK", destination)
        prefix, _, flags, _ = receiver.recvmsg(5)
        truncated = bool(flags & socket.MSG_TRUNC)
        if sent != 12 or prefix != b"abcde" or not truncated:
            raise RuntimeError("Expected five bytes and MSG_TRUNC.")
        print(f"truncation: sent={sent} copied={len(prefix)} flag={truncated}")

        marker, _, flags, _ = receiver.recvmsg(64)
        if marker != b"OK" or flags & socket.MSG_TRUNC:
            raise RuntimeError("Expected the next datagram, without any remainder.")
        print(f"next_datagram: {marker.decode('ascii')}")

        sender.sendto(b"", destination)
        empty, _, flags, source = receiver.recvmsg(64)
        if empty != b"" or flags & socket.MSG_TRUNC or source != sender.getsockname():
            raise RuntimeError("Expected a complete zero-length datagram from the same sender.")
        print(f"empty_datagram: {len(empty)} bytes")


if __name__ == "__main__":
    main()
