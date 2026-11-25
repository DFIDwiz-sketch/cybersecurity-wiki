"""Observe conventional DNS transport on IPv4 loopback using synthetic replies."""

import socket
import struct


LOOPBACK = "127.0.0.1"
TIMEOUT = 3
HEADER = struct.Struct("!6H")
LENGTH = struct.Struct("!H")
QR = 0x8000
AA = 0x0400
TC = 0x0200
QUESTION = b"\x07service\x04test\x00" + struct.pack("!HH", 1, 1)
ADDRESS = "192.0.2.42"
ANSWER = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ADDRESS)


def socket_for(kind):
    sock = socket.socket(socket.AF_INET, kind)
    sock.settimeout(TIMEOUT)
    return sock


def require(condition, message):
    if not condition:
        raise ValueError(message)


def make_query(txid):
    return HEADER.pack(txid, 0, 1, 0, 0, 0) + QUESTION


def make_response(query, truncated):
    txid, flags, questions, answers, authority, additional = HEADER.unpack_from(query)
    require((flags, questions, answers, authority, additional) == (0, 1, 0, 0, 0)
            and query[HEADER.size:] == QUESTION, "Unexpected lab query")
    flags = QR | AA | (TC if truncated else 0)
    answer = b"" if truncated else ANSWER
    return HEADER.pack(txid, flags, 1, int(not truncated), 0, 0) + QUESTION + answer


def check_response(response, query, truncated):
    txid, flags, questions, answers, authority, additional = HEADER.unpack_from(response)
    expected_id = LENGTH.unpack_from(query)[0]
    require(txid == expected_id and flags == QR | AA | (TC if truncated else 0),
            "Response ID or flags differ")
    require((questions, answers, authority, additional) == (1, int(not truncated), 0, 0),
            "Unexpected section counts")
    expected_body = QUESTION if truncated else QUESTION + ANSWER
    require(response[HEADER.size:] == expected_body, "Question or answer bytes differ")


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        # Small reads exercise incomplete reads without assuming segment boundaries.
        chunk = sock.recv(min(3, size - len(data)))
        if not chunk:
            raise EOFError(f"TCP stream ended after {len(data)} of {size} bytes")
        data.extend(chunk)
    return bytes(data)


def receive_message(sock):
    # Assemble even a length prefix whose two bytes need separate reads.
    first_byte = read_exact(sock, 1)
    size = LENGTH.unpack(first_byte + read_exact(sock, 1))[0]
    require(size >= HEADER.size, "DNS/TCP frame shorter than the DNS header")
    return read_exact(sock, size)


def send_message(sock, message):
    sock.sendall(LENGTH.pack(len(message)) + message)


def udp_exchange(server, endpoint, truncated):
    query = make_query(100)
    with socket_for(socket.SOCK_DGRAM) as client:
        client.connect(endpoint)
        client.send(query)
        received_query, peer = server.recvfrom(4096)
        server.sendto(make_response(received_query, truncated), peer)
        response = client.recv(4096)
    check_response(response, query, truncated)
    return bool(HEADER.unpack_from(response)[1] & TC)


def tcp_exchange(server, endpoint):
    query = make_query(200)
    with socket_for(socket.SOCK_STREAM) as client:
        client.connect(endpoint)
        connection, _ = server.accept()
        with connection:
            connection.settimeout(TIMEOUT)
            send_message(client, query)
            send_message(connection, make_response(receive_message(connection), False))
            check_response(receive_message(client), query, False)


def run_case(mode):
    with socket_for(socket.SOCK_STREAM) as tcp, socket_for(socket.SOCK_DGRAM) as udp:
        tcp.bind((LOOPBACK, 0))
        endpoint = tcp.getsockname()
        udp.bind(endpoint)
        if mode == "tcp-first":
            tcp.listen(1)
            tcp_exchange(tcp, endpoint)
            return f"TCP TC=0 A={ADDRESS}"

        truncated = udp_exchange(udp, endpoint, mode != "udp-complete")
        if not truncated:
            return f"UDP TC=0 A={ADDRESS}"
        if mode == "no-listener":
            with socket_for(socket.SOCK_STREAM) as client:
                try:
                    client.connect(endpoint)
                except ConnectionRefusedError:
                    return "UDP TC=1; TCP connection refused"
            raise RuntimeError("Expected refusal from the bound, non-listening TCP socket")

        tcp.listen(1)
        tcp_exchange(tcp, endpoint)
        return f"UDP TC=1; TCP TC=0 A={ADDRESS}"


def main():
    for mode in ("udp-complete", "fallback", "no-listener", "tcp-first"):
        print(f"PASS {mode}: {run_case(mode)}")


if __name__ == "__main__":
    main()
