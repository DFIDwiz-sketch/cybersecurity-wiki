"""Inspect only a disposable IPv4 TCP exchange in the current Linux namespace."""

import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys


def fd_inode(pid, fd):
    target = os.readlink(f"/proc/{pid}/fd/{fd}")
    match = re.fullmatch(r"socket:\[(\d+)\]", target)
    if not match:
        raise RuntimeError(f"FD {fd} is not a socket")
    return int(match.group(1))


def tcp_states(pid, inodes):
    rows = Path(f"/proc/{pid}/net/tcp").read_text(encoding="ascii").splitlines()[1:]
    states = {}
    for row in rows:
        fields = row.split()
        inode = int(fields[9])
        if inode in inodes:
            states[inode] = fields[3]
    return states


def listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as service:
        service.bind(("127.0.0.1", 0))
        service.listen(1)
        service.settimeout(5)
        print(json.dumps([service.getsockname()[1], service.fileno()]), flush=True)
        peer, _ = service.accept()
        with peer:
            print(peer.fileno(), flush=True)
            sys.stdin.buffer.read(1)


def check(label, condition):
    if not condition:
        raise RuntimeError(f"FAIL {label}")
    print(f"PASS {label}")


def has_holder(line, inode, pid):
    return bool(re.search(rf"\bino:{inode}\b", line) and re.search(rf"\bpid={pid}\b", line))


def inspect(child):
    port, listen_fd = json.loads(child.stdout.readline())
    pid = child.pid
    own_pid = os.getpid()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
        peer_fd = int(child.stdout.readline())
        listen_inode = fd_inode(pid, listen_fd)
        accepted_inode = fd_inode(pid, peer_fd)
        client_inode = fd_inode(own_pid, client.fileno())
        related = {listen_inode, accepted_inode, client_inode}

        own_ns = os.readlink(f"/proc/{own_pid}/ns/net")
        child_ns = os.readlink(f"/proc/{pid}/ns/net")
        check("observer and listener share a network namespace", own_ns == child_ns)
        observer_view = tcp_states(own_pid, related)
        child_view = tcp_states(pid, related)
        check("both namespace tables show the listener", observer_view.get(listen_inode) == "0A"
              and child_view.get(listen_inode) == "0A")
        own_links = []
        for fd in Path(f"/proc/{own_pid}/fd").iterdir():
            try:
                own_links.append(os.readlink(fd))
            except FileNotFoundError:
                continue
        check("the observer does not hold the listening socket",
              f"socket:[{listen_inode}]" not in own_links)
        check("client and accepted socket have distinct established inodes",
              client_inode != accepted_inode
              and child_view.get(client_inode) == child_view.get(accepted_inode) == "01")
        duplicate = os.dup(client.fileno())
        try:
            check("two descriptors can reference the same socket",
                  fd_inode(own_pid, duplicate) == client_inode)
        finally:
            os.close(duplicate)

        listing = subprocess.run(
            ["ss", "-Hltnep", f"sport = :{port}"], capture_output=True, text=True, check=True
        ).stdout
        matched = [line for line in listing.splitlines() if has_holder(line, listen_inode, pid)]
        check("ss links the listener inode to the child PID", len(matched) == 1)

        connections = subprocess.run(
            ["ss", "-Htnpe", "state", "established", f"( sport = :{port} or dport = :{port} )"],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        check("ss reports both ends with their own holders", all(
            any(has_holder(line, inode, holder) for line in connections)
            for inode, holder in ((client_inode, own_pid), (accepted_inode, pid))
        ))


def main():
    if not sys.platform.startswith("linux") or not shutil.which("ss"):
        raise SystemExit("Use Linux with procfs and iproute2 ss")
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--listener"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        inspect(child)
    finally:
        child.stdin.close()
        child.stdout.close()
        try:
            child.wait(timeout=6)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    if sys.argv[1:] == ["--listener"]:
        listener()
    else:
        main()
