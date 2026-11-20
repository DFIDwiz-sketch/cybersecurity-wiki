"""Walk a four-leaf CT-style inclusion proof using synthetic bytes."""
from hashlib import sha256
from hmac import compare_digest


def leaf_hash(data):
    return sha256(b"\x00" + data).digest()


def parent_hash(left, right):
    return sha256(b"\x01" + left + right).digest()


def verifies(data, leaf_index, tree_size, siblings, expected_root):
    # The exercise only supports a complete, four-entry tree.
    if tree_size != 4 or not 0 <= leaf_index < tree_size or len(siblings) != 2:
        return False
    if any(len(sibling) != 32 for sibling in siblings) or len(expected_root) != 32:
        return False
    node = leaf_hash(data)
    for sibling in siblings:
        if leaf_index & 1:
            node = parent_hash(sibling, node)
        else:
            node = parent_hash(node, sibling)
        leaf_index //= 2
    return compare_digest(node, expected_root)


# Treat the root as already authenticated for this exercise. It was computed
# independently using OpenSSL. The four entries are "lab-A" through "lab-D".
root = bytes.fromhex("802a70f35633ed8fe1a881edf9bd60824093bcf019a57a177995b0f7dca0c10c")
left = leaf_hash(b"lab-A")
right_subtree = parent_hash(leaf_hash(b"lab-C"), leaf_hash(b"lab-D"))
proof = (left, right_subtree)
different_root = bytes([root[0] ^ 1]) + root[1:]

cases = [
    ("intact entry", b"lab-B", 1, 4, proof, root, True),
    ("changed entry bytes", b"lab-b", 1, 4, proof, root, False),
    ("incorrect leaf position", b"lab-B", 0, 4, proof, root, False),
    ("reversed siblings", b"lab-B", 1, 4, proof[::-1], root, False),
    ("incomplete proof", b"lab-B", 1, 4, proof[:1], root, False),
    ("different root", b"lab-B", 1, 4, proof, different_root, False),
    ("unsupported tree size", b"lab-B", 1, 5, proof, root, False),
]

if __name__ == "__main__":
    for name, data, index, size, path, head, expected in cases:
        actual = verifies(data, index, size, path, head)
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected}, observed {actual}")
        print(f"{name}: {'verified' if actual else 'rejected'}")
    print(f"{len(cases)} synthetic checks passed.")
