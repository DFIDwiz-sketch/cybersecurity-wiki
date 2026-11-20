"""Offline DNSSEC wire-format exercise for a fixed, fictional child zone."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from struct import pack
from subprocess import CalledProcessError, run
from tempfile import TemporaryDirectory
import sys

ZONE = 'training.example.'
OWNER = 'www.training.example.'
ED25519 = 15
A = 1
DNSKEY = 48
TTL = 300
NOW = int(datetime(2026, 11, 21, tzinfo=timezone.utc).timestamp())
START, EXPIRY = NOW - 3600, NOW + 3600
SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')

@dataclass(frozen=True)
class Signature:
    inception: int
    expiration: int
    value: bytes = b''

def openssl(*args, check=True):
    return run(['openssl', *args], capture_output=True, check=check)

def wire_name(name):
    labels = name.lower().rstrip('.').split('.')
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + bytes(1)

def make_key(folder, label, flags):
    private = folder / f'{label}.pem'
    openssl('genpkey', '-algorithm', 'ED25519', '-out', str(private))
    der = openssl('pkey', '-in', str(private), '-pubout', '-outform', 'DER').stdout
    if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 32:
        raise ValueError('Unexpected Ed25519 public-key encoding')
    rdata = pack('!HBB', flags, 3, ED25519) + der[len(SPKI_PREFIX):]
    return private, rdata

def key_tag(rdata):
    total = sum(b << 8 if i % 2 == 0 else b for i, b in enumerate(rdata))
    return (total + (total >> 16)) & 0xffff

def ds_rdata(key):
    # SHA-256 DS digest over canonical child owner name followed by DNSKEY RDATA.
    return pack('!HBB', key_tag(key), ED25519, 2) + sha256(wire_name(ZONE) + key).digest()

def signed_data(owner, rrtype, rdatas, key, sig):
    # RRSIG RDATA before its signature, followed by the canonical RRset.
    labels = len(owner.rstrip('.').split('.'))
    header = pack('!HBBIIIH', rrtype, ED25519, labels, TTL, sig.expiration,
                  sig.inception, key_tag(key)) + wire_name(ZONE)
    records = (
        wire_name(owner) + pack('!HHIH', rrtype, 1, TTL, len(rdata)) + rdata
        for rdata in sorted(rdatas)
    )
    return header + b''.join(records)

def sign(folder, private, owner, rrtype, rdatas, key):
    sig = Signature(START, EXPIRY)
    payload = folder / 'payload'
    payload.write_bytes(signed_data(owner, rrtype, rdatas, key, sig))
    value = openssl('pkeyutl', '-sign', '-rawin', '-inkey', str(private), '-in', str(payload)).stdout
    return replace(sig, value=value)

def verify(folder, owner, rrtype, rdatas, key, sig):
    payload, public, signature = (folder / n for n in ('payload', 'public.der', 'signature'))
    payload.write_bytes(signed_data(owner, rrtype, rdatas, key, sig))
    public.write_bytes(SPKI_PREFIX + key[4:])
    signature.write_bytes(sig.value)
    return openssl('pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER',
                   '-inkey', str(public), '-in', str(payload), '-sigfile', str(signature),
                   check=False).returncode == 0

def review(folder, parent_ds, keys, ksk, zsk, key_sig, answer, answer_sig, now):
    if parent_ds is None:
        return 'no_authenticated_delegation_evidence'
    if ds_rdata(ksk) != parent_ds or ksk not in keys:
        return 'parent_ds_mismatch'
    if not key_sig.inception <= now <= key_sig.expiration:
        return 'dnskey_signature_outside_validity'
    if not verify(folder, ZONE, DNSKEY, keys, ksk, key_sig):
        return 'dnskey_rrset_signature_failed'
    if zsk not in keys:
        return 'answer_signer_outside_authenticated_rrset'
    if not answer_sig.inception <= now <= answer_sig.expiration:
        return 'answer_signature_outside_validity'
    if not verify(folder, OWNER, A, [answer], zsk, answer_sig):
        return 'answer_rrset_signature_failed'
    return 'validated_fixture_chain'

def main():
    with TemporaryDirectory(prefix='dnssec-lab-') as temp:
        folder = Path(temp)
        ksk_private, ksk = make_key(folder, 'ksk', 257)
        zsk_private, zsk = make_key(folder, 'zsk', 256)
        keys = [ksk, zsk]
        answer = IPv4Address('192.0.2.10').packed
        base = dict(parent_ds=ds_rdata(ksk), keys=keys, ksk=ksk, zsk=zsk, answer=answer, now=NOW,
                    key_sig=sign(folder, ksk_private, ZONE, DNSKEY, keys, ksk),
                    answer_sig=sign(folder, zsk_private, OWNER, A, [answer], zsk))
        # The KSK's earlier DS remains fixed while each case varies one input.
        wrong_ds = base['parent_ds'][:-1] + bytes([base['parent_ds'][-1] ^ 1])
        scenarios = [
            {},
            {'answer': IPv4Address('192.0.2.11').packed},
            {'parent_ds': wrong_ds},
            {'now': EXPIRY + 1},
            {'keys': [ksk]},
            {'parent_ds': None},
        ]
        print(f'Child KSK tag: {key_tag(ksk)} (varies with generated key)')
        for i, changes in enumerate(scenarios, 1):
            print(f'LAB-{i:02} {review(folder, **(base | changes))}')

if __name__ == '__main__':
    try:
        main()
    except FileNotFoundError:
        sys.exit('OpenSSL was not found. Install OpenSSL 3.x and add it to PATH.')
    except CalledProcessError as error:
        sys.exit('OpenSSL error: ' + error.stderr.decode(errors='replace').strip())
