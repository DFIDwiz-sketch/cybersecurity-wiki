---
title: "TLS 1.3 Hybrid Key Agreement · Verify the Selected Group"
description: "Separate the ClientHello offer, the final TLS group, certificate authentication and HTTP evidence, then verify four OpenSSL loopback cases."
category: network
tags: [TLS, TLS 1.3, Post-Quantum Cryptography, ML-KEM, OpenSSL, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/tls-hybrid-key-agreement-evidence/
---

A capture shows `X25519MLKEM768` in a ClientHello. Does that connection use post-quantum hybrid key agreement? The offer is a starting point. Follow the final ServerHello, the handshake result, and the exact connection leg before reporting what happened.

## 1. Separate key agreement, authentication and traffic protection

A **named group** tells TLS peers how to exchange key material. **X25519** uses ephemeral elliptic curve Diffie–Hellman to compute a shared secret. **ML-KEM** is a key encapsulation mechanism, standardized in NIST FIPS 203. Given a public encapsulation key, one peer produces a shared secret and a ciphertext. The holder of the private decapsulation key uses that ciphertext to recover the corresponding secret.

**X25519MLKEM768** combines X25519 and ML-KEM-768 under one TLS group. The client supplies an ephemeral X25519 share and an ML-KEM encapsulation key. The server sends its own X25519 share and an ML-KEM ciphertext. The two peers compute both component secrets. For this group, RFC 10024 puts the ML-KEM secret before the X25519 secret in the combined input to the TLS key schedule. TLS derives traffic keys from the handshake and uses symmetric authenticated encryption for application records. The two components are part of one agreement, so success is established by the completed TLS handshake.

The motivation includes **harvest now, decrypt later**. Someone can record encrypted traffic today in the hope that future advances let them recover the key material. Hybrid agreement adds a post-quantum component while retaining a traditional exchange. The deployment still needs a trusted peer identity, sound implementations and protected endpoints.

<figure>
  <img src="{{ '/assets/diagrams/tls-hybrid-key-agreement-evidence.svg' | relative_url }}" width="560" height="357" alt="The client offers groups and shares. The server can request a new share, or select a group in the final ServerHello. The hybrid group feeds X25519 and ML-KEM secrets into TLS key derivation. Certificate authentication is a separate check." />
  <figcaption>Follow the final group selection, then check handshake completion and endpoint authentication.</figcaption>
</figure>

| Field or observation | What it supports | What to corroborate |
| --- | --- | --- |
| ClientHello `supported_groups` | Groups advertised for this connection. | Compare the actual key shares and the server's final choice. |
| ClientHello `key_share` | Key material supplied in this hello for particular groups. | A supported group may have no initial share. Inspect a second ClientHello if there is a retry. |
| HelloRetryRequest `key_share.selected_group` | The server asks for a share for a specific group, if the extension is present. | The retry uses a special ServerHello-shaped message. Confirm the second hello and final ServerHello. |
| Final ServerHello `key_share` | The selected group for this connection. IANA lists **4588** (`0x11ec`) for `X25519MLKEM768`. | Confirm handshake completion with endpoint evidence. An observed final ServerHello can still be followed by failure. |
| TLS 1.3 cipher suite, certificate and signature | The cipher suite names the symmetric AEAD cipher and key-schedule hash. The certificate and handshake signature support authentication when validated. | Inspect negotiated group, certificate/signature evidence and application outcome separately. A PSK-only handshake can omit a key share. |

## 2. Read a normal handshake and a retry

Suppose an approved client connects to a TLS gateway. The ClientHello lists X25519 and X25519MLKEM768 and includes a hybrid key share. The final ServerHello selects 4588. The client completes TLS with a trusted ECDSA certificate, a TLS 1.3 AES-GCM suite and the hybrid group. If the gateway terminates TLS, its connection to the origin is a separate leg with its own group and authentication. Inspect both logs before describing end-to-end coverage.

On another run, the client advertises both groups and initially supplies only an X25519 share. A server requiring the hybrid group can send a HelloRetryRequest for 4588. The client sends the requested hybrid share in the second ClientHello. A normal retry adds a round trip. The special Random value in the retry message, followed by the second ClientHello and final ServerHello, distinguishes this from treating the retry itself as a completed selection. When there is no common group in a non-PSK handshake, the endpoints can fail to negotiate, as in the lab below.

**Current and historical references.** RFC 9846 (July 2026) superseded the original TLS 1.3 RFC 8446 (August 2018). RFC 10024 (August 2026) specifies three hybrid groups. OpenSSL's 3.5 documentation describes hybrid support and lists X25519MLKEM768 first in its default group list from 3.5. Build, provider and application policy can change the effective set. Check numeric IDs when interpreting historical captures or dissector labels.

## 3. Collect evidence, test a change and respond

1. **Scope each TLS leg.** Record UTC time, endpoint addresses and ports, the gateway or load balancer listener, build and policy, and the upstream connection if any. Compare an application or connection identifier across sources. Check for resumption, TLS interception or a separate connection during retry at the application layer.
2. **Read the handshake in order.** A packet capture requires access to the relevant leg and enough bytes for TLS reassembly. Wireshark's `tls.handshake.extensions_key_share_group` can appear on both the client offer and the server exchange. Inspect direction and handshake message. The field `tls.handshake.extensions_key_share_selected_group` is useful for a group requested in a HelloRetryRequest. Treat a visible offer in an outer ClientHello under ECH as outer-hello evidence. Check exact endpoint evidence if the relevant data is obscured or the connection is only partly captured.
3. **Confirm outcome at the right layer.** Record the final group, TLS version, handshake completion and certificate verification from controlled endpoint or trusted gateway telemetry where available. Compare HTTP or application records separately. The larger hybrid key shares can span more segments. Check snap length, missing traffic and reassembly before interpreting a partially decoded hello. Avoid collecting private keys or TLS session secrets for routine group monitoring.
4. **Investigate policy drift.** Less protection than the policy requires can result from legacy peers, a differently configured proxy, provider restrictions or traffic arriving at the wrong listener. Unapproved termination or changes to the accepted groups can also reduce coverage. Confirm the route and effective policies before attributing intent. For deployment validation, check failure rates and retry rates, test approved clients in a staged rollout, and retain per-leg evidence of the selected group.

## 4. Verify four cases on loopback

Use your own or an explicitly approved Linux workspace with Python 3 and an OpenSSL CLI build supporting the group and `-trace`. Check `openssl version` and `openssl list -tls-groups -tls1_3`. The example was executed with **OpenSSL 3.5.9**. Download <a href="{{ '/assets/labs/tls-hybrid-key-agreement-evidence/tls-group-cases.csv' | relative_url }}" download="tls-group-cases.csv">tls-group-cases.csv</a>, save the code as `review_groups.py` beside it, and run `python3 review_groups.py`.

The script binds a fresh port on `127.0.0.1` for each case. It creates an ephemeral test certificate and private key in a temporary directory, trusts that certificate only for the client test and verifies the hostname `localhost`. It leaves the system trust store untouched. Its trace checks the standardized HelloRetryRequest Random and counts ClientHello messages. The lab performs TLS handshakes and stops before any HTTP tests. In the retry row, OpenSSL's `*` marks the group whose initial share is sent, while both groups are advertised.

```python
import csv
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time

def listening_address(server):
    deadline = time.monotonic() + 5
    output = b""
    while time.monotonic() < deadline:
        wait = max(0, deadline - time.monotonic())
        if not select.select([server.stdout], [], [], wait)[0]:
            break
        chunk = os.read(server.stdout.fileno(), 4096)
        if not chunk:
            break
        output += chunk
        match = re.search(rb"^ACCEPT (127\.0\.0\.1:[0-9]+)\r?$", output, re.M)
        if match:
            return match[1].decode("ascii")
    raise RuntimeError("The loopback TLS server did not report a listening port")

def check(row, cert, key):
    server_args = [
        "openssl", "s_server", "-accept", "127.0.0.1:0", "-tls1_3",
        "-groups", row["server_groups"], "-cert", str(cert), "-key", str(key), "-www",
    ]
    with subprocess.Popen(server_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as server:
        try:
            address = listening_address(server)
            result = subprocess.run([
                "openssl", "s_client", "-connect", address, "-tls1_3",
                "-groups", row["client_groups"], "-CAfile", str(cert),
                "-verify_hostname", "localhost", "-verify_return_error", "-brief", "-trace",
            ], input="", capture_output=True, text=True, timeout=8)
        finally:
            server.terminate()

    count = len(re.findall(r"^\s+ClientHello, Length=", result.stdout, re.M))
    retry = bool(re.search(
        r"gmt_unix_time=0xCF21AD74\s+random_bytes \(len=28\): "
        r"E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C",
        result.stdout,
    ))
    assert count == (2 if retry else 1), f"{row['case']}: trace incomplete or unexpected"
    if row["expected_group"] == "none":
        assert result.returncode != 0 and "alert handshake failure" in result.stderr, result.stderr
        assert "CONNECTION ESTABLISHED" not in result.stderr
        group = "none"
    else:
        assert result.returncode == 0 and "Verification: OK" in result.stderr, result.stderr
        match = re.search(r"^(?:Negotiated TLS1\.3 group|Peer Temp Key): ([^,\s]+)", result.stderr, re.M)
        assert match, result.stderr
        group = match[1]
    assert group == row["expected_group"], f"{row['case']}: got group {group}"
    assert retry == (row["hello_retry"] == "yes"), f"{row['case']}: unexpected ClientHello count"
    print(f"{row['case']}: group={group}, retry={retry}")

with tempfile.TemporaryDirectory() as tmp:
    cert = Path(tmp) / "cert.pem"
    key = Path(tmp) / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-noenc", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost", "-days", "1",
    ], check=True, capture_output=True)
    with open("tls-group-cases.csv", encoding="utf-8", newline="") as stream:
        cases = list(csv.DictReader(stream))
    assert len(cases) == 4
    for case in cases:
        check(case, cert, key)
```

| Case | Expected result |
| --- | --- |
| Hybrid | Completed TLS, certificate verified, X25519MLKEM768, one ClientHello. |
| Classical | Completed TLS, certificate verified, X25519, one ClientHello. |
| Retry | HelloRetryRequest and two ClientHellos, then completed TLS with X25519MLKEM768. |
| No overlap | Handshake failure, with no completed TLS connection. |

**Failure checks.** If a version or provider rejects a group, confirm the supported group list and the installed CLI build. If the trace assertion fails, compare the OpenSSL version and trace labels. Do not infer a successful exchange from a missing trace. As a negative control, change the expected group for the hybrid case to X25519 in a copy of the CSV and run against that copy. The checker should fail and report the observed hybrid group. The loopback tests verify the local CLI configuration. The Wireshark field descriptions were reviewed against the official field reference.

## 5. Check your understanding

1. **The client offers 4588 and the final ServerHello selects 29. What did the handshake select?** X25519. The offer alone does not establish hybrid use.
2. **The hybrid connection used an ECDSA certificate. Which property does 4588 describe?** The hybrid key agreement. Read the signature and validation result to evaluate authentication.
3. **The browser-facing connection is hybrid. Is the origin-facing connection covered?** Look up the origin-facing TLS leg and its own negotiation evidence.

Complete the chapter when you can identify an offer, retry and final selection, link the selected group to a completed handshake, and scope the claim to the correct TLS leg.

## Official references

Reviewed **2026-11-27**. Standards scope includes NIST ML-KEM (August 2024), TLS 1.3 (July 2026) and the hybrid TLS groups (August 2026). Product scope includes OpenSSL 3.5 documentation and the current Wireshark TLS field reference.

- [IETF · RFC 9846 TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)
- [IETF · RFC 10024 Hybrid key agreement groups](https://www.rfc-editor.org/rfc/rfc10024.html)
- [IANA · TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
- [NIST · FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [OpenSSL 3.5 · Supported-group settings](https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/)
- [OpenSSL 3.5 · Initial shares and group configuration](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
- [OpenSSL 3.5 · s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/)
- [Wireshark · TLS fields](https://www.wireshark.org/docs/dfref/t/tls.html)

[Previous · Public keys, private keys and signatures]({{ '/wiki/public-key-cryptography/' | relative_url }}) · [Next · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) · [Compare ALPN per connection leg]({{ '/wiki/tls-alpn-evidence/' | relative_url }})
