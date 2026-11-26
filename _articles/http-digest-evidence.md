---
title: "HTTP Digest Evidence · Which Bytes Did the Sender Hash?"
description: "Verify Content-Digest and Repr-Digest across gzip, HTTP/1.1 chunking, ranges and HEAD without confusing the byte scopes."
category: network
tags: [HTTP, HTTP Digest, Content Encoding, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/http-digest-evidence/
---

**Learning goal.** A gateway reports a digest mismatch, but the JSON displayed at both ends looks identical. Learn to recover the exact bytes each field describes and distinguish a valid mismatch from a capture or byte-scope error.

## 1. Identify the byte layer

An HTTP **representation** is a selected form of a resource, such as JSON served with a particular content coding. Its **representation data** includes codings declared by `Content-Encoding`. HTTP **message content** is what a particular request or response carries. It can include the complete selected representation, a slice, or no bytes. An HTTP/1.1 **transfer coding** such as `chunked` frames content for transmission. A **digest** is a fixed-size value computed from a sequence of bytes.

| Field or layer | What it describes | How to read it |
| --- | --- | --- |
| `Content-Type` | Media type, such as `application/json` | Tells you how to interpret the data after removing the content coding. |
| `Content-Encoding` | Coding applied to the representation, such as `gzip` | The compressed bytes are relevant to both digest scopes for the same complete gzip response. |
| HTTP/1.1 `Transfer-Encoding: chunked` | A transport wrapper with chunk sizes, delimiters and an optional trailer section | Remove transfer framing before computing a digest. Preserve relevant trailers separately. |
| `Content-Digest` | Content carried by this HTTP message | Use exact content bytes after transfer decoding and before content decoding. |
| `Repr-Digest` | Complete selected representation data | Require the correct complete variant, including its content coding. |
| `ETag` | An opaque validator assigned to a representation | Use validator semantics for cache and range requests. Its text need not contain a digest. |

RFC 9530 defines these fields as Structured Fields dictionaries. A single member might be written as `sha-256=:BASE64_BYTES:`, where the placeholder represents Base64 of the raw digest bytes, enclosed in colons. Select an algorithm under your application policy. Production software needs a conforming dictionary parser and evidence of all relevant field lines. Legacy `Digest` and `Want-Digest` are defined differently. RFC 9530 obsoletes RFC 3230 and those fields.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http-digest-evidence-en.svg' | relative_url }}" alt="A JSON resource is encoded as gzip to form a complete selected representation. The message carries all or part of the selected representation or no bytes. HTTP/1.1 chunk framing wraps the message. Repr-Digest covers the complete representation, and Content-Digest covers what the message carries." width="480" height="384">
  <figcaption>Track each transformation before choosing the bytes to hash. The same displayed document can have different coded bytes.</figcaption>
</figure>

## 2. Compare three normal responses

A fictional reporting server offers a small JSON resource. For a normal full GET, the client accepts gzip and the server chooses that variant. The HTTP/1.1 server sends the gzip bytes in chunks. A client first removes the chunk framing. Both digests can then match the same gzip bytes because this message carries the complete representation. Decompressing the data for display changes the input bytes and therefore changes the hash. Compressing the same JSON again can also change the bytes because gzip metadata or implementation details can differ.

| Response | Bytes for Content-Digest | Bytes for Repr-Digest |
| --- | --- | --- |
| Full `200` GET serving gzip JSON | Complete received gzip bytes after transfer decoding | Same complete gzip representation |
| Single-range `206` GET serving an uncoded variant | Only the received range bytes | The full uncoded representation used to select the range |
| `200` HEAD for the gzip variant | Empty content if the field is sent | The complete gzip representation selected for this request, which is absent from the HEAD body |

The range example uses an uncoded variant for clarity. RFC 9110 defines byte ranges over the **coded** sequence when a content coding applies. A multipart response has different message content from a single range. Its media-type boundaries are content. Chunk framing is outside that content. A HEAD response can carry a `Content-Length` describing the equivalent GET, while its own content is empty. Do not use that value as evidence of transferred bytes. The full and HEAD responses in the lab select exactly the same gzip byte sequence, which allows the HEAD representation claim to be checked elsewhere.

## 3. Explain mismatches and misuse

| Observation | Plausible explanation | Evidence to check |
| --- | --- | --- |
| Digest mismatches only after loading into a browser tool | The tool saved a decompressed or otherwise transformed copy | Capture/export layer, original coding and received content |
| Full-body comparison fails after a partial transfer | The message carried a range, multipart body or a truncated capture | Response status, `Content-Range`, content length, framing and capture completeness |
| Same decoded document has different coded digests | Recompression, a different coding variant or differing metadata | Byte-for-byte comparison, coding, cache selection and proxy transformation records |
| Field is present and checks successfully | The bytes agree with the supplied value | Authenticate the source and any policy-required metadata separately |
| Field is missing or uses an unsupported algorithm | Endpoint contract, intermediary behavior, trailer visibility or collection limitation | Applied policy, raw headers and trailers, tool capabilities and the actual route |

A plain digest field does not identify the sender. An untrusted party able to replace both the content and its expected digest can leave a self-consistent response. Authenticated transport provides protection along its trust scope. For a stronger claim about the origin, verify a trusted signature or signed release manifest under the appropriate policy. RFC 9421 allows a message signature to cover a digest field and selected metadata. Acceptance also requires validating the actual message bytes against the covered digest, plus verifying the trusted key and required signature scope.

## 4. Collect and respond

1. **Name the observation point.** Capture UTC, request or trace ID where available, HTTP version, direction, origin/proxy/cache position and whether the bytes were seen after authorized TLS termination. A passive encrypted capture often cannot supply the content. Record whether the client automatically removed transfer framing or decoded the content coding.
2. **Preserve scope and metadata.** Keep exact bytes as observed, relevant raw headers and trailers, method, status, `Content-Encoding`, `Content-Type`, length, range, applicable `Vary` fields and a completeness flag. Record whether full representation bytes were actually available. Preserve the capture hash and protect any sensitive content and authorization data.
3. **Validate the right field.** For `Content-Digest`, hash complete received message content at the right layer. For `Repr-Digest`, establish the exact selected variant, then check the full coded bytes. If material is missing or transformed, record the result as unverified. Do not treat a range-only comparison as proof of representation mismatch.
4. **Investigate repeatable failures.** Compare same-route successful controls, partial or unavailable captures, wrong variants and a genuine byte difference. Break down mismatches by observation point, endpoint, coding and response type. Look for changes in proxy transformations or trailer collection before attributing modification. If an integrity or signature policy actually fails, use the approved rejection or incident process and correlate release or origin records.

## 5. Authorized loopback drill

Download <a href="{{ '/assets/labs/http-digest-evidence.py' | relative_url }}" download>the Python 3 loopback lab</a> into a directory you control. Run it where you are allowed to bind `127.0.0.1` on an ephemeral port. It creates and closes its own local HTTP/1.1 server. It sends only hard-coded requests to that server and processes a small fictional report.

```sh
python3 http-digest-evidence.py
python3 http-digest-evidence.py --negative-control
```

| Checks | What to reproduce |
| --- | --- |
| A–D | Both full-response digests match coded gzip. Decompressed JSON and chunk-framed bytes produce expected mismatches. |
| E–G | The range digest matches. Full representation checking remains unavailable from the slice alone and matches when the correct complete bytes are supplied. |
| H–I | HEAD content is empty. Its representation digest matches when checked with the full gzip variant outside the HEAD response. |
| J–L | Another gzip encoding of the same input differs, a missing field has no verdict and an invalid-length digest is rejected by the checker. |

Expect `12/12 HTTP digest checks matched.` in the normal run. The negative control changes one received byte in memory for A. The result is `A: mismatch`, 11 expected outcomes and exit status 1. If loopback binding or a connection is denied, use an authorized environment that permits loopback and check for local policy restrictions. A normal-run mismatch merits checking the script version and full output.

The cloud run exercised real local HTTP/1.1 GET, Range and HEAD responses, gzip and SHA-256, along with the altered-byte control. The parser handles only the exercise's single SHA-256 member. HTTP/2, HTTP/3, full Structured Fields parsing, trailer preservation, external proxies and signature verification are outside the executed scope. RFC behavior for those relevant concepts was reviewed separately.

## 6. Check your understanding

1. **Which bytes go into Content-Digest for chunked gzip?** Remove the chunk framing and hash the gzip bytes before decompression.
2. **A 206 passes Content-Digest. Has the whole file passed?** The message's range bytes match the field. Check a complete selected representation against Repr-Digest separately.
3. **Why can a HEAD advertise Repr-Digest?** It describes the selected representation even without sending its content. Verification requires those exact full bytes from a matching source.
4. **Does a digest match authenticate the publisher?** Establish the trust source and verify the applicable signature or authenticated transport separately.

**Completion.** Explain C, D, F, H and J. Reproduce both commands and name the byte layer, HTTP status and capture point you would record for a real mismatch.

## Official references

Reviewed 2026-11-26. RFC 9530 is the standards-track reference for the digest fields. The HTTP specifications define content, representation and transfer scope. Python documentation describes the gzip library used in the exercise.

- Current digest fields and legacy transition. [RFC 9530, February 2024](https://www.rfc-editor.org/rfc/rfc9530.html) · [RFC 9651, September 2024](https://www.rfc-editor.org/rfc/rfc9651.html)
- HTTP semantics, coded ranges and HTTP/1.1 framing. [RFC 9110, June 2022](https://www.rfc-editor.org/rfc/rfc9110.html) · [RFC 9112, June 2022](https://www.rfc-editor.org/rfc/rfc9112.html)
- Signature coverage and gzip behavior. [RFC 9421, February 2024](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.8) · [Python gzip documentation](https://docs.python.org/3/library/gzip.html)

[Previous · HTTP range evidence]({{ '/wiki/http-range-evidence/' | relative_url }}) · [Next · HTTP cache evidence]({{ '/wiki/http-cache-evidence/' | relative_url }})
