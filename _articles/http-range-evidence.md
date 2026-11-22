---
title: "HTTP Range Requests and Partial Download Evidence"
description: "Read 200, 206 and 416 responses, measure distinct byte coverage and separate HTTP transfer evidence from client completion."
category: network
tags: [HTTP, HTTP Range, CDN, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/http-range-evidence/
---

A client requests parts of a 1,000-byte file. The edge access log records 1,100 body bytes across three successful responses. Did the client receive all 1,000 distinct bytes? Did the origin send them? Use the response ranges, representation identifiers and observation point to investigate those questions separately.

## 1. What a range request asks for

A **representation** is the selected form of a resource. The same URL can return different file revisions or different content encodings. A **byte offset** is a position in that representation's byte sequence, starting at zero. A **byte range** includes both endpoints. `0–399` therefore covers 400 bytes. If a content coding such as gzip is applied, these positions refer to the coded byte sequence.

Clients use ranges to resume a download or fetch a segment of media. `Range: bytes=400-799` asks for 400 bytes starting at offset 400, `bytes=400-` asks for the remainder, and `bytes=-200` asks for the last 200 bytes. `Accept-Ranges: bytes` advertises support. The observed response determines whether any particular range request was honored.

| Signal | How to read it | What to check next |
| --- | --- | --- |
| `Range` | Offsets requested by the client | Use the response to identify offsets served |
| `If-Range: "r1"` | Apply the range if the selected representation strongly matches | A changed representation can produce a full 200 |
| `206`, one part | Server chose to send part of the representation | Read `Content-Range` and actual transfer evidence |
| `206`, multipart | Each part carries its own `Content-Range` | Exclude MIME boundaries and part headers from unique coverage |
| `200` on a GET with `Range` | Full-response semantics, for example after `If-Range` mismatch or when the range is ignored | Correlate the representation, body length and completion |
| `416` | Server rejected the range request | `Content-Range: bytes */1000` can report the current length |

For a single-part response, `Content-Range: bytes 400-799/1000` declares the inclusive positions and total representation length. Its `Content-Length: 400`, if present, describes the response body length. A declared length differs from a counter observed after sending, and both differ from client-side validation.

## 2. Follow a normal download

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http-range-evidence-en.svg' | relative_url }}" alt="The viewer asks the edge for a range. The edge can answer from cache or fetch from the origin. Investigators use completed response intervals with the same strong validator to track unique coverage.">
  <figcaption>Use the viewer-facing response for viewer coverage. The origin request and response describe a separate hop.</figcaption>
</figure>

Consider this fictional exchange for a 1,000-byte training file with no content coding:

```text
GET /training.bin
Range: bytes=0-399

HTTP 206
Content-Range: bytes 0-399/1000
Content-Length: 400
ETag: "r1"
```

1. The first response declares bytes 0–399, version `"r1"`. The client resumes using `Range: bytes=300-699` and `If-Range: "r1"`. The edge serves 300–699 with the same strong ETag.
2. The client asks for 700–999 with the same validator. From the edge's perspective, all three responses finish with 400, 400 and 300 body bytes. The transfer total is 1,100, with 100 bytes of overlap. The union of intervals is 0–999, so edge evidence supports full **observed coverage**.
3. If the representation changed before the third request, the server would ignore the range when the `If-Range` check fails. When the ordinary GET succeeds, the new representation is returned with 200. Keep its evidence separate from `"r1"`. A weak ETag, marked `W/`, cannot establish byte-for-byte identity for combining parts. A matching strong ETag applies within the correct resource and variant context. It is also distinct from a cryptographic file digest.

A CDN can answer a range from cache or retrieve a different interval at the origin. AWS documents that CloudFront may request a larger interval from the origin than the viewer requested. An absent origin request therefore needs cache and collection context. For cache-side combination and revalidation, continue with the linked HTTP cache chapter.

## 3. Collect, detect and respond

Collect at the HTTP termination point that serves the client. On encrypted traffic without decryption, a network sensor generally cannot see the HTTP headers or range positions. Require both request and response fields, and record which hop each row represents.

- Record UTC time, a trusted edge request ID, resource or object ID, representation variant and content encoding, and a pseudonymous authenticated principal or download session where available. Correlate source IP and User-Agent as context. One address or UA can describe many unrelated clients.
- Record `Range` and `If-Range`, status, response ETag and `Content-Range`, any body byte counter, completion or abort indicator, cache outcome, and the edge-to-origin correlation ID if a request went upstream. Drop credentials, authorization headers, cookies and signed URL parameters from the investigation export.
- NGINX examples of field sources are `$http_range`, `$http_if_range`, `$sent_http_content_range`, `$sent_http_etag`, `$body_bytes_sent` and `$request_completion`. The access log format must explicitly include the required fields. The completion variable indicates request completion as observed by NGINX. Confirm the byte and completion semantics on the deployed version and protocol with a known complete transfer and a controlled interruption.
- For single-part ranges, group by authorized download context, resource, variant, coding and strong validator. Compare the interval size with measured body bytes and retain both raw bytes and distinct coverage. An absent field, changed object revision, missing telemetry or interrupted transfer may leave the result uncertain. For multipart, retain per-part evidence when available. A header-only capture cannot reconstruct the body part intervals.

**Triage pattern.** High range volume can come from ordinary seeking, retries or a new client release. Range processing can also be abused to consume disproportionate resources. Review request rate alongside range patterns, error rate and edge/origin latency or resource cost under the same time window and route. When investigating possible unauthorized retrieval, join the authenticated principal, authorization decision, resource sensitivity and viewer-facing evidence. A pattern or a single status code cannot establish an incident or its actor.

**Response.** Preserve the raw edge, origin and authorization records and document known coverage gaps. Confirm the intended customer behavior with the service owner. For resource pressure, review configured request limits and cache behavior with the operator, then verify normal playback and resume behavior after any approved change. For suspected exposure, contain access with the owner and preserve the affected object version and identities. State whether evidence shows a request, an edge send, unique coverage, or client validation.

## 4. Practice with offline evidence

Use an approved workstation or training VM with Python 3.8 or later. Download the <a href="{{ '/assets/labs/http-range-evidence.py' | relative_url }}" download="http-range-evidence.py">coverage script</a> and the <a href="{{ '/assets/labs/http-range-evidence.json' | relative_url }}" download="http-range-evidence.json">synthetic evidence</a> to the same directory. The script reads local JSON only. Each scenario represents a single resource and client session at the viewer-facing hop. Run:

```bash
python3 http-range-evidence.py http-range-evidence.json
```

| Scenario | Expected observed coverage |
| --- | --- |
| `overlap_complete` | 1,100 body bytes across eligible rows, 1,000 distinct bytes |
| `gap` | 800 of 1,000 distinct bytes despite two completed 206s |
| `version_switch` | `"r1"` covers 400, `"r2"` covers 600. Keep the two groups separate |
| `interrupted` | Second row is incomplete. 400 bytes qualify and 200 observed bytes in the short row remain outside the coverage calculation |
| `weak_etag` | No verified group for the stored partials |
| `full_fallback` | Report 200 separately. The earlier 206 covers 400 bytes of the earlier version |
| `unsatisfied` | Report 416 separately. Its error body adds no representation coverage |
| `different_encoding` | Identity and gzip rows stay separate even when their test ETag strings match |

If Python cannot open the JSON file, check that both filenames are in the working directory. If a row is excluded, check its status, ETag, range bounds, completion and observed count. To test your understanding, alter a copy of the `gap` case so the second completed range starts at 400 and ends at 999 with a measured 600 bytes. It should report full observed coverage. The published examples were run against synthetic files. CloudFront and NGINX behavior was reviewed in official documentation.

## 5. Check your understanding

1. **Why is a sum of 1,100 bytes plausible for a 1,000-byte file?** Retries or overlapping responses can transmit an offset more than once. Compute the union of eligible ranges.
2. **Can the first half with ETag `"r1"` and the second half with `"r2"` establish one complete version?** Track them separately. The shared URL and equal total length do not establish byte identity.
3. **What would show the download was saved successfully?** Seek client-side completion, a size check and a trusted digest when available. Viewer-facing server logs establish observations from the sender's vantage point.
4. **What does a 416 with a small nonzero byte counter show?** An error response may have a body. Its bytes do not belong to the requested file.

Completion criterion: calculate the union for the normal trace, explain why the version-change and interrupted cases cannot establish full coverage, and name the additional evidence needed for client validation and authorization.

## Official references and next steps

Reviewed November 23, 2026. The IETF standards below were published in June 2022. Product notes describe the NGINX and CloudFront online documentation reviewed on that date.

- [RFC 9110 §13.1.5, 14, 15.3.7 and 15.5.17](https://www.rfc-editor.org/rfc/rfc9110.html#section-14) covers conditional ranges, byte offsets and status codes.
- [RFC 9111 §§3.3–3.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-3.3) covers partial responses and strong-validator requirements for caches.
- [CloudFront Range GET documentation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RangeGETs.html) describes behavior across the viewer and origin hops.
- [NGINX access logging](https://nginx.org/en/docs/http/ngx_http_log_module.html) and [HTTP variables](https://nginx.org/en/docs/http/ngx_http_core_module.html#variables) describe the proposed collection fields.

[Previous · HTTP requests and responses]({{ '/wiki/http-evidence/' | relative_url }}) · [Next · HTTP cache investigation]({{ '/wiki/http-cache-evidence/' | relative_url }})
