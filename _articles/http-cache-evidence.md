---
title: "Investigate HTTP Caches: Freshness, Variants, and Revalidation"
description: "Read Age, Vary, ETag, and Cache-Status, trace 200 and 304 across layers, and distinguish normal reuse from an unsafe shared response."
category: network
tags: [HTTP, HTTP Caching, CDN, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/http-cache-evidence/
---

A browser displays a response, but the application owner cannot find that request in the origin access log. A cache can explain this. First identify the layer that returned the response, then ask whether its reuse was expected and which clients could see the stored content.

## 1. Where a response can be reused

The **origin** is the server responsible for the resource. A **private cache** is dedicated to a single user, such as a browser's HTTP cache. A **shared cache** can reuse responses for multiple users, such as a CDN edge. A **cache key** identifies a stored response candidate. The HTTP model uses at least the request method and target URI. A deployment may add dimensions through its cache rules.

A **representation** is the content and associated metadata selected for a request. The same URL might have separate English and Korean representations. A **validator** such as an `ETag` identifies a representation version for conditional requests. Tags are opaque to clients. Some are weak (prefixed by `W/`) and may compare as equivalent even if bytes differ.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http-cache-evidence-en.svg' | relative_url }}" alt="The client asks an edge cache for a response. A fresh eligible variant can be reused at the edge. Otherwise the edge may forward the request to an upstream server. A 304 can validate stored content, while a 200 can carry replacement content.">
  <figcaption>Follow each request hop. A downstream 200 can coexist with an upstream 304.</figcaption>
</figure>

| Evidence | What to look for | Interpretation limit |
| --- | --- | --- |
| `Cache-Control` | Rules for storage and reuse on the request or response | Read direction, cache type, and actual configuration. |
| `Age` and `Date` | Cache's estimated age in seconds and message origination date | Age is not a timestamp or proof of residence in a specific edge. Missing Age cannot establish an origin request. |
| `Vary` | Request header dimensions that influence response selection | Compare the named request headers at the observed hop. `Vary: *` never matches as an ordinary stored variant. |
| `ETag` / `If-None-Match` | Validator supplied by the sender and conditional request value | Use the selected representation and HTTP comparison rules. A tag is not automatically a trusted content hash. |
| `Cache-Status` | Optional report of how individual caches handled the request | Members run from closest to origin to closest to user. Check who inserted the field and corroborate with operator logs. |

## 2. Decide whether a response can be used

**Freshness** is about eligibility to reuse a stored response without validation. It is not the age of the file on disk. Compare the response's current age with its freshness lifetime. Once freshness expires, revalidate or fetch again unless serving stale is permitted under the applicable rules. A cache can be configured to serve stale in limited situations.

| Response directive | Practical effect |
| --- | --- |
| `max-age=60` | Supplies a 60-second freshness lifetime under the applicable policy. |
| `s-maxage=120` | Supplies the shared-cache lifetime and overrides `max-age` there. Private caches use the other applicable directives. |
| `no-cache` without an argument | Storage can be permitted. Reuse requires successful validation. |
| `no-store` | Directs caches to avoid storing the immediate request or response. It does not purge pre-existing copies. |
| `private` without an argument | Prevents ordinary shared-cache storage. Private caching can still be allowed. |
| `public` | Explicitly permits shared caching when other requirements are met. Check that the whole response is safe for the intended audience. |

For requests carrying `Authorization`, RFC 9111 restricts shared reuse unless a response directive explicitly permits it and the cache satisfies its requirements. Examples include `public`, `s-maxage`, or `must-revalidate` under the applicable conditions. Cookie-based sessions are a separate case. `Set-Cookie` alone does not prevent caching in the HTTP standard. Verify product overrides and apply explicit policy to personalized content.

## 3. Follow a normal response across hops

In the synthetic scenario the public page `/notice` has `Vary: Accept-Language`. Its response says `public, max-age=60, s-maxage=120`. The edge reports `Cache-Status: edge; hit; ttl=100` and `Age: 20`. That is consistent with the shared lifetime and an edge hit. If the recorded request language differs from the one stored, confirm variant selection. A French-language request with no matching variant could be forwarded, which is what `fwd=vary-miss` reports in case H03.

Later the edge sends a conditional GET to its upstream using the validator for the matching stored variant. If the representation is unchanged, the upstream can return **304 Not Modified**, with headers and no body. A browser that sent its own condition may receive a 304 and reuse its body. If the browser sent an ordinary GET and the edge revalidated its own stored response, the edge may send a full **200** using the validated body. An origin access log with 304 and an edge access log with 200 can therefore describe the same request chain.

Separate the standard from vendor fields. For example, Cloudflare documents `CF-Cache-Status` values including `HIT`, `MISS`, `BYPASS` and `REVALIDATED`. Those labels describe its processing. A `MISS` at one layer alone cannot tell you what an upstream cache did. Use the provider's definitions and actual configuration for the investigated time.

## 4. Investigate suspicious reuse

An unsafe cache policy can reuse content across users or tenants when the response's intended audience is narrower than the cache's reuse scope. A public landing page hit is ordinary. A confirmed shared hit containing genuinely account-specific material deserves review. Compare with approved synthetic test accounts or existing authorized evidence. A hit marker or a different language variant alone does not establish data exposure.

1. **Preserve the chain.** Record UTC times, request method, normalized route, hostname, status codes, request IDs, cache node or region, cache status, validators and policy. Retain relevant request header values named by `Vary`. Preserve cache settings and application change revisions. Restrict access to captures and redact credentials, cookies and personal data from working exports as needed.
2. **Separate edge from upstream.** Correlate request IDs when propagated and use timing plus route where IDs differ. Inspect client and edge logs, the reported upstream status, and origin logging coverage. If the browser used a private cache or a service worker, verify which layer produced the visible response. A missing origin entry can be expected during a fresh hit or can reflect logging gaps.
3. **Check the expected audience.** Compare identity-bound and public routes, effective cache-key dimensions and variant headers. Validate policy with harmless fixture responses and approved scope. Separate a confirmed cross-user response from a route that only appears risky. Review rule changes and deployments before attributing intent.
4. **Respond with the service owner.** Preserve affected time ranges, policy versions, and evidence of reach before approved containment. Fix unsafe shared reuse, coordinate invalidation of the affected entries where appropriate, and rerun positive and negative controls. A current bypass or corrected header does not establish the absence of earlier exposure. Investigate historical response delivery separately.

## 5. Offline exercise and actual loopback validation

Save the [synthetic traces]({{ '/assets/labs/http-cache-cases.json' | relative_url }}) and [Python exercise]({{ '/assets/labs/http-cache-review.py' | relative_url }}) together. Python 3 and permission to bind loopback are needed. The script interprets fixed evidence labels, then starts a tiny HTTP origin on `127.0.0.1` on an automatically chosen port, sends three requests, and shuts down. It does not contact a real cache or CDN. The origin implements the two fixed lab languages and test validator, not general HTTP negotiation.

1. For each row, identify the observed layer and whether an upstream result is visible. The `scope` and `vary_matches` values are analyst context for the worksheet.
2. Run the script and compare the six trace results and real loopback responses.

```bash
python3 http-cache-review.py
```

| Case | Expected interpretation |
| --- | --- |
| `H01` / `H02` | Edge reuse / upstream 304 with downstream 200. |
| `H03` / `H04` | No matching stored variant / cache path unknown. |
| `H05` / `H06` | Shared hit on a personalized response needs review / this edge bypassed the current request. |
| Loopback | English 200 with a body and ETag, conditional English 304 without a body, and Korean 200 with a distinct tag when given the English tag. |

If the worksheet is missing, check both filenames and the directory. If binding loopback is prohibited, the six offline checks finish before the binding error. Use those results and read the expected HTTP sequence. If testing outside the script, keep the loopback origin and preserve the exact headers. A request for another representation does not validate the English body with its English tag.

**Verification scope.** All six synthetic checks and three actual loopback requests ran successfully. CDN behavior was reviewed in official documentation. The lab did not execute a browser or commercial CDN cache.

## 6. Check your understanding

1. **The server returned 304. Was new content transferred?** A 304 has no message content. Look at the stored response and which hop performed the validation.
2. **Why can two requests to one URL return different languages?** The origin selects a representation. When an applicable `Vary` field names the language header, a cache must match that dimension before ordinary reuse.
3. **Can a missing `Age` prove the origin produced the response?** No. Use cache and upstream logs to establish the path.
4. **Does a bypass after a repair prove nobody previously received a shared response?** It supports current behavior at the reported edge. Historical exposure requires older delivery evidence.

**Completion criteria.** Explain the six traces and the three real HTTP responses. Write a short finding that separates observed reuse, intended audience, and the next evidence needed to assess exposure.

## 7. Official references and next steps

Reviewed **2026-11-21**. The IETF specifications below were published in **June 2022**. RFC 9111 supersedes RFC 7234. Provider-specific definitions reflect Cloudflare's documentation updated **2026-09-04**.

- Freshness, validation, authenticated requests and privacy. [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html)
- Representation selection, conditional requests and response semantics. [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
- Standard cache status and vendor-specific fields. [RFC 9211](https://www.rfc-editor.org/rfc/rfc9211.html) · [Cloudflare cache responses](https://developers.cloudflare.com/cache/concepts/cache-responses/)

Previous · [HTTP Evidence]({{ '/wiki/http-evidence/' | relative_url }})  
Next · [Network Monitoring]({{ '/wiki/network-monitoring/' | relative_url }})
