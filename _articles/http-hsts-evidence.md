---
title: "HTTP Strict Transport Security · Trace an HSTS Upgrade"
description: "Distinguish browser policy from an HTTP redirect and verify where HSTS applies, expires, or survives a rollback."
category: network
tags: [HTTP, TLS, HSTS, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/http-hsts-evidence/
---

One browser goes straight to HTTPS. Another gets a 301 before it reaches the same page. Both can show the same final URL, but they leave different evidence. Follow the steps below to tell when HTTP was actually sent, when the browser learned a policy, and when a later failure can occur before the application receives a request.

## 1. Three ways a URL ends up on HTTPS

**HTTP Strict Transport Security (HSTS)** is a policy a compatible client can learn from a valid `Strict-Transport-Security` response header received over HTTPS without secure-transport errors. The browser stores dynamic policy by DNS hostname. For a hostname covered by active HSTS, the client upgrades an HTTP URL before sending that HTTP request. If TLS validation then fails, the HSTS client terminates the connection. A literal IP address is outside the RFC's HSTS hostname model.

| Mechanism | Who acts and when | Evidence to look for |
| --- | --- | --- |
| Server HTTP redirect | The edge or server receives plaintext HTTP and sends a 3xx with `Location` | Plaintext request and response at the serving hop |
| Learned HSTS | A compatible client applies a previously stored policy before sending HTTP | Earlier valid HTTPS response, policy scope and timing, and client-side upgrade evidence |
| Preloaded HSTS | A supporting browser applies a rule shipped with its software | Browser family and version, vendor list or browser policy evidence |
| HTTPS-first or HTTPS-only setting | The client tries or requires HTTPS according to its own settings | Browser configuration, trace and version |

A 3xx is a response to a request that already reached a server. A client-side transition can be represented as an internal redirect in developer tools. Correlate the network trace and edge logs before calling it a server response.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http-hsts-evidence-en.svg' | relative_url }}" alt="For an HTTP URL, an active HSTS match upgrades it in the client before transmission. Without an HSTS match, a server can redirect after receiving HTTP if no other browser upgrade applies. Both paths can then reach HTTPS.">
  <figcaption>The HSTS decision and the network redirect occur at different points. Other browser upgrade mechanisms are omitted from this diagram.</figcaption>
</figure>

## 2. Follow a normal policy through time

Suppose a test browser visits `http://learn.example.test/` at time 0, has no prior policy, has no applicable preload entry, and has no other upgrade mechanism enabled. The HTTP edge replies with a 301 pointing to `https://learn.example.test/`. After the client connects with valid TLS, it receives:

```http
Strict-Transport-Security: max-age=300; includeSubDomains
```

- `max-age` is the lifetime in seconds from receipt. A later valid header from the same host can refresh the expiry and replace the subdomain setting. Absence of the header in a later response does not erase an existing entry. An HSTS header received over plaintext HTTP is ignored.
- At time 60, the browser turns `http://media.learn.example.test:80/` into `https://media.learn.example.test:443/` before sending HTTP because of the parent's `includeSubDomains`. An explicit port other than 80 is preserved when upgrading. A sibling such as `other.example.test` is outside that parent policy.
- At time 120, the child receives a valid HTTPS header with `max-age=0`. This removes that child's own learned entry, if any. The parent entry still applies while active. If the parent entry expires without a refresh, the child loses that inherited coverage. A separate child entry or installed preload policy needs its own evaluation.
- Preloading can cover first contact on supported clients. A `preload` token alone does not prove inclusion in a deployed list. The Chromium project documents a separate submission and removal process. Rollbacks must account for installed releases even after a header changes.

These times, names and responses are illustrative. They are separate from production observations.

## 3. Assess failures, collect evidence and respond

Plain HTTP on an initial visit can be intercepted or modified before the client sees a redirect. An active HSTS policy avoids sending that plaintext request for a covered hostname. HSTS does not fix expired or mismatched certificates, authorize an HTTP action, or secure content separately from TLS. If a deployment applies `includeSubDomains` to a parent with HTTP-only descendants, browsers may fail to reach them. The failure can occur in TLS before an application request exists.

1. **Observe the client and the serving edge.** Record UTC time, browser family and version, profile state (fresh or previously used), initial URL scheme and port, the request scheme actually sent, TLS validation result, and whether the client reported an internal upgrade. Collect sanitized browser traces or equivalent endpoint evidence. Join with edge redirect records or HTTPS response headers at the viewer-facing hop. Origin logs can miss redirects generated at the edge.
2. **Check policy by hostname and time.** Record the observed header, response status and serving hop, entries that can apply from parent names, expiry timing, and whether preload or a browser setting is in scope. Test a clean profile and one that has learned the policy, under equivalent client settings. A fresh profile can still have a browser preload list. A header captured at one edge proves only what that hop delivered for the request tested.
3. **Compare customary and unexpected behavior.** Alert on an unintended loss or change of the HTTPS response header after a deployment, or plaintext requests to a host expected to be covered. Use planned endpoint probes and inspect scheme and status. Correlate changes with edge configuration, certificates and browser traces. A plaintext request alone can come from a new profile, a client that ignores HSTS, a previously expired entry or an uncovered hostname.
4. **Respond with the edge and application owners.** Preserve original response and client evidence. Restore valid TLS first when a covered hostname has a certificate problem. Inventory descendant hosts before expanding subdomain coverage. For an approved rollback, distinguish a learned entry's expiry or valid `max-age=0` response from a parent rule or browser preload. Recheck allowed HTTPS access and expected coverage on affected clients.

On an approved endpoint or an equivalent staging route, inspect the server's first response on each scheme. Substitute a hostname you own and have permission to test. The example host below is fictional. These commands use GET without following redirects, discard bodies, and leave certificate validation enabled.

```bash
curl -q -sS -D - -o /dev/null http://learn.example.test/
curl -q -sS -D - -o /dev/null https://learn.example.test/
```

Compare the HTTP status and `Location` with the HTTPS response and its `Strict-Transport-Security` value. HTTP need not be listening for HSTS to work for a covered client. A network or TLS error can prevent obtaining a header. These commands were reviewed against the curl documentation. They measure a server response and do not reproduce a browser's cache, preload decision, or HTTPS-first behavior.

## 4. Run the offline model

Save the <a href="{{ '/assets/labs/http-hsts-evidence.py' | relative_url }}" download="http-hsts-evidence.py">policy script</a> and <a href="{{ '/assets/labs/http-hsts-evidence.json' | relative_url }}" download="http-hsts-evidence.json">fictional events</a> in an approved workspace. Run with Python 3.8 or newer:

```bash
python3 http-hsts-evidence.py http-hsts-evidence.json
```

Each case starts with an empty profile. Input rows already describe parsed header directives and whether HTTPS was valid. The model evaluates dynamic entries for lowercase sample DNS names and tracks expiry, inheritance, and explicit ports. It has no network access. It does not parse headers, simulate TLS, model preloaded lists or implement another browser upgrade mode. `no_hsts` means only that this dynamic model found no matching policy.

| Case | Expected modeled result |
| --- | --- |
| `first_and_later` | First URL has no policy. After a valid HTTPS header, the covered URL upgrades |
| `plaintext_header` | Header received over plaintext is ignored |
| `invalid_tls` | Header received with TLS errors is ignored |
| `expiry` | Policy covers the name at 99 seconds and expires at 100 |
| `child_removal` | Child's own policy is removed. The parent still covers it and port 80 becomes 443 |
| `port_preserved` | An explicitly supplied non-80 port stays unchanged |
| `no_subdomains` | Parent policy without `includeSubDomains` does not cover the child |
| `refresh` | A later valid header extends policy life |

If the script cannot read the input, confirm both filenames and directory. If an outcome surprises you, check the order of the events, receipt times, and whether a parent has an active policy. Try changing the parent's `include_subdomains` value in `child_removal` to false. After removal of the child's policy, the model should print `no_hsts`. The fictional cases were executed offline. A real browser preload list and deployed edge policy were not exercised by this lab.

## 5. Check your understanding

1. **What proves a 301 came from a server?** A recorded HTTP request and corresponding 301 at the client-facing hop support that conclusion. An internal transition in developer tools alone does not.
2. **Can an HTTP response teach a client HSTS?** A compatible client learns the dynamic policy only over error-free secure transport with a valid header.
3. **Why can a child still upgrade after receiving `max-age=0`?** The child changes only its own learned entry. Check an active parent entry with `includeSubDomains` or a preload rule.
4. **Why might an app log show nothing after an upgrade?** The client may fail TLS validation before sending any HTTP request over the secure connection.

Complete the chapter when you can account for the first and later requests, predict a descendant's coverage from host and time, and name the separate browser, TLS and edge evidence needed to investigate an outage.

## Official references and next steps

Reviewed November 23, 2026. RFC 6797 was published in 2012. The browser references describe Chromium's documented behavior and preload process at review time. Browser family, version and settings can affect the observed result.

- [IETF · RFC 6797, user agent processing](https://www.rfc-editor.org/rfc/rfc6797.html#section-8)
- [Chromium · HTTP Strict Transport Security](https://www.chromium.org/hsts/) and [Chrome preload submission and removal](https://hstspreload.org/)
- [curl command-line manual](https://curl.se/docs/manpage.html)

[Previous · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) · [Next · HTTP proxy response evidence]({{ '/wiki/http-proxy-response-evidence/' | relative_url }})
