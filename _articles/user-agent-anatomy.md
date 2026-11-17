---
title: "User-Agent anatomy and token meanings"
description: "Decode Mozilla, WebKit, Gecko, browser and platform claims, UA Reduction and Client Hints without over-interpreting them."
category: "network"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/ko/wiki/user-agent-anatomy/"
user_agent_series: true
---
{% include ua-series.html %}

## 1. Locate the request header

```http
GET /guide HTTP/1.1
Host: portal.example
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0
Accept: text/html
```

This is an illustrative request with a reserved example hostname and illustrative versions. The header name is User-Agent; its value follows the colon. HTTP field names are case-insensitive, so HTTP/2's lowercase name refers to the same field. Preserve the value's original case and spacing for evidence and explicit matching semantics.

The standard permits product names, optional versions and comments. Multiple products may appear. A short custom value such as `CustomHealthCheck/1.0` can be legitimate; a long Mozilla-style value is not mandatory. Clients can also be configured not to send the header.

## 2. Decode the individual tokens

| Token | Meaning | Avoid this conclusion |
| --- | --- | --- |
| `Mozilla/5.0` | Historical compatibility claim | Firefox is installed, version 5 |
| `Windows NT 10.0` | Windows platform claim | Cannot be Windows 11 |
| `Win64; x64` | 64-bit platform-related claim | Verified process architecture |
| `WOW64` | Historically associated with 32-bit execution on 64-bit Windows | Inherently malicious |
| `AppleWebKit/537.36` | WebKit lineage/compatibility marker, also present in Chromium | Apple hardware or the current WebKit release |
| `KHTML, like Gecko` | Historical compatibility comment | Actual Gecko engine proven |
| `Chrome/140.0.0.0` | Chromium product/compatibility version token | Request necessarily came from Chrome |
| `Safari/537.36` | Safari compatibility marker | Safari application version 537.36 |
| `Edg/140.0.0.0` | Chromium-based desktop Edge token | Ignore it because Chrome appears earlier |

Prefer specific product markers over the first familiar word. The example claims to be Edge. A custom program can generate the identical header, so corroborate with endpoint evidence.

## 3. Other browser and operating-system formats

Firefox uses `rv:` for Gecko-related version information. `Gecko/20100101` is commonly a fixed compatibility date, not a 2010 installation date. Safari's `Version/` and `Safari/` numbers have different roles; Version is the more direct application-version clue. CriOS, FxiOS and EdgiOS identify iOS products; engine availability and platform policy require separate version/region checks.

You may encounter X11, Linux x86_64, Macintosh, Intel Mac OS X, Android, iPhone and CPU iPhone OS. These remain claims. Language tokens such as en-US do not establish location or nationality. The historical U marker is not a user account. Mobile does not authenticate a physical phone: web views, desktop modes and spoofing complicate interpretation.

## 4. UA Reduction changes version analysis

Supporting Chromium browsers reduce some platform and version detail to limit fingerprinting. Zeros in patch components, an Android 10 / K shape or a fixed macOS representation may be intentional reduction. Do not automatically classify them as outdated systems or malware.

Both Windows 10 and Windows 11 can report Windows NT 10.0. Confirm precise OS and architecture using managed inventory or host collection. A major version that remains fixed over time is worth investigating, but enterprise update policies, embedded applications and legacy software are alternative explanations. Old version numbers alone are insufficient.

## 5. User-Agent Client Hints

```http
Sec-CH-UA: "Chromium";v="140", "Microsoft Edge";v="140", "Not_A Brand";v="99"
Sec-CH-UA-Mobile: ?0
Sec-CH-UA-Platform: "Windows"
```

Illustrative values: Sec-CH-UA supplies brands/versions; ?0 means false and ?1 means true for the mobile hint. Servers can request additional hints through Accept-CH, subject to support and policy. An odd brand can be a GREASE value intended to prevent brittle brand-list parsing.

UA-CH disagreement with the UA is a clue, not cryptographic identity proof. Non-browser clients can construct similar headers. Missing hints may reflect browser support, policy or intermediaries. Do not treat their absence as maliciousness.

## 6. Related fields are different evidence

| Field | What it describes | Limitation |
| --- | --- | --- |
| HTTP UA | Client's self-description | Can be changed or omitted |
| Server | HTTP response software claim | Can be hidden or changed |
| TLS SNI | Server-name information in TLS | Not a UA; ECH can conceal it |
| JA3 / JA4 | Derived protocol characteristics | Shared, mutable and subject to collisions; not user identity |
| navigator.userAgent | Browser JavaScript observation | Different collection point from proxy headers |
| Email User-Agent / X-Mailer | Some email-client message headers | HTTP UA rules cannot simply be transplanted |

## Check your understanding

Chrome plus Safari plus Edg claims Edge, but the process is unverified. Gecko/20100101 need not identify an old browser. Windows NT 10.0 cannot reliably distinguish Windows 10 from 11. Encrypted TLS traffic alone generally does not reveal the HTTP UA.

## Sources

[HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-user-agent) · [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent) · [UA Reduction](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/User-agent_reduction) · [Windows 11 guidance](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/how-to-detect-win11) · [Chrome Client Hints and GREASE](https://developer.chrome.com/docs/privacy-security/user-agent-client-hints)

{% include ua-series.html %}
