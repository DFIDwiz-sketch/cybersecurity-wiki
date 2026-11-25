---
title: "JWT Key Rotation Evidence · Trace a JWKS Cache Miss"
description: "Distinguish normal signing-key rollover, an unavailable key set, signature failure and token-policy rejection."
category: cloud
tags: [JWT, JWKS, OAuth, Cloud Security, Blue Team, DFIR]
level: Intermediate
updated: "2026-11-26"
translation_url: /ko/wiki/jwt-key-rotation-evidence/
---

**Learning goal.** An API starts rejecting requests during a signing-key rotation. Determine whether the verifier missed the new public key, could not refresh, failed cryptographic verification or rejected the token under its own access policy.

## 1. What a verifier has to establish

A signed **JWT** carries claims, such as who issued it and which service it targets. In a compact **JWS** the protected header, payload and signature are encoded separately. The **issuer** holds signing authority. With asymmetric signing it uses a private key. The API **verifier** uses trusted public keys to check the signature. A **JWK** is a JSON representation of a key, and a **JWKS** is a set of JWKs. In issuer metadata, `jwks_uri` points to the published key set. A verifier can learn that endpoint through the metadata for a preconfigured issuer or have it configured directly.

| Field or control | Why it matters | How to interpret it |
| --- | --- | --- |
| `kid` | Helps select a candidate key during rotation | Compare it within the configured issuer and key set. Identical strings across issuers can identify unrelated keys. |
| `alg` | Declares the signing algorithm | Require an algorithm allowed by local policy and compatible with the key and its intended use. |
| `typ` and token profile | Distinguish credentials with different purposes | Apply the endpoint's explicit validation rules. RFC 9068 defines `at+jwt` for its JWT access token profile. ID tokens have OIDC client validation rules. |
| `iss`, `aud`, `exp` | Identify the issuer, intended recipient and expiration | Compare the exact configured issuer, require the correct audience and evaluate time against the verifier clock and documented tolerance. Also apply required claims such as `nbf` when applicable. |
| Signature result | Checks the signed bytes against the selected trusted key | On success, continue with token-profile and claims checks. Authorization for a particular operation is a separate decision. |

Header and claim values are untrusted input until validated. Where several issuers are supported, an unverified issuer claim can be used only as a lookup hint into a finite trusted configuration, with the validated issuer checked exactly. Keep access-token and ID-token validation rules separate. Use a maintained protocol library and the provider's documented contract. Some access tokens are opaque, and the RFC 9068 type check applies only to deployments using that profile.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/jwt-key-rotation-evidence-en.svg' | relative_url }}" alt="Trusted issuer configuration leads to a cached key lookup. A cache miss can trigger a bounded refresh from the configured JWKS before looking up the key. Verify the signature with a trusted key, then check claims and operation permissions." width="480" height="434">
  <figcaption>A cache refresh can establish key availability. Signature, claims and operation decisions have separate evidence.</figcaption>
</figure>

## 2. Read a normal rollover

A fictional issuer operates the orders API. At 09:00 UTC its trusted JWKS contains `k1`. At 09:15 it publishes `k2` alongside `k1`, then starts signing new tokens with `k2` at 09:20. A replica that refreshed at 09:17 already knows the new key. Another replica still has `k1`, records a miss for `k2`, loads the trusted key set under its configured refresh policy and repeats key selection. It accepts this request after signature and claims validation, then evaluates the requested order operation. Existing tokens using `k1` can still validate during the planned overlap, subject to their claims and authorization. The times are illustrative.

Routine rotation needs a rollout window calibrated to publication, cache propagation, in-flight tokens and their lifetime. OIDC Core describes retaining recently retired public keys for a reasonable interval in a planned rollover. A compromised private key calls for an incident response. Removing its public key from publishing does not immediately purge existing verifier caches. Use the issuer and resource owner's documented controls for distrust, cache refresh and token/session handling, and measure their effect across replicas.

## 3. Explain failures and misuse

| Observation | Plausible explanations | Discriminating evidence |
| --- | --- | --- |
| Unknown `kid`, trusted refresh succeeds and finds it | Routine rotation or a verifier that skipped a scheduled refresh | Issuer deployment record, replica cache generation and later key match |
| Unknown `kid`, refresh stops or fails | Local throttling, upstream error, TLS or network problem | Whether an actual request was sent, its approved endpoint, result and time, plus affected replicas |
| Trusted fresh snapshot still lacks the key | Different issuer or key namespace, retired key, propagation lag or invalid input | Validated configuration per replica, trusted snapshot from the incident window and issuer publication timeline |
| Trusted key matched, signature failed | Input corruption, incompatible or replaced key material or invalid input | Library validation result, configured algorithm and key version or fingerprint linked to that decision |
| Signature valid, policy rejects | Wrong audience, wrong type, expiration or another claim restriction | Validation stage, deployed policy profile and verifier time |
| Unexpectedly high refresh load | Many verifier instances starting, slow metadata service or repeated unknown-key inputs | Refresh attempts per trusted issuer and replica, cache hit rate, deployment and safe failure counts |

An untrusted token may carry key-location headers or an issuer value that points elsewhere. Derive authority from trusted configuration. Key lookup and refresh stay within the issuer's approved metadata and JWKS endpoints. Limit refresh by trusted issuer, share or coalesce concurrent requests where the implementation supports it and bound the wait. An unknown key or failed validation yields a rejection under the verifier policy. An already trusted cached key can still be used only within the documented freshness and incident policy. A burst of unknown-key failures is a signal to investigate and cannot establish who generated the traffic.

## 4. Collect, detect and respond

1. **Record the verifier decision.** With approved application diagnostics, record UTC, request correlation ID, service, replica, deployment version, configured issuer alias, token profile and validation stage. Export implementation status such as cache hit or miss, refresh attempted or suppressed, signature outcome, claims decision and operation outcome. Product names for these fields vary. Label candidate header values as untrusted, cap their length and avoid unbounded dimensions in metrics. Keep bearer tokens, Authorization headers and personal claims out of routine logs.
2. **Reconstruct the key view.** Obtain the cached generation or fetch time from affected replicas if the library exposes it. For authorized provider telemetry or captures, preserve timestamps, status, cache validators and a key-set version or approved fingerprint. An HTTP 304 reuses the prior representation. A current diagnostic fetch cannot reconstruct a lost historical cache. Keep metadata fetch failures separate from JWKS fetch failures. Compare exact issuer configuration and approved URI before joining key observations.
3. **Measure and verify scope.** Group validation results by trusted issuer, audience profile and replica in a documented interval. Compare a known-good verifier with affected replicas. Check the fraction of misses followed by a successful refresh and later key match. Investigate when misses or refresh failures rise above baseline while user failures rise. Before attributing them to key rotation, join a publication or deployment change. Treat authentication and authorization outcomes as separate stages. A generic 401 alone provides too little detail.
4. **Restore the validated path.** Confirm changes with the issuer owner. Correct trusted configuration, rollout timing, clock or metadata reachability as evidence indicates. Follow the provider's supported procedure for refreshing validators. During a compromise, use the designated key-distrust and session or token response, then check acceptance and rejection controls on each relevant replica. Preserve the initial decision and the effect of the mitigation for incident review.

Microsoft's signing-key rollover documentation describes per-tenant key handling and a cache refresh algorithm for the Microsoft identity platform. Use the documented behavior for your library and provider version. Collection of internal cache state requires instrumentation or an exposed diagnostic interface. If the only available records are gateway status codes, retain that limitation in the incident timeline.

## 5. Offline evidence drill

Download <a href="{{ '/assets/labs/jwt-key-rotation-evidence.py' | relative_url }}" download>the Python 3 checker</a> and <a href="{{ '/assets/labs/jwt-key-rotation-evidence-cases.json' | relative_url }}" download>the fictional cases</a> into an approved directory you control. Use the verifier configuration in the JSON and reason through the cases first. Each case describes a normalized validation record. The `signature` field is a synthetic observation supplied by the fixture. The checker reads only the JSON file. It has no token parser, signature code, network calls or platform dependencies beyond Python 3.

```sh
python3 jwt-key-rotation-evidence.py
```

| Cases | What to explain |
| --- | --- |
| A, B | The same key is accepted either directly from a valid cache or following a trusted refresh. |
| C, D, J | The trusted fetch fails, a successful fetch lacks the key, or cooldown suppresses the attempt. Each leaves a different gap. |
| E, F, G, H, M | Issuer, token profile, audience, expiration and algorithm settings can stop acceptance independently of a refresh. |
| I | A candidate key was available, but the recorded signature check failed. |
| K, L | A refresh used the wrong source, or the fixture's single-key policy found an ambiguous identifier. Both stop this drill's decision path. |

The original fixture prints `13/13 JWT evidence cases matched.` For a negative control, copy the JSON, remove `k2` from case B's `refresh.kids` array and pass the copied filename as the script argument. B becomes `key-absent-after-refresh`, the total is 12 of 13 and the exit status is 1. If the original fails to load, check both filenames and JSON syntax. If the altered case still passes, check the argument and the array you edited. The lab assumes one compatible key per matching identifier and a single clock with zero tolerance. Production libraries may resolve multiple compatible candidates differently, order their checks differently and enforce additional claims.

The original and altered fixtures were run in cloud Python. Platform key handling and token-profile rules were reviewed in the referenced documentation. The drill exercises evidence interpretation, with no live issuer, JWT cryptography or resource API call.

## 6. Check your understanding

1. **Only one replica rejects the new key. What distinguishes rollout lag from an issuer publishing failure?** Compare the two replicas' configured issuers, cached key-set versions and refresh outcomes against a trusted publication observation from the same window.
2. **A refresh returns success and the API still rejects the token. Where do you look next?** Confirm the right key was present and selected, then read the signature, token-profile, audience and timing decisions. A key fetch establishes availability at one point.
3. **The same `kid` is in two tenants' sets. Can the verifier use a single global cache keyed by that string?** Scope keys to trusted issuer or tenant and key source. Also compare key identity and usage when the implementation must choose among candidates.
4. **What would establish that an accepted token changed an order?** Join the verifier decision to resource authorization and application or data audit records for the actual operation.

**Completion.** Explain cases B, C, D and J using the cache and refresh evidence. Identify the stage that rejects cases F, G and I. Reproduce both fixture outcomes and name one source needed to confirm a real rotation.

## Official references

Reviewed 2026-11-26. The guide covers asymmetric JWT signing, the RFC 9068 access token profile where adopted and current Microsoft identity platform documentation for the provider-specific example.

- JWT validation, algorithm controls and separation of token rules. [RFC 8725, February 2020](https://www.rfc-editor.org/rfc/rfc8725.html)
- Key identifiers, keys and metadata. [RFC 7517, May 2015](https://www.rfc-editor.org/rfc/rfc7517.html) · [RFC 8414, June 2018](https://www.rfc-editor.org/rfc/rfc8414.html)
- Signed JWT access-token validation at the resource server. [RFC 9068, October 2021](https://www.rfc-editor.org/rfc/rfc9068.html#section-4)
- Planned signing-key rotation and platform cache behavior. [OpenID Connect Core 1.0, §10.1.1](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys) · [Microsoft identity platform signing key rollover](https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover)
- Conditional HTTP responses and cached representations. [RFC 9111, June 2022](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4)

[Previous · OAuth and OIDC evidence]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}) · [Next · Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}) · [Background · Public-key cryptography]({{ '/wiki/public-key-cryptography/' | relative_url }})
