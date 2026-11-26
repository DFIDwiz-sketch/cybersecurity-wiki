---
title: "HTTP Rate Limiting · Find the Source of a 429"
description: "Correlate gateway and origin evidence, read Retry-After safely, and verify the difference in a loopback exercise."
category: network
tags: [HTTP, API Security, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/http-rate-limit-evidence/
---

A client reports HTTP 429 during a busy release. The same status might come from a gateway policy, an origin quota or a service downstream of the origin. Start with the request that failed. Identify the layer that produced the response before deciding whose limit was reached or changing the policy.

## 1. Read the outcome and the policy separately

A **rate limit** controls activity over time. A **quota** may limit consumption over a broader interval. A **burst limit** can restrict short spikes even when the average rate is low. A policy can count by tenant, route, client identity, account, or another key. RFC 6585 assigns 429 to excessive requests and permits a `Retry-After` field. It leaves the identity and counting methods to the implementation. Its rules prohibit caches from storing 429 responses. A cached policy decision inside a limiter is a separate mechanism.

| Observation | What it supports | Evidence still needed |
| --- | --- | --- |
| 429 at the client | Client-visible rate limiting outcome | Producing hop, policy key, scope, conditions and rule decision |
| 429 with edge rejection and no upstream attempt | The edge enforced the recorded decision for this request | Policy revision and the reason this request matched |
| Client 429 with a matching upstream 429 | The upstream hop returned 429 to the proxy | Whether the upstream generated it or relayed it from a dependency |
| 503 with `Retry-After` | A service-unavailable response with retry guidance | Capacity, maintenance or upstream evidence. The header alone does not identify a quota |
| Missing or invalid `Retry-After` | The client has no usable timing guidance from that field | Its configured backoff, timeout and retry budget |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http-rate-limit-evidence-en.svg' | relative_url }}" alt="The client sends a request to a gateway. The gateway can reject it with 429 before contacting the origin, or forward it and relay an origin response. A matching request ID and upstream attempt help distinguish the paths." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. The same client-facing 429 can follow two different paths.</figcaption>
</figure>

## 2. Follow a normal call and two throttled calls

In a fictional tenant called Lab A, a read-only GET for inventory arrives at the gateway at 10:00:00 UTC. The gateway forwards it, the origin returns 200, and both layers log a linkable request ID. One minute later a request receives 429 and `Retry-After: 30`. The gateway log has a local rate-limit decision and an explicit upstream-attempt value of false. This supports a gateway rejection for that request. If the same field instead says the gateway contacted the origin, match the peer's request record and verify the upstream status before attributing the 429.

Thirty seconds is a delay relative to receipt of the response. `Retry-After` can also carry an absolute HTTP date. If it says `Fri, 27 Nov 2026 10:02:30 GMT` and the client's wall clock is 10:02:00 UTC, the estimated remaining wait is 30 seconds. Preserve the response's `Date` and both clocks' known uncertainty when diagnosing disagreement. A past date leaves no positive wait from the field. It does not remove the application's retry policy. Treat repeated or malformed values as unusable unless your client has a documented handling rule.

## 3. Test competing explanations

Bulk operations, a release, scheduled clients firing together, a shared NAT address and retry storms can create 429s. Some automated abuse also produces repeated bursts or targets expensive routes. A response code, shared address or User-Agent alone does not establish an attacker. Compare request rates, tenant scopes, request mix and release history. A caller can trigger an application limit while the gateway stays well within its own control.

A client can worsen overload by retrying immediately. For an approved client, respect valid retry guidance and apply bounded backoff, jitter and a retry budget. Keep overall deadlines in mind. Automatic retries of non-idempotent writes require evidence that the original was not applied or an application contract that makes repetition safe. A lost response and a confirmed rejection are distinct observations. Do not assume a write is replay-safe because the status resembles a transient failure.

## 4. Collect, detect and respond

1. **Preserve the failing request at each boundary.** Record UTC time, method, route, tenant or policy scope, status, `Retry-After`, `Date`, client-facing and upstream request IDs, and the observed transport. Keep identifiers from trusted logs. Strip credentials, cookie values and request bodies from shared evidence. ID and forwarded-source fields supplied by a client need validation against your trusted infrastructure.
2. **Prove the producing hop.** Correlate gateway decision, policy version, count or budget if available, upstream attempt, upstream status and origin event. A null upstream field can reflect logging gaps. Establish an affirmative local decision and an explicit absence of an upstream attempt when available. Where retries occur at a proxy, retain the sequence of attempts instead of just the final status.
3. **Measure by policy scope.** Track throttled count and ratio with the total request denominator for the same scope, method and route. Separate origin and edge decisions. Check legitimate burst size and retry amplification. For example, AWS API Gateway documents regional account rate and burst targets and route controls for HTTP APIs, with best-effort throttling. Use the active deployment and vendor documentation to interpret the policy instead of treating one 429 as a threshold measurement.
4. **Verify a narrow correction.** Identify whether the policy is protecting a dependency, the client should slow down, or the wrong grouping key was used. If an adjustment is approved, test the smallest scope with a known client and confirm accepted traffic, expected throttles and upstream health. Preserve before and after samples.

## 5. Authorized loopback exercise

Download the <a href="{{ '/assets/labs/http-rate-limit-evidence.py' | relative_url }}" download>Python exercise</a> and run it with Python 3 in your own or approved environment. It listens only on `127.0.0.1` using two ephemeral ports for a gateway and an origin. The client sends seven one-off GETs without retries. Routes deterministically simulate outcomes rather than measuring actual limit capacity. The gateway output and the origin observations are compared by request ID. The clock for the header tests is fixed.

~~~bash
python3 http-rate-limit-evidence.py
~~~

| Route | Expected observation |
| --- | --- |
| `/ok` | 200, matched at origin |
| `/edge` | Gateway 429, no origin match, delay of 30 seconds |
| `/origin` | Relayed 429 with origin match and delay of 45 seconds |
| `/maintenance` | Relayed 503 with an absolute date corresponding to 90 seconds |
| `/missing`, `/invalid`, `/repeat` | Missing, malformed and repeated timing fields remain distinct and supply no usable wait |

Expect `7/7 observations matched.` Try `--negative-control`, which changes only the gateway's delay on `/edge` to 31 seconds. The program should exit 1 and report a mismatch for that case. If the baseline fails at startup, check whether your approved execution environment allows local loopback sockets. The lab exercises actual loopback HTTP, with fictional policies and no external service. Provider behavior was reviewed in official documentation without testing a managed gateway.

## 6. Check your reasoning

1. **Two gateways return 429. Did they enforce the same limit?** The status identifies an outcome. Compare the actual rule, key, route and scope at each producing layer.
2. **Does the same `Retry-After` make 429 and 503 equivalent?** It only supplies timing guidance. The statuses support different hypotheses, and the producing hop still matters.
3. **Can a failed client-side write be replayed automatically?** Establish whether repeating it is safe from the operation's contract or evidence about the first attempt.
4. **How can a retry storm be distinguished from an initial traffic surge?** Compare request IDs or documented linkage, original and retry timestamps, and repeated calls by the same logical client or job.

**Completion criterion.** Reproduce the seven observations and the negative control. For one 429, name the producing hop, the decision evidence, and the next action for the client or service owner. Continue with [HTTP evidence]({{ '/wiki/http-evidence/' | relative_url }}) and [reverse proxy response evidence]({{ '/wiki/http-proxy-response-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-27. RFC 6585 is from April 2012. RFC 9110 is from June 2022. The provider example concerns AWS API Gateway HTTP APIs in the reviewed guide. The IETF `RateLimit` and `RateLimit-Policy` work was still an Internet-Draft in revision 12, published 2026-11-20. Check the deployed product before assuming any quota-header format.

- [RFC 6585 § 4 · 429 Too Many Requests](https://datatracker.ietf.org/doc/html/rfc6585#section-4)
- [RFC 9110 · Retry-After](https://datatracker.ietf.org/doc/html/rfc9110#section-10.2.3), [503](https://datatracker.ietf.org/doc/html/rfc9110#section-15.6.4) and [idempotent methods](https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.2)
- [AWS API Gateway HTTP API throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-throttling.html)
- [IETF HTTPAPI · RateLimit draft revision 12, work in progress](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers-12)
