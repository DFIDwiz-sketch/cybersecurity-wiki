---
title: "HTTP Proxy Response Evidence · Find Where the Status Came From"
description: "Compare client-facing status, upstream attempts and application outcomes across a reverse proxy."
category: network
tags: [HTTP, Reverse Proxy, Network Security, Blue Team, DFIR, NGINX]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/http-proxy-response-evidence/
---

**Learning goal.** A browser reports 504. Did the gateway time out, did a backend return a 504, and did the underlying operation complete? Use evidence at each hop to answer these as separate questions. Start with [HTTP request and response evidence]({{ '/wiki/http-evidence/' | relative_url }}) if you are new to HTTP status codes.

## 1. Why status codes need a vantage point

A **reverse proxy** accepts a client connection on behalf of a service. It can answer locally or send the request to an **upstream**, such as an application server or another proxy. A **load balancer** can choose among several backends. In this guide the **edge** is the first proxy you are investigating, even if a CDN or another service is in front of it. A **request ID** labels a request in a defined system. An **attempt ID** distinguishes individual upstream tries when instrumentation has such a field. A **trace** connects operations across services. A trace can have several spans and requests. Use span and attempt context where you need to distinguish them.

An edge status records what that proxy sent or recorded for its downstream connection. It may have been generated locally, relayed, or substituted. An upstream status reflects what that proxy recorded for an attempt, which depends on the product's field semantics. An application audit entry can show an operation started or changed state even when the client never saw a success response.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/http-proxy-response-evidence-en.svg' | relative_url }}" alt="A client request reaches the proxy. The proxy can answer directly or contact an upstream. Compare the client-facing status with the upstream attempt and application outcome.">
<figcaption>The edge can answer without contacting a backend. When it forwards, preserve the upstream attempt and application result separately.</figcaption>
</figure>

## 2. Read a normal request first

In this fictional example, the edge assigns `r1` within the `shop` service scope when it receives `GET /orders/summary`. It passes the identifier to the application under a documented logging contract and routes the request to the orders backend. The backend completes the read and sends 200. The edge records a 200 to the client, the selected backend and one upstream attempt, labelled `a1` in this fictional instrumentation. Correlate both layers before stating which component served the request.

| Observation | Fictional evidence | What it supports |
| --- | --- | --- |
| Proxy access record | `shop / r1`, final 200, routed to orders, attempt `a1` | A 200 was recorded at this hop and one upstream attempt was logged. |
| Application request record | `shop / r1 / a1`, status 200, result served | The orders application recorded the read and response. |
| Trace or flow, if available | Matching request or span plus expected destination and timing | Independent context for the path. A flow alone may have no HTTP status. |

A client-provided identifier is input. Establish where trusted correlation identifiers are generated or validated, which proxies preserve them, and how the application logs them. W3C Trace Context defines `traceparent` for distributed tracing, which can relate spans when consistently propagated. It does not authenticate a user. A matching ID outside its service or trust scope is a weak join. Check service, request time, backend and attempt or span as available.

## 3. Distinguish the common failure paths

| Client-facing observation | Plausible explanation | Evidence that narrows it |
| --- | --- | --- |
| 403 | Local access policy or WAF decision, or a backend refusal | Identify the decision record and whether there was a forwarding attempt. Check the application for a corresponding 403. |
| 502 | A gateway problem receiving a valid upstream response, or a relayed code from another gateway | Upstream selection, connection and response details, proxy error log and the next hop's records. |
| 503 | Capacity, maintenance or unavailable targets at a gateway or application | Upstream identity, response-origin evidence, target health and maintenance records. |
| 504 | A proxy timed out waiting for a needed upstream, or relayed an already generated 504 | Connection and response timings, timeout evidence and the related application request or business record. |
| Final 200 with earlier upstream failure | A later attempt succeeded, or an intermediary served a fallback | Keep each attempt, its backend and timing. Confirm which response was used. |

An application can commit a write before a gateway's timer expires, or complete it after the client observes the timeout. Check the durable operation record or the service's documented idempotency mechanism before repeating a write. A cache can also answer without a current backend request. See [HTTP caching evidence]({{ '/wiki/http-cache-evidence/' | relative_url }}).

Misuse can trigger the same symptoms as failures. Requests outside a service's normal access policy can generate local denials. Unexpected request volume can contribute to load-related retries or timeouts. Services also produce those patterns during deployments and ordinary traffic surges. Compare policy decisions, authenticated identities, time windows and baseline traffic. A 5xx spike or a client-supplied User-Agent cannot establish intrusion or identify an actor.

## 4. Gather the right fields and investigate

1. **Start at the symptom.** Record the UTC window, client-visible response, hostname and path, method, request ID, and any clock offset. Identify the exact proxy instance and configuration active for that request. Preserve the original records and applicable configuration revision. Avoid collecting bearer tokens, cookies or request bodies unless the investigation specifically requires them under controlled access.
2. **Expand one request into attempts.** Keep the final status, route or local decision, upstream identities, per-attempt results, durations and corresponding error logs. A retry can choose a different backend. Compare clock sources and whether the timestamps describe processing start or end. Preserve time units. Do not subtract unrelated durations to infer where a delay occurred.
3. **Join to the application.** Use the approved identifier and scope. Add the backend instance and attempt or span when available. Application logs, error telemetry and durable business records answer different questions. If the join fails, verify instrumentation, sampling, log delivery and retention before concluding the application received nothing.
4. **Respond at the confirmed layer.** Check listener, route and target health for connection failures. For a confirmed policy block, compare the active rule with the approved change and intended scope. If backend results are confirmed, bring the application owner the matched attempt and error. If a timeout preceded a durable write, resolve the operation state before any repeat.

| Product and prerequisite | Useful fields | Common reading error |
| --- | --- | --- |
| NGINX HTTP proxy with access logging configured to include the fields | `$status`, `$request_id`, `$upstream_addr`, `$upstream_status`, `$upstream_connect_time`, `$upstream_header_time` and `$upstream_response_time` | Keep multi-attempt sequences and upstream-group separators. NGINX can record upstream 502 when it cannot select a server. That value does not prove an application sent 502. |
| AWS Application Load Balancer with access logs enabled and retrievable | `elb_status_code`, `target_status_code`, target address and processing-time fields | A dash in `target_status_code` means no target status was recorded under the documented conditions. Inspect log actions and target evidence before assuming there was no backend-side effect. |
| Application with request/trace logging enabled | Service and instance, trusted request identifier and span or attempt, response and operation result | A request-start entry does not establish completion. A commit record does not establish a response reached the client. |

NGINX logs where processing finishes, which can be after an internal redirect. The upstream fields can list more than one value, separated by commas or colons. Read them with the original formatting and the same request's error log. The cited NGINX upstream durations are in seconds with millisecond resolution. ALB has its own processing-time definitions and missing-value conventions. Verify your collector's mapping before applying the lab's field names to production.

## 5. Offline lab · decide what each hop actually proves

Download <a href="{{ '/assets/labs/http-proxy-response-lab.py' | relative_url }}" download>the Python evidence exercise</a>. It contains two fictional record sets and requires Python 3. Read the cases first, then run `python3 http-proxy-response-lab.py` on an authorised machine. It reads only its embedded data. It sends no traffic. The `decision` and `attempt` fields are explicitly supplied by this fixture and are not universal NGINX or ALB fields.

| Case | Records to compare | Expected reading |
| --- | --- | --- |
| r1 | Proxy 200, matching application 200 | Relayed successful response. |
| r2 | Proxy 403 with explicit local denial and no attempts | Local block in this fixture. |
| r3 | Proxy relays a matching application 503 | Application response, confirmed by the join. |
| r4 | Final 200, two recorded attempts, last attempt returns 200 | Success after multiple attempts. The first attempt's outcome remains unproven in the fixture. |
| r5 | Proxy records timeout and 504. Same attempt has an application commit but no recorded HTTP response | Gateway timeout and recorded operation completion can coexist. Verify the commit before retrying a write. |
| r6 | Proxy 502. Candidate application entry has the same ID under a different service scope | Response origin unresolved. The candidate is not a valid join. |
| r7 | Proxy 504 marked as relay, with matching backend 504 | The investigated proxy relayed the status. Investigate the backend's dependency if root cause is needed. |

Expect `7/7 evidence controls matched.` If r6 seems attributable, add the service scope to the join. If r5 and r7 look identical, compare the proxy decision and the application record rather than using the status alone. The fixture ran in the cloud. The NGINX and AWS field definitions were reviewed in official documentation rather than exercised in live deployments.

## 6. Check your reasoning

1. **What proves a backend returned 503?** Match the right upstream attempt and confirm its application response or equivalent hop evidence. A client-facing 503 alone does not identify its origin.
2. **A 504 appeared during a write. What should you check before repeating it?** Check durable application state or the service's idempotency record for the same operation.
3. **The final result was 200. Can an earlier retry still appear in logs?** Yes. Read the attempts rather than aggregating only final responses.
4. **A proxy and application share an ID in different service scopes. Should you join them?** Establish a trusted propagation relationship and confirm the hop and time first.

**Completion criteria.** Explain the three evidence layers, classify all seven fixtures and name one record you would collect to resolve r6.

## Official references

Reviewed 2026-11-22. Use the deployed product and version's field definitions when collecting logs.

- [RFC 9110 §15.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6), June 2022 HTTP status semantics.
- [W3C Trace Context](https://www.w3.org/TR/trace-context/), November 2021 Recommendation.
- NGINX documentation for [upstream variables](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#variables), [access logging](https://nginx.org/en/docs/http/ngx_http_log_module.html) and [core variables](https://nginx.org/en/docs/http/ngx_http_core_module.html#variables).
- AWS current service documentation for [Application Load Balancer access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html).

## Follow QUIC and HTTP/3 Evidence

[QUIC and HTTP/3 request evidence]({{ '/wiki/quic-http3-evidence/' | relative_url }}) · Compare discovery, QUIC startup and request protocols on each proxy hop.

## Trace an HSTS upgrade

Use [HSTS evidence]({{ '/wiki/http-hsts-evidence/' | relative_url }}) to distinguish a client-side upgrade before transmission from a redirect sent by the server.
