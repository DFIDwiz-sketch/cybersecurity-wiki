---
title: "HTTP Trace Context · Connect Requests, Retries, and Audit Evidence"
description: "Read W3C traceparent, validate joins at a gateway, and distinguish retries and missing spans from application outcomes."
category: network
tags: [HTTP, OpenTelemetry, Distributed Tracing, Detection Engineering, DFIR, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/http-trace-context-evidence/
---

A client sees `200`, an application log shows `503`, and both appear under one trace. A retry can explain all three facts. To make that conclusion, you need evidence showing which proxy request produced which upstream attempts, which application handled them, and which response the proxy sent.

## 1. Name each level of the observation

A **trace** groups related work across services. A **span** describes one operation with an identity, context, and timing. A span may represent an inbound request, an outbound client attempt, or background work. A **parent** describes where that span descended from. A **span link** associates one span with another without requiring a parent-child relationship, even across different traces. An edge **request ID** is a local logging contract that identifies one inbound request to a particular gateway. Check who issued it and where it is carried. HTTP does not assign a universal meaning to a deployment's request-ID header.

W3C Trace Context defines fields that carry tracing context over HTTP. For version `00`, one possible `traceparent` value is:

```text
00-72af9c30ed854219816c57b32a09d4fe-0102030405060708-01
```

| Part or record | Meaning | Investigation limit |
| --- | --- | --- |
| `00` | Header format version | Parse with the applicable version rules. This chapter and its exercise use version 00. |
| 32 hex digits | 16-byte trace ID | Can group many related operations, including separate HTTP requests. |
| 16 hex digits | Eight-byte parent ID carried by the sender | For an instrumented outbound request, this commonly identifies the sending span. The receiver's own server span has its own ID. A forwarding-only hop may carry the same header unchanged. |
| Two hex digits | Trace flags. The low bit is the sampled flag in this format. | A hint propagated at that hop. It does not prove a span reached storage. |
| `tracestate` | Optional, vendor-specific tracing context | Use only when needed. Keep sensitive values out of it and restrict capture. |

A version-00 value has fixed-width lowercase hexadecimal parts and separators. A trace ID or parent ID consisting entirely of zeros is invalid. A well-formed value establishes syntax only. If it came from an untrusted caller it does not establish who made the request or whether the request was authorized.

<figure>
  <img src="{{ '/assets/diagrams/http-trace-context-evidence.svg' | relative_url }}" width="560" height="338" alt="A client's trace context reaches a gateway. The gateway assigns request R17 and uses trace T17. Two upstream attempts have separate sending spans. The app reports 503 on attempt 1 and 200 on attempt 2. The gateway finally reports 200.">
  <figcaption>Both upstream attempts can share one trace while having distinct spans and outcomes.</figcaption>
</figure>

## 2. Follow a normal trace across a retry

In this fictional example the edge receives `GET /reports/summary`, assigns request `R17`, and starts internal trace `T17`. Those labels are abbreviations. The lab uses full hexadecimal IDs. The gateway validates or restarts context according to policy. It logs its first outbound client span `A1` to `reports-a`. The receiver creates server span `B1` with parent `A1` and reports `503`. The gateway retries once as `A2` to `reports-b`, which records server span `B2`, parent `A2`, and `200`. The edge reports final `200`.

Correlate the two attempts using the gateway's own request and attempt records. Correlate each application log to its specific outbound attempt by confirming the internal trace ID and that the app's parent span matches the gateway's sending span, within the same environment, route, upstream peer, and compatible time window. Orders may vary with clocks and collection delay. If a trace backend displays only `B2`, the independent gateway logs still show two attempts. The client needs its own evidence to establish whether it received the body.

Where HTTP instrumentation supports it, OpenTelemetry recommends a client span per send attempt and provides `http.request.resend_count` for repeated sends. A resend can also come from redirection, authentication, or a network issue. Some implementations expose only a logical client span. Check the actual instrumentation before interpreting a missing attempt or inferring a specific retry reason.

## 3. Check trust and collection before joining

| Observation point | Collect when enabled | Use and limit |
| --- | --- | --- |
| Gateway access and upstream logs | UTC time, environment and gateway, edge-issued request ID, normalized route, response status, each attempt and peer, outbound span ID and internal trace ID if available | Distinguish final response from attempt results. Preserve the boundary decision on accepting or restarting external context. |
| Application logs | Service and instance, route, request or internal trace ID, local span ID and parent if instrumented, application outcome | Confirm the matched operation locally. When supported, OTel log records can carry `TraceId`, `SpanId`, and `TraceFlags`. A log's span ID is the local span, while its parent needs tracing data or a separately logged field. |
| Trace collector and storage | SDK sampling policy, collector drop or export metrics, tenant and retention, trace lookup window | Explain why spans may be missing. Head sampling decides early. Tail sampling can consider collected later spans. Neither policy recovers telemetry that never reached it. |
| Application audit or job logs | Business event type and outcome, job identifier, authenticated principal where appropriate, recorded enqueue/consume relation or a span link | Establish completion or causality beyond the request. HTTP `202` confirms acceptance for processing, while job telemetry is needed for execution. |

**Start at the trust boundary.** A caller can accidentally or intentionally reuse its own ID across requests. An external sampled flag can also increase telemetry load if treated as an instruction. Decide which upstream identities can continue context. At a public edge, a locally issued request ID and a fresh internal trace can make correlation clearer when incoming context is untrusted. If the design continues validated external context, use an independent boundary-issued request identifier and scope joins to services and attempts. Set sampling and export budgets locally. Never use tracing values for authentication or authorization. Preserve just enough to diagnose boundary behavior and avoid logging full credentials, sensitive URLs, or tracing state by default.

**Investigate a mismatch.** Begin with the boundary-issued request ID and the gateway's recorded attempts. Query the matching services and compare parentage, route, peer, timestamps, and deployment revision. Use event time where available and distinguish it from collector observation time. A repeated incoming trace ID across unrelated requests is a lead to check ingress policy and possible misuse, including badly instrumented clients. A mismatch between upstream and application records can reflect a wrong join, incomplete collection, or one recorded enqueue followed by later processing. Escalate to application audit when the question is whether a protected operation happened.

**Handle missing spans as a coverage question.** Confirm instrumentation on the expected route, then check SDK sampling, exporter delivery, collector capacity, filters, retention, and query scope. A sampled flag can coexist with a missing exported trace. A span can be absent while an independent application audit record confirms an operation. A matching trace tells you about telemetry context, while actor identity and data access require their own audit evidence.

## 4. Offline exercise · Compare six requests and two signals

Use Python 3.9 or later in a directory you control. Save the script and fictional JSON file with the names shown. The script makes no HTTP requests and does not use an OpenTelemetry SDK. Its normalized fields model a gateway whose request IDs are unique within the recorded environment and gateway. Its app join requires environment, route, peer, internal trace ID, and a matching parent span within five seconds. Five seconds is an exercise assumption, not a universal timeout. Job completion is joined using a scoped job ID within a separate 60-second exercise window.

- <a href="{{ '/assets/labs/http-trace-context-evidence/review_trace.py' | relative_url }}" download="review_trace.py">Download review_trace.py</a>
- <a href="{{ '/assets/labs/http-trace-context-evidence/cases.json' | relative_url }}" download="cases.json">Download fictional observations</a>

```sh
python3 review_trace.py cases.json
```

| Fixture | Expected result |
| --- | --- |
| Retry | The edge shows 200. Distinct attempts join to app outcomes 503 and 200. |
| Reused external context A and B | Two requests share a client-supplied trace ID. Their internal traces and application results stay separate. |
| Unsampled but audited | App logs match the attempt despite the unsampled context and no stored span. |
| Sampled but missing | App outcome stays unknown when no matching record exists. A similar record from a different environment is excluded. |
| Accepted job | Edge 202 is separate from the recorded job completion linked by the issued job ID. |

The script prints six passing comparisons. For a negative control, copy the JSON, change the first app record's `parent_span_id` to another nonzero 16-hex value, and run against the copy. Retry attempt 1 should lose its app match and the program should exit 1. If original inputs fail, check that the downloads match, both files are present, and the environment and timestamp fields are intact. The fictional evidence exercise was executed. OpenTelemetry behavior was reviewed in its documentation.

## 5. Check your reasoning

1. **Two requests carry the same incoming trace ID. Is it one request?** A caller or an upstream transaction can reuse the value. Compare gateway-issued request IDs and the recorded attempt relationships.
2. **The sampled bit is set. Can you establish why the app span is absent?** The bit alone leaves delivery, sampling, storage, and lookup coverage unresolved. Check the relevant logs and telemetry pipeline.
3. **The client saw `202`, and a worker logged completion under a different trace ID. Can they describe the same job?** Yes. Find the enqueue and completion records for the same scoped job ID or a documented explicit link, then check the operation's outcome independently.

**Completion criteria.** Reproduce the six results and the negative control. Explain which record supports the final response, each attempt, and any background side effect. For a missing span, name two evidence sources that could narrow the cause.

## Official references

Reviewed 2026-11-27. The header examples follow the W3C Level 1 Recommendation of November 2021 and version 00. The Level 2 document checked here was the March 2024 Candidate Recommendation Draft. OpenTelemetry field and sampling statements refer to the official documentation available on the review date.

- W3C [Trace Context Level 1](https://www.w3.org/TR/trace-context/) and [Level 2 status](https://www.w3.org/TR/trace-context-2/).
- IETF [RFC 9110 §15.3.3 · HTTP 202 Accepted](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.3).
- OpenTelemetry [Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/), [Tracing API](https://opentelemetry.io/docs/specs/otel/trace/api/), and [Sampling](https://opentelemetry.io/docs/concepts/sampling/).
- OpenTelemetry [HTTP spans and resend conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-request-retries-and-redirects).

[Previous · Trace a reverse proxy response]({{ '/wiki/http-proxy-response-evidence/' | relative_url }}) · [Next · Build an incident timeline]({{ '/wiki/incident-timeline-evidence/' | relative_url }}) · [HTTP evidence fundamentals]({{ '/wiki/http-evidence/' | relative_url }})
