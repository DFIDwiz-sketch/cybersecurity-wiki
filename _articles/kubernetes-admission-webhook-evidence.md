---
title: "Kubernetes Admission Webhooks · Distinguish Denial, Timeout, and Fail-Open"
description: "Read AdmissionReview decisions, API audit annotations, and control-plane metrics to explain admission outcomes during a webhook failure."
category: cloud
tags: [Kubernetes, Admission Webhook, Cloud Security, Audit Logs, Detection Engineering, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/kubernetes-admission-webhook-evidence/
---

A deployment receives an API error while the admission webhook’s dashboard shows HTTP 200. Both records can be accurate. Kubernetes admission involves two exchanges. The client calls the Kubernetes API, and the API server can call a webhook. The webhook’s transport status, its policy decision, and the API server’s final response answer different questions.

## 1. Follow the two exchanges

An **admission controller** evaluates a request after authentication and authorization, before the requested write is persisted. A **mutating webhook** can propose changes, such as adding a benign ownership label. A **validating webhook** checks the resulting request and may deny it. Matching rules and conditions determine whether a particular webhook participates. A webhook's successful decision cannot establish what the rest of the admission chain did.

The API server sends a matching webhook an HTTPS request with an `AdmissionReview` body. With `admission.k8s.io/v1`, a valid decision uses webhook HTTP 200 and an `AdmissionReview.response` body. The response copies `request.uid` into `response.uid` and sets `allowed`. A webhook can include `status` for a denial. The **AdmissionReview UID** identifies this exchange with the webhook. The API audit event's **`auditID`** identifies the original request across audit stages. Use a verified mapping in telemetry if one exists. Do not equate the two fields by name or value format.

<figure>
  <img src="{{ '/assets/diagrams/kubernetes-admission-webhook-evidence.svg' | relative_url }}" width="560" height="350" alt="The client calls the API server. The API server separately calls the webhook. A valid decision may allow or deny. A call failure is handled by failurePolicy. Remaining admission checks and persistence determine the final API result.">
  <figcaption>The API response to the client is a separate record from the HTTPS response the webhook returns to the API server.</figcaption>
</figure>

## 2. Compare the normal path and four outcomes

**Fictional normal path.** A team creates a ConfigMap in the `training` namespace. The API server authorizes its caller, invokes a mutating webhook that adds an ownership label, then evaluates the final object with a validating webhook. Each returns a valid response with the corresponding review UID and `allowed: true`. For a regular create that succeeds, the API response in this example is 201. An audit mutation annotation can show which call applied the label, and a read of the returned object UID can check what is present later. An observed object with the same name might belong to a different, subsequent create, so compare the UID and timeline.

| Observation on the webhook exchange | How admission interprets it | What to verify next |
| --- | --- | --- |
| Webhook HTTP 200, valid response, `allowed: true` | This webhook allowed the request. A mutating webhook may also provide a patch. | Remaining checks, final API result, and object state when applicable. |
| Webhook HTTP 200, valid response, `allowed: false` | An explicit policy denial. The failure policy does not change it. | Policy reason on the original API response and matching webhook or audit evidence. |
| Call error, such as connection failure, timeout, or malformed response, handled with effective `Fail` | The request is rejected because the call failed. `Fail` is the default when unset. | API server error with webhook name, service availability, TLS and effective configuration at that time. |
| Call error handled with effective `Ignore` | The API server continues past that error. This is commonly called **fail-open** for that webhook. | Whether later checks denied the request, whether it was a dry run, and which objects were actually persisted. |

A client-side 403 can have multiple sources, including authorization and other admission checks. An API 201 does not tell you which webhook ran. A server-side dry run, requested with `dryRun=All`, can return a successful response without persistence. Keep transport, webhook decision, API outcome, and storage separate in the case notes.

## 3. Collect request evidence and window-level signals

| Source | Collection requirements and key fields | Supported conclusion |
| --- | --- | --- |
| API audit event | Audit enabled with a matching rule and retained `ResponseComplete` events. Record cluster, `auditID`, times, `verb`, `user.username`, `objectRef`, `responseStatus`, `requestURI` and relevant annotations. | Final API response, caller as recorded, and supported per-request admission details. An earlier `RequestReceived` event may lack annotations added during admission. |
| Webhook service or API server logs | Enable approved structured logging. Capture webhook name, review UID, request scope and time, outcome or error class. Keep an explicit audit-to-call mapping only where instrumentation provides one. | A specific call and its reported decision or error. Without a verified join, use time and object scope as leads and keep ambiguity visible. |
| API server metrics | Confirm the cluster version, metric exposure, scraper coverage by API server, and labels before querying. Track counter changes over time and account for counter resets. | A window-level signal by webhook. These metrics do not contain the audit ID of an individual request. |
| Policy or storage evidence | Preserve the configuration revision and matching rules effective then. Where authorized, capture object UID or a readback, and use controller or workload telemetry for downstream behavior. | What should have been evaluated, what persisted, and what later ran are separate findings. |

In the upstream Kubernetes v1.36 documentation, a mutating call can produce `mutation.webhook.admission.k8s.io/round_<n>_index_<n>` at `Metadata` audit level or higher. Its string value decodes into JSON with the configuration, webhook and `mutated` flag. `mutated: false` records that the invocation made no change. With `Request` or higher, a `patch.webhook.admission.k8s.io/round_<n>_index_<n>` annotation can show the applied patch. Use a limited resource and time scope before collecting patches or request bodies because they may contain sensitive configuration.

For fail-open, the upstream v1.36.0 dispatchers record annotations beginning with `failed-open.mutation.webhook.admission.k8s.io/` or `failed-open.validating.webhook.admission.k8s.io/` for the relevant recorded failure paths. The value is the webhook name. These are implementation details verified for v1.36.0. Confirm that your build and managed logging pipeline expose the annotation. Its absence alone does not establish that a webhook ran, was healthy, or enforced its policy.

Two control-plane counters can help prioritize work when available. `apiserver_admission_webhook_rejection_count` distinguishes `error_type="no_error"` for a properly returned policy denial, `calling_webhook_error` for relevant failing calls that reject, and `apiserver_internal_error`. `apiserver_admission_webhook_fail_open_count` counts observed fail-open outcomes by webhook name and admission type. Both are alpha in the v1.36 reference. Scrape the API server’s metrics if approved and available, and corroborate an increase with audit events and logs before assigning it to any resource.

## 4. Investigate and restore coverage

Start by determining whether one control is unavailable or whether there is a broader control-plane failure. Compare webhook error timing with deploys, certificate and CA changes, service endpoint health, and API server connectivity. Preserve both the policy revision and the health signals. Look for unexpected changes to webhook configuration, unexpectedly broad or missing coverage, and unexpected object changes during the window. An outage can disrupt legitimate writes or leave a check unevaluated. Neither result proves abuse. Compare authorized change records and inspect the affected resource scope.

Restore webhook availability through the approved change process and check that controls apply to their intended scope. Use an approved benign request and a controlled policy-denied fixture in a separate test environment. Observe both API outcomes and telemetry. In incident review, identify affected writes using per-request records, check what actually persisted, and flag uncertain joins and collection gaps. Keep aggregate metrics for scope and timing, rather than treating their increase as a list of affected objects.

## 5. Offline exercise · Separate seven outcomes

In a directory you control, use Python 3.9 or later and save these files with the names shown. Data is fictional. Kubernetes-shaped audit events are paired with simplified, explicitly linked diagnostic records in selected cases. The script does not start a cluster, apply manifests, or send requests.

- <a href="{{ '/assets/labs/kubernetes-admission-webhook-evidence/review_admission.py' | relative_url }}" download="review_admission.py">Download review_admission.py</a>
- <a href="{{ '/assets/labs/kubernetes-admission-webhook-evidence/cases.json' | relative_url }}" download="cases.json">Download fictional observations</a>

```sh
python3 review_admission.py cases.json
```

| Cases | Expected result |
| --- | --- |
| Mutation and normal create | One mutation is observed. API 201 is reported for a normal request. |
| Explicit denial | Webhook transport is 200, but the valid decision is deny. The API rejection is recorded separately. |
| Timeout and rejection | An explicitly linked call error explains the rejected API request. |
| Fail-open then 201, fail-open then 403 | The annotation identifies the skipped decision for one webhook. The two final API outcomes differ. |
| Success with aggregate signal only | Webhook outcome for that request remains unknown. |
| Dry-run mutation | A patch is observed on the request and API 201 is recorded, with no persistence from the dry run. |

All seven comparisons should pass. For a negative control, copy the JSON and change the `audit_id` in the explicit-denial case’s diagnostic record while leaving the audit event’s `auditID` intact. The app should no longer attribute the denial to that webhook and should exit 1 because the expected match failed. If the unmodified cases fail, confirm that you have both matching downloads and valid JSON. The Python exercise was run against the fictional evidence. Kubernetes behavior was reviewed against documentation and upstream source.

## 6. Confirm your understanding

1. **The webhook returned HTTP 200 with `allowed: false`. Did it allow the object?** No. The HTTP status belongs to the webhook exchange. The valid decision explicitly denies.
2. **A fail-open annotation and final 403 appear on the same audit event. Can they coexist?** Yes. One webhook’s call failure was skipped. The final API request was rejected at another check.
3. **The counter rose during a deployment. Which object was admitted without that check?** The metric itself cannot identify an object. Inspect request-level evidence and verify persistence separately.

**Completion criteria.** Reproduce seven comparisons and the negative control. For each outcome, explain which field identifies a call, a whole API request, the final response, and any remaining storage question.

## Official references

Reviewed 2026-11-27. API and metrics examples target the Kubernetes v1.36 documentation. Fail-open annotation details were checked in upstream v1.36.0 source.

- Kubernetes [Dynamic Admission Control](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/), [Admission Webhook Good Practices](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/) and [Kubernetes Metrics Reference](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/).
- Kubernetes [Auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) and [dry-run semantics](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/#dry-run).
- Upstream Kubernetes v1.36.0 [validating dispatcher](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/validating/dispatcher.go), [mutating dispatcher](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/mutating/dispatcher.go), and [AdmissionReview API types](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/api/admission/v1/types.go).

[Previous · Kubernetes Audit evidence]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) · [Next · Compare built-in Pod Security Admission]({{ '/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }}) · [Compare quota and admission rejections]({{ '/wiki/kubernetes-quota-evidence/' | relative_url }})
