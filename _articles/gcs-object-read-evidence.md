---
title: "Google Cloud Storage Object Read Evidence · From IAM to Receipt"
description: "Distinguish object listing, metadata and content reads, then investigate Data Access gaps with nine offline cases."
category: cloud
tags: [Google Cloud, Cloud Storage, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/gcs-object-read-evidence/
---

**Learning goal.** Given a Cloud Storage audit entry and a matching client or service record, decide whether it supports a listing, a metadata lookup, an object content read or only an unresolved attempt. Determine which logging gaps make a negative search inconclusive.

## 1. What exactly was read?

A **bucket** holds objects. An **object name** identifies an object within that bucket. A **generation** identifies a particular revision of the object's data. The same name can refer to different bytes at different times. A **principal** is an identity that can receive permissions, such as a user or a workload's service account. IAM permissions decide what that identity may do. Audit configuration decides what evidence Google Cloud writes about those actions.

| Operation or record | What it tells you |
| --- | --- |
| List objects | Which objects matched a listing request. It does not return their content. |
| JSON API object GET, default | Returns object metadata. |
| JSON API object GET with `alt=media` | Requests object data. A `Range` request can retrieve a portion. |
| Admin Activity | Includes actions such as setting bucket IAM. Use it to establish policy changes in the timeline. |
| Data Access, `DATA_READ` | Covers object listing, metadata and data reads when applicable. It is disabled by default for Cloud Storage. |

Both forms of JSON API object GET use the `storage.objects.get` permission. That permission and the broad audit category cannot establish the response body. Identify the API and request form before interpreting a method: a JSON API GET and an XML API GET have different default behavior.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/gcs-object-read-evidence-en.svg' | relative_url }}" alt="A Cloud Storage request leads to two pieces of evidence. Audit records describe identity, authorization and outcome when collected. Client or service records describe the response type and bytes. Both must be joined to support a transfer claim.">
  <figcaption>Read the storage audit event and the evidence of delivery together.</figcaption>
</figure>

## 2. Follow a normal object read

A reporting job uses a service account to fetch generation `17` of a fictional object named `reports/summary.csv` from a private bucket. It reads metadata first to check the expected generation, then separately requests data and records the verified length and checksum after receipt.

1. The job authenticates and requests metadata. With `DATA_READ` in scope, the audit event can show the service, method, object and authenticated principal. A successful metadata lookup confirms that metadata was returned.
2. The job sends a distinct data request. IAM permission checks can appear in `protoPayload.authorizationInfo`. Match the element for the relevant resource and permission. `granted` describes that check. `protoPayload.status`, when populated, describes the operation and uses Google RPC status codes. HTTP status, if available, comes from a separate HTTP field or record.
3. The job records the object generation, bytes received and verification result. A shared request ID is the strongest join when both sources expose it. Otherwise, combine time, bucket, object, generation and caller where available, and report the match confidence. A single succeeded API status does not show that the client completed the transfer or used the data.

Google Cloud doesn't log reads granted through `allUsers` or `allAuthenticatedUsers` in Cloud Audit Logs, even if Data Access is enabled. Authenticated browser downloads outside the console can produce entries with `principalEmail` and `callerIp` redacted. Google recommends Cloud Audit Logs for general auditing and documents separate bucket usage logs for coverage needs such as public access. Usage logs must be configured in advance. Their delivery can be incomplete or delayed. Their `sc_bytes` field, when available, means bytes sent in the response. Check the request and status before treating it as object content, and use client-side evidence for receipt.

## 3. Investigate an unexpected read or a missing record

An overbroad IAM grant can make sensitive objects readable by a legitimate workload that was never meant to see them. Reuse of a service account credential can cause an unexpected request under a familiar identity. A signed URL grants limited access to its bearer for a defined time. Its issuance does not establish use, and a signing identity does not identify every individual bearer. A new caller IP or user agent can also come from a healthy deployment, a proxy, or a client update. Avoid attributing the request to a person from any single field.

1. **Confirm coverage.** Select the project that owns the bucket or the routed log destination. Check `DATA_READ`, effective configuration at the event time, exempt principals, sink routing, exclusions, view access and retention. Data Access in the default buckets requires appropriate access such as `roles/logging.privateLogViewer`. In a custom destination, verify access to the relevant log view. Record the time range in UTC and run a known private-read control where authorized.
2. **Preserve the original events.** Keep timestamps, log name, resource, `insertId`, method, generation if present, auth and delegation context, relevant authorization entries and overall status. `insertId` helps identify a log entry and should not be assumed to be a cross-system request ID. Add safe request and response metadata when already recorded. Do not collect object content, access tokens or signed URL query strings for this triage.
3. **Compare and respond.** Group listings, metadata and corroborated content responses separately. Compare a burst against the identity's expected schedule, object set and destinations. Adjust for retries and separate range responses before estimating volume. Review recent bucket IAM changes and service account activity. If there is a credible exposure, coordinate with the owner to contain the access path, preserve evidence and validate the new policy with an approved control read and a denied test identity.

Start in Logs Explorer with a window that includes the test and replace the fictional bucket name. This query finds the bucket's Cloud Storage Data Access events, including operations beyond reads. First review the service's actual fields. Then narrow to the observed method and resource for the chosen API. Use the full log scope and view that can read sensitive logs.

```text
log_id("cloudaudit.googleapis.com/data_access")
resource.type="gcs_bucket"
resource.labels.bucket_name="wiki-audit-lab"
protoPayload.serviceName="storage.googleapis.com"
```

If the query is empty, confirm the project, view, UTC range and actual bucket name. Check logging coverage independently of the suspected event. Search for a positive control. Leave a historical gap unresolved when the necessary data was never produced or retained. Google documents where to search Policy Denied audit logs for applicable policy violations. The broad Data Access query above does not include that log class. A denied attempt in one record establishes its own result, while a later retry remains a separate request.

## 4. Practice in an approved workspace

Save the <a href="{{ '/assets/labs/gcs-object-read-evidence.py' | relative_url }}" download="gcs-object-read-evidence.py">Python script</a> and <a href="{{ '/assets/labs/gcs-object-read-evidence-cases.json' | relative_url }}" download="gcs-object-read-evidence-cases.json">fictional cases</a> in one folder. The JSON fields are normalized observations for this exercise, not native Cloud Logging names. The matching evidence is supplied in the fixture. The script reads local files only.

```bash
python3 gcs-object-read-evidence.py gcs-object-read-evidence-cases.json
```

```text
listing: listing_observed
metadata: metadata_observed
get_without_detail: request_kind_unresolved
partial_response: partial_content_sent
full_receipt: full_receipt_confirmed
denied_request: request_denied
other_connection: content_delivery_unconfirmed
public_read_gap: coverage_gap
no_matching_entry: no_event_observed
```

If the file cannot be found, check the working directory and both names. Compare `partial_response` and `full_receipt`. The first case has correlated response evidence for a range. Only the second has integrity-checked client evidence that the complete object was received. `no_matching_entry` also has no positive read evidence. It describes a search result.

For an optional product check, use a private bucket and dummy object in an approved test project. With `DATA_READ` already enabled and authorized log viewing set up, retrieve metadata and then download the same object generation with an approved client. Record the UTC window and the received file's length and checksum. Use the query to compare the entries and then try a separate, authorized test identity with no object read permission. Allow for ingestion delay. If records are absent, troubleshoot the positive control before interpreting the denied test. Leave the object private throughout. The Python fixture was executed. The Logs Explorer filter and cloud procedure were reviewed against Google documentation. No live Google Cloud project was exercised.

## 5. Check your reasoning

- **You see a successful `storage.objects.get` permission check. Did the client receive all bytes?** First establish the operation result, request form and generation. Then obtain matching delivery or client verification evidence.
- **No Data Access record exists for a public object. Can you rule out access?** No. Confirm the access path and look for previously configured usage logs or other approved service evidence.
- **The caller IP was redacted. Should you label the request anonymous?** No. Redaction can occur for an authenticated browser download. Look for workload or application evidence before deciding attribution.

Finish when all nine outputs match and you can explain the difference between permission, request result, bytes sent and verified receipt, plus one reason a read can be absent from your query.

## Official references

Reviewed November 23, 2026. These references describe the current Google Cloud service and APIs, with the Cloud Storage audit page updated November 17, 2026 UTC.

- Cloud Storage audit categories, supported operations and coverage restrictions. [Cloud Audit Logs with Cloud Storage](https://docs.cloud.google.com/storage/docs/audit-logging)
- JSON API request forms, generations and ranges. [Objects: get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get)
- Audit payload and status fields. [AuditLog](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
- Audit configuration, privileges and query syntax. [Enable Data Access](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) · [Cloud Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit) · [Logging query language](https://docs.cloud.google.com/logging/docs/view/logging-query-language)
- Usage log coverage, delivery limits and fields. [Cloud Storage usage and storage logs](https://docs.cloud.google.com/storage/docs/access-logs)
- Time-limited bearer access to a Cloud Storage resource. [Signed URLs](https://docs.cloud.google.com/storage/docs/access-control/signed-urls)

[Compare · Amazon S3 object reads]({{ '/wiki/s3-object-read-evidence/' | relative_url }}) · [Related · Investigate audit log gaps]({{ '/wiki/cloudtrail-log-integrity/' | relative_url }})

[Previous · Investigate service account impersonation]({{ '/wiki/gcp-service-account-impersonation-evidence/' | relative_url }})
