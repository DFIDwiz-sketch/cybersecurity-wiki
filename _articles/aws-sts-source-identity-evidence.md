---
title: "AWS STS SourceIdentity · Trace a CloudTrail Role Chain"
description: "Connect temporary credentials to each role issuance, verify the provenance of SourceIdentity, and investigate missing or conflicting CloudTrail evidence."
category: cloud
tags: [AWS, IAM, STS, SourceIdentity, CloudTrail, Blue Team, DFIR]
level: Intermediate
updated: "2026-11-27"
translation_url: /ko/wiki/aws-sts-source-identity-evidence/
---

CloudTrail shows a report object read by `Reader/report-job`. The same session name appears on several calls, and one record carries `example-workload-417` as its source identity. A defensible investigation answers three questions in order. Which credentials made the request? Which sessions issued those credentials? Who controlled the original source identity value?

## 1. Understand the values and their scope

**AWS Security Token Service (STS)** issues temporary credentials. A role's **trust policy** governs who can assume it and under what conditions. An **assumed-role session** is one issuance of credentials to use the role. **Role chaining** uses credentials from one assumed-role session to assume another role. The next session has its own credentials and session name. When a source identity is set, STS preserves it through chaining and does not let it change within that chain.

<figure>
  <img src="{{ '/assets/diagrams/aws-sts-source-identity-evidence.svg' | relative_url }}" width="560" height="326" alt="A verified broker assumes Entry and obtains key A. Entry assumes Reader with A and obtains key B. Reader uses B for the object request. SourceIdentity remains constant, while each issuance has its own key." />
  <figcaption>Work backward from API use to issuance, then corroborate the original identity at its source.</figcaption>
</figure>

| Value or field | Evidence it provides | Limitation |
| --- | --- | --- |
| Issued key ID and session ARN | Compare `responseElements.credentials.accessKeyId` and `responseElements.assumedRoleUser.arn` from issuance with `userIdentity.accessKeyId` and `userIdentity.arn` on use. | Compare creation and expiry, account and role context. Missing keys or issuance records leave gaps. |
| `roleSessionName` | A label for the session that appears in its assumed-role ARN. | Names can be reused across issuances. Even a matching ARN needs a key and time check. |
| `sourceIdentity` | An attribution value attached at assumption and carried into later sessions. | Its meaning depends on which caller or identity provider supplied it and which policy validated it. Multiple issuances can share it. |
| `sessionContext.sessionIssuer` | The IAM role that issued the current assumed-role context. | It describes the role, and additional issuance evidence is needed to identify the previous caller. |
| `sharedEventID` | When present, relates account views of the same AWS action. | Each view has its own `eventID` and `recipientAccountId`. This field does not join different hops. |

At issuance, inspect `requestParameters.sourceIdentity` and `responseElements.sourceIdentity` where present. In API use, look under `userIdentity.sessionContext.sourceIdentity`. A chained `AssumeRole` event is both a use of the incoming session and an issuance of a new one. Read the caller's identity separately from the newly issued session's details in that record.

## 2. Walk a normal chain and test what its label means

In this fictional example, a broker starts an approved report workflow. At 09:00 UTC it assumes `Entry` in account A. STS issues key A for `Entry/report-job` with a source identity mapped by the broker to workflow 417. At 09:02, key A calls STS to assume `Reader` in account B and receives key B. At 09:03, the `GetObject` event uses key B and carries the same source identity. Start from key B, locate its issuance, and read its caller, key A. Find the earlier issuance of key A and use the workflow and broker records to verify the original association.

**Immutability starts after assignment.** AWS preserves the value once set. AWS does not independently verify what the supplied string means. A policy allowing any correctly shaped value can retain a misleading value across every hop. Likewise, use of misappropriated temporary credentials can retain the original label. A valid match therefore identifies the session that acted, and attribution to a person or job requires independent evidence.

For a defensive policy review, confirm which callers are allowed to assume the role and set or propagate source identity. Review the mapping from an authenticated identity provider or trusted broker to a controlled identifier. `sts:SourceIdentity` is checked in the assumption context, and `aws:SourceIdentity` is available to policy evaluation after it is set. `sts:SetSourceIdentity` is a permissions-only action. AWS documents that chaining and cross-account propagation require permission on both the calling principal and the target role trust policy. A requirement that only checks presence may enforce completeness without establishing attribution.

## 3. Collect and assess the evidence

1. **Start with the action and its result.** Preserve the original event, resource, account views, Region, UTC event time, and any error. For a chained caller, record the key ID, session ARN and issuer. Assess whether the event represents an attempt or a successful API response. A successful object API call alone cannot establish how the output was used.
2. **Find each issuance.** Walk backward using the issued key and ARN, checking account, role, issuance time and expiry. Look in the appropriate caller and role accounts. AWS documents that denied cross-account STS requests are absent from the target account's log. Global-endpoint STS calls are logged in `us-east-1` even if requests are served elsewhere. Regional endpoint calls log in their own Region. Preserve `endpointType` and `awsServingRegion` if present. When two account views share a `sharedEventID`, keep both originals and reconcile their common fields before counting the API action once. Keep unmatched or conflicting evidence visible.
3. **Check coverage and reconcile identity.** Event history covers the most recent 90 days of management events in the selected account and Region. For object-level S3 `GetObject`, verify the data-event selector, resource scope and incident-time retention in the trail or event data store. Investigate a missing source identity in light of the actual integration. AWS documents that some AWS service or service-linked role actions on behalf of workforce or federated identities lack it. Identity Center actions can provide separate `onBehalfOf` evidence where the service supports it. Corroborate with available identity-provider or broker sign-in and workflow history and the policies in effect at the time.
4. **Respond to corroborated anomalies.** If the key, scoped resource and time match but provenance diverges, verify raw account views and parsing before drawing conclusions. Preserve the original events and relevant configuration, then follow the approved access-containment workflow if independent evidence supports unauthorized use. Review trust and permission changes with identity owners. Keep keys and identity values in authorized evidence storage and avoid exporting session tokens or secrets to analysis notes.

## 4. Offline defense validation

Use a workspace you own or are authorized to use and Python 3. Download <a href="{{ '/assets/labs/aws-sts-source-identity-evidence/sts-chain-cases.json' | relative_url }}" download="sts-chain-cases.json">sts-chain-cases.json</a>, save the code as `review_chain.py` beside it and run `python3 review_chain.py`. The records are invented and the key IDs are placeholders. The lab makes no AWS or network requests.

This fixture uses only `AssumeRole` and normalizes timestamps to ISO 8601 with a UTC offset. For real data, preserve originals and normalize time according to the exported schema. This checker stops when it reaches a recorded non-role caller. It does not authenticate that caller, assess every AWS identity type, or automatically merge account views.

```python
import json
from datetime import datetime

def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def trace(activity, issuances):
    seen = set()
    current = activity
    while current["userIdentity"].get("type") == "AssumedRole":
        caller = current["userIdentity"]
        key = caller.get("accessKeyId")
        arn = caller.get("arn")
        if not key or not arn or key in seen:
            return "unlinked-hop"
        seen.add(key)
        observed = instant(current["eventTime"])
        candidates = []
        for event in issuances:
            if (event.get("eventSource"), event.get("eventName")) != ("sts.amazonaws.com", "AssumeRole"):
                continue
            if event.get("errorCode"):
                continue
            response = event.get("responseElements") or {}
            credentials = response.get("credentials") or {}
            session = response.get("assumedRoleUser") or {}
            expiration = credentials.get("expiration")
            if credentials.get("accessKeyId") != key or session.get("arn") != arn or not expiration:
                continue
            if instant(event["eventTime"]) <= observed < instant(expiration):
                candidates.append(event)
        if not candidates:
            return "unlinked-hop"
        if len(candidates) > 1:
            return "ambiguous-hop"
        issued = candidates[0]
        issued_source = issued["responseElements"].get("sourceIdentity")
        used_source = (caller.get("sessionContext") or {}).get("sourceIdentity")
        if issued_source and used_source and issued_source != used_source:
            return "source-conflict"
        current = issued
    return "chain-complete"

with open("sts-chain-cases.json", encoding="utf-8") as stream:
    cases = json.load(stream)
for case in cases:
    result = trace(case["activity"], case["issuances"])
    assert result == case["expected"], f"{case['name']}: {result} != {case['expected']}"
    print(f"{case['name']}: {result}")
assert len(cases) == 8
```

**Expected results.** Eight cases pass. Two chains link to an original recorded caller, including one with a reused session name and a different key. A missing intermediate issuance, a missing leaf key, a call at expiration, and a denied issuance each leave a gap. Two unreconciled account views produce ambiguity. A conflict between issuance and use stays flagged.

**Failure check.** In a copy of the fixture change the first case's API key ID from `SIM-READER` to `SIM-ENTRY`. The session ARN remains the Reader ARN, so the first case should fail with `unlinked-hop`. If the file cannot be opened, check the working directory and filename. The offline cases were executed in the cloud. The product behavior was reviewed against AWS documentation.

## 5. Check your understanding

1. **Two issued sessions have the same ARN and SourceIdentity. Can I combine them?** Compare the issued key, times and context. Reused labels may describe separate sessions.
2. **Does a complete chain identify the human at the keyboard?** It identifies the recorded chain. Investigate who controlled the original value and how the credentials were used.
3. **Event history has the issuance, but no `GetObject`. Was the object untouched?** Check object data-event collection and resource scope. Management event history alone cannot answer.

Complete the chapter when you can trace both hops, distinguish a recorded label from verified attribution, and document one coverage limitation without treating it as a negative finding.

## Official references

Reviewed **2026-11-27**. Scope includes current AWS IAM, STS and CloudTrail documentation for assumed-role sessions. The historical sample logs in AWS manuals illustrate field placement. Field presence and collection coverage depend on the actual identity flow and event.

- [AWS IAM · Monitor and control actions with assumed roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- [AWS IAM · IAM and STS events in CloudTrail, including role chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [AWS CloudTrail · userIdentity schema](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [AWS CloudTrail · Event record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [AWS CloudTrail · Event history scope](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [AWS IAM Identity Center · Identity-enhanced roles](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)

[Previous · IAM roles and CloudTrail]({{ '/wiki/aws-iam-role-evidence/' | relative_url }}) · [Next · Verify CloudTrail delivery and coverage]({{ '/wiki/cloudtrail-log-integrity/' | relative_url }}) · [Apply the evidence to AWS KMS]({{ '/wiki/aws-kms-evidence/' | relative_url }})
