---
title: "Google Cloud Service Account Impersonation Evidence"
description: "Distinguish token issuance, resource access and caller attribution using Cloud Audit Logs and an offline investigation lab."
category: cloud
tags: [Google Cloud, IAM, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/gcp-service-account-impersonation-evidence/
---

**Learning goal.** Trace a short-lived service account credential from an authorized request to a separate API call. Explain which records support issuance, use and attribution, and recognize when two events are only possible matches.

## 1. Identities, permissions and tokens

A **principal** is an identity that can make a request, such as a user or a workload. A **service account** is a Google Cloud identity intended for software. With **impersonation**, an authorized principal obtains a short-lived credential to act as that service account. This lets an organization give an approved job time-limited access without distributing a persistent private key. This chapter covers OAuth 2.0 access tokens issued by the IAM Service Account Credentials API.

| Control or credential | What it governs | What to check |
| --- | --- | --- |
| Token creation permission | Who can request an access token for the target account | `iam.serviceAccounts.getAccessToken` and the effective grant, often Service Account Token Creator |
| Service Account User role | Where a caller can attach or run a resource as a service account, when the resource API allows it | `iam.serviceAccounts.actAs` is distinct from permission to request a token |
| OAuth access token | Authenticates an API call within the token's scope and lifetime | Resource authorization still depends on the service account's effective permissions |
| Resource authorization | Whether the called operation is permitted on the target resource | Resource, method, policy and outcome at the time of the call |

For `GenerateAccessToken`, the normal maximum is one hour. A service account allowed by the organization policy for extended lifetimes can request up to twelve hours. Use a verified expiration when you have one. A default maximum is an investigation window, with uncertainty about the actual expiration and applied policy. Treat an access token as a secret: possession can be enough to present it to an API.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/gcp-service-account-impersonation-en.svg' | relative_url }}" alt="An authorized caller asks IAM Credentials for a token for a service account. A separate call presents a token to a resource API. The first audit record describes the issuance request. The second describes the resource operation and may show delegation.">
  <figcaption>Map the requester, target service account and resource operation to the evidence available at each stage.</figcaption>
</figure>

## 2. Follow an approved job across projects

In this fictional example, Mina runs a scheduled quality check. The service account lives in project A and has read access to a private test bucket in project B. The job owner approves a single metadata lookup.

1. At 09:00 UTC, Mina requests an access token for the account. The Credentials API evaluates the caller's permission on the target service account and returns a token if the request succeeds. Look for the `GenerateAccessToken` audit event for project A or its routed destination. In Google's documented example, `protoPayload.authenticationInfo.principalEmail` shows the requester and `resource.labels.email_id` shows the target.
2. At 09:03 UTC, the job presents a token to Cloud Storage. In project B's logs or their destination, read the method, bucket, timestamp and operation status. On a service that logs delegation for the method, `protoPayload.authenticationInfo.principalEmail` can show the service account and `serviceAccountDelegationInfo` can show Mina's identity or other delegation context. Federated principals can appear as `principalSubject`. Preserve the original structure for multi-hop delegation.
3. Compare both records with the approved job's run record and recorded result. A successful metadata lookup supports a lookup, with object transfer requiring separate evidence. Even matching identities and times leave uncertainty about which token was used if multiple tokens could be valid. A downstream event with delegation supports the recorded identity chain for that call.

Google documents attribution gaps for some services, including App Engine and GKE. A service-account principal without delegation could reflect a process using an attached identity, a key-backed credential, or a path whose service audit event omits delegation. Check the applicable product and method.

## 3. Collect, detect and respond

An overly broad token-creation grant can expose every resource that a privileged service account can reach. Someone who obtains an already-issued token can reuse it within its validity. A new issuer or a read from an unusual project also has ordinary explanations, including a new deployment or an approved cross-project job.

1. **Establish audit coverage at the event time.** For issuance, enable the IAM API (`iam.googleapis.com`) Data Access `DATA_READ` permission type, or the equivalent all-services configuration. Issuance events use `iamcredentials.googleapis.com` as the logged service name. Separately establish the resource API's audit category and coverage. The private Storage metadata lookup in this example requires Cloud Storage Data Access `DATA_READ`. Check effective inherited settings, exemptions, routing and exclusions, retention, and log-view scope. The default log bucket requires Data Access viewing privileges such as `roles/logging.privateLogViewer`. In a routed bucket, check the relevant view.
2. **Preserve and compare.** Preserve the original event timestamp and receive timestamp when present, `logName`, `insertId`, target account and its immutable identifier when present, caller and complete delegation chain, method, resource, request context and operation status. `insertId` identifies an entry for logging purposes. A caller IP or User-Agent can assist a join, with neither establishing identity or a shared request. Keep token values and authorization headers out of investigation notes.
3. **Look for a policy change and then for use.** Compare the issuer–target pair with approved jobs, expected scopes and resources, and IAM policy changes affecting the account or its ancestors. When reviewing a permission check, distinguish its grant flag from the overall operation outcome. Search separately for issuance failures and for downstream operations. An unexpected mint followed by a new sensitive operation is a stronger lead than a mint by itself. Google Security Command Center documents an anomalous-impersonator finding based on Data Access records. Validate the underlying event and expected job with its owner before escalating.
4. **Contain both paths when authorized.** Review affected workloads with the account owner. Removing an inappropriate grant prevents future issuance through that grant when the policy takes effect. Separately limit resource permissions for active tokens or, when the impact warrants it, disable the affected service account under your incident procedure. Google's disable API says existing access tokens are rejected while the account is disabled and can be accepted again if it is re-enabled while they are still valid. Validate containment and expected workload access with separate controls.

### Two searches in Logs Explorer

Use a UTC interval that covers the known test and select the issuance project or its routed log view for the first query. This Data Access search can return issuance attempts. Check the status in the original entry. Other logs, including applicable Policy Denied events, require separate coverage and search.

```text
log_id("cloudaudit.googleapis.com/data_access")
protoPayload.serviceName="iamcredentials.googleapis.com"
protoPayload.methodName="GenerateAccessToken"
```

Run the next search in the resource project's scope or its routed view. Replace the example account and service. The query is a starting point for Storage and leaves the audit category open. Use the proven method, resource and service to narrow it. Keep records without delegation while examining the coverage gap.

```text
protoPayload.serviceName="storage.googleapis.com"
protoPayload.authenticationInfo.principalEmail="report-reader@wiki-iam-lab.iam.gserviceaccount.com"
```

Both filters were reviewed against Google documentation. The offline exercise below does not query Cloud Logging. If a search is empty, use an approved known request to verify service name, logging scope, roles, time interval and delivery delay. A positive control now verifies current visibility. For a historical gap, you still need evidence of coverage at the incident time.

## 4. Run the offline investigation

Save the <a href="{{ '/assets/labs/gcp-service-account-impersonation.py' | relative_url }}" download="gcp-service-account-impersonation.py">Python script</a> and <a href="{{ '/assets/labs/gcp-service-account-impersonation-cases.json' | relative_url }}" download="gcp-service-account-impersonation-cases.json">fictional cases</a> in your own or approved workspace. Use Python 3.9 or newer. This lab uses local files, no network or credentials. It uses normalized fields and explicit UTC expirations supplied by the fictional cases. Real logs can omit those values. A candidate means a successful issuance for the same account, before use and before a known expiration if one was available. A candidate does not uniquely link the token to the event. A missing expiration makes the match weaker.

```bash
python3 gcp-service-account-impersonation.py gcp-service-account-impersonation-cases.json
```

| Case | Expected finding |
| --- | --- |
| `issued_only` | Issuance observed, no resource call observed |
| `mint_denied` | Issuance denied |
| `delegated_use` | Resource success and recorded delegation, with one candidate issuance |
| `resource_denied` | Resource operation denied even though a token was issued |
| `two_candidates` | Resource success with recorded delegation and two candidate issuances |
| `expired_candidate` | Resource success, caller unresolved, earlier token excluded by known expiration |
| `issuance_gap` | Resource success and recorded delegation, issuance coverage missing |
| `unknown_lifetime` | Resource success, caller unresolved, one candidate with unknown expiration |
| `empty_with_coverage` | No event observed in the supplied covered sample |

The script prints the outcome, delegation, candidate count and issuance coverage for each case. It exits with a failure when any expected finding differs. For an unreadable file, check both names and your working directory. If a candidate count surprises you, examine the target and UTC timestamps before reviewing delegation. Test a boundary by changing the resource-call time in a copy of `expired_candidate` to a second before expiration. The case should fail its original expectation and report a candidate. Script execution was verified in the cloud workspace. No live IAM project, service account or Security Command Center detector was exercised.

## 5. Check your reasoning

- **A successful issuance follows a Token Creator grant. Was the bucket accessed?** Establish the resource call and its outcome separately in the bucket's logs and approved job records.
- **Two successful mints for the same account overlap a successful resource call that names Mina in delegation. Which token was used?** The call records Mina in its chain. The two mint entries still leave the credential-level link unresolved.
- **Resource activity names the service account but no caller or issuance. Did the job necessarily use an attached account?** Several paths fit those observations. Check the service's delegation coverage, effective historic settings and the workload's authenticated identity records.

Finish when all nine cases pass and you can write a short finding that states the operation outcome, the observed caller or attribution gap, whether any mint is only a candidate, and which missing source you would check next.

## Official references

Reviewed November 26, 2026. Scope is the Google Cloud IAM Credentials v1 access-token flow and Cloud Audit Logs. The Credentials audit page was updated November 17, 2026 UTC, and the service-account examples November 13, 2026 UTC.

- Credential issuance and lifetime. [GenerateAccessToken v1](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken) · [Service account impersonation](https://docs.cloud.google.com/iam/docs/service-account-impersonation) · [Service account permissions](https://docs.cloud.google.com/iam/docs/service-account-overview)
- Audit categories and identity fields. [Credentials audit logging](https://docs.cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds) · [Service account log examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts) · [Federated identity log examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity)
- Log coverage and searching. [Configure Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) · [Cloud Audit Logs overview](https://docs.cloud.google.com/logging/docs/audit) · [Logging query language](https://docs.cloud.google.com/logging/docs/view/logging-query-language) · [Cloud Storage audit logging](https://docs.cloud.google.com/storage/docs/audit-logging)
- Detection and containment. [Security Command Center finding](https://docs.cloud.google.com/security-command-center/docs/findings/threats/anomalous-sa-delegation-impersonator-data-access) · [Compromised-credential response](https://docs.cloud.google.com/docs/security/compromised-credentials) · [Disable a service account](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/disable)

[Next · Investigate a Cloud Storage object read]({{ '/wiki/gcs-object-read-evidence/' | relative_url }}) · [Compare · AWS IAM roles and CloudTrail]({{ '/wiki/aws-iam-role-evidence/' | relative_url }})
