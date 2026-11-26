---
title: "Azure Key Vault Secret Reads · What Does SecretGet Prove?"
description: "Separate access grants, secret metadata, value responses and downstream use when investigating Key Vault audit records."
category: cloud
tags: [Azure, Key Vault, Azure Monitor, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/azure-key-vault-read-evidence/
---

**Learning goal.** Azure reports that a workload signed in, someone received a vault role and a client called `SecretGet`. Find evidence of the particular value response, identify the expected identity and version, and decide what remains unknown.

## 1. Distinguish four stages

An Azure Key Vault **secret** holds a value, such as an application credential. Its **name** can have multiple **versions**, each with its own identifier. A workload can authenticate to Microsoft Entra ID as a **managed identity**. Microsoft Entra issues a token. Key Vault evaluates whether the presented identity can perform the requested operation. In an **Azure RBAC** vault, role assignments and scope matter. Vaults using the **access policy** model use a different set of data permissions. Network rules can independently block access.

The **management plane** changes vault settings and access. The **data plane** handles calls such as requesting a secret value. SaaS and hosting products may cache values. An application can use a previously retrieved value without a new vault read.

| Stage or source | Evidence it supplies | Separate decision to verify |
| --- | --- | --- |
| Entra sign-in or workload identity evidence | Identity authentication or token acquisition, when collected | Which vault request actually used the token |
| Azure Activity Log and access configuration | Management action or potential permission, such as a role assignment | Whether a data-plane request occurred and its result |
| Key Vault `AuditEvent` | Operation against an identified vault, status and token identity if present | Whether a client received, stored or used the value |
| Application or dependent service audit | Application receipt or use at the dependent service, when logged | Which exact version or credential was involved |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/azure-key-vault-read-evidence-en.svg' | relative_url }}" alt="A workload authenticates to Entra ID, then requests a value from Key Vault. The vault evaluates access and records its response. Later application use needs separate evidence. Management events describe access changes on a separate path." width="480" height="384">
  <figcaption>A role change enables potential access. A data-plane response and later application use each require their own evidence.</figcaption>
</figure>

## 2. Follow a normal read

A fictional reporting service uses the managed identity `report-worker` against vault `vault-training-a`. The service owner has approved a read-only data-plane role at the intended scope, and the request comes through the expected network path. The service requests a specific version. The vault's resource audit records `SecretGet` with HTTP 200. The documented API returns a secret value in that successful response. This is strong evidence of a value-bearing response at the service. Separately, the application records receipt and its downstream database records a connection. Only those later sources can support a conclusion about receipt or use.

| Operation or result | Interpretation |
| --- | --- |
| `SecretGet` with HTTP 200 | A successful value-response operation. Correlate the vault, secret, requested version and identity. |
| Unversioned `SecretGet` with HTTP 200 | The API selects the latest version for the request. Confirm the exact returned version from reliable response, application or corresponding service metadata. The latest version now may differ. |
| `SecretList` or `SecretListVersions` with HTTP 200 | A metadata listing. The list operation alone does not establish value retrieval. |
| `SecretGet` with HTTP 401 or 403 | An authentication response or access denial for that attempt. Check for a legitimate authentication challenge, a subsequent retry, and the detailed reason for a 403. |
| `SecretGet` with HTTP 404 or 429 | A resource lookup failure or throttling for that attempt. Check the client retry and deadline separately. |
| Role assignment or vault configuration write | Management evidence. Compare effective permissions and the data-plane audit stream. |

Scope access by the actual permission model. Microsoft documents `Key Vault Contributor` as a management role and `Key Vault Secrets User` as a role that can read secret contents in an RBAC vault. A Contributor in a vault using the access policy model can present a separate risk if they can change the access policy. Verify what changed and what the caller subsequently did.

## 3. Recognize misuse and alternatives

An attacker with access to a workload identity or an overly broad grant can try to read credentials. A single successful read can also be normal service startup, scheduled refresh or rotation. A burst can come from expected scaling or unexpected enumeration. Start by comparing the vault ID, exact operation, principal, effective scope, expected runtime and time window.

| Observation | Test before escalating |
| --- | --- |
| A new principal reads a production secret | Compare workload inventory, role timeline, change approvals, selected network route and available request details. |
| A read follows a permission change | Check the exact scope and principal. Time proximity alone does not connect the two actions. |
| A workload sees 403 | Read the provider's detailed error. Firewall or authorization policies can each produce 403. Confirm the effective settings at the time. |
| There is no audit row | Verify diagnostic settings, destination, relevant vault, time, retention, ingestion and query filters. A cached value can also explain the lack of a new call. |

A token record identifies the principal or app claims presented to the API when available. It cannot establish a particular human, host process or device by itself. Caller IP can be shared by several workloads behind a proxy or egress address. A sequence of list and read events merits comparison with deployment and runtime records.

## 4. Collect, detect and respond

1. **Verify the route for logs.** Check the relevant vault's diagnostic setting sends the `AuditEvent` category to the intended destination. For Log Analytics, verify the table and schema actually in use. Run the example below for a resource-specific destination using `AZKVAuditLogs`. A legacy `AzureDiagnostics` destination has a different schema and needs its own query. Record the effective setting, ingestion delay, retention and time coverage. Export raw records where required.
2. **Record the service result.** Preserve UTC, full vault resource ID, operation, status and available result details. Use `Identity` and `CallerIpAddress` where available and the scoped `RequestUri` to identify the requested secret and version. A URI without a version does not reveal the exact returned value version. Handle request paths and identity fields as sensitive. Never collect a raw secret or bearer token as part of routine investigation.
3. **Cross-check identity and change.** Compare the request against Entra identity evidence and the management history for that resource and principal. The Key Vault `CorrelationId` can be absent and is documented as an optional client correlation value. Use it with time, resource and client evidence where applicable. Do not assume Entra IDs and vault correlation values share a namespace. Preserve replay, retry and duplicated export evidence before collapsing counts.
4. **Validate the finding and contain it.** Test the logic on an approved scope with one permitted value-response record, one denied request and one metadata-only record. Then compare observed counts and gaps. For unexpected value responses, preserve evidence, confirm the workload owner and effective access, and follow the approved process to restrict access and replace the affected credential in the dependent service. Changing the value in Key Vault alone does not revoke a credential the dependent service still accepts. Verify new access and dependent-service outcomes.

For a workspace with resource-specific Key Vault logs and read permission, substitute the approved resource ID. The query omits request URIs, identities and values from this initial view. Limit further investigation to the evidence you need.

```kusto
let vault = "/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>";
AZKVAuditLogs
| where TimeGenerated >= ago(1d)
| where _ResourceId =~ vault
| where OperationName in~ ("SecretGet", "SecretList", "SecretListVersions")
| project TimeGenerated, _ResourceId, OperationName,
          HttpStatusCode, ResultType, ResultSignature, CorrelationId
| order by TimeGenerated desc
```

For a detection baseline, track the first successful `SecretGet` for a principal and scoped secret category during an agreed period. Corroborate new combinations against rollout and rotation windows. Monitor repeated denials separately. A later success after denials is a distinct condition to investigate on the same vault and principal.

## 5. Offline evidence drill

Download <a href="{{ '/assets/labs/azure-key-vault-read-evidence.py' | relative_url }}" download>the Python 3 checker</a> and <a href="{{ '/assets/labs/azure-key-vault-read-evidence-cases.json' | relative_url }}" download>the fictional audit cases</a>. Save both in the same directory. The fixture is deliberately normalized and contains only synthetic fields. The checker reads local files and sends no cloud requests.

```sh
python3 azure-key-vault-read-evidence.py
```

| Cases | Expected reasoning |
| --- | --- |
| A, B, L | Successful value-response records can differ in exact version evidence and token identity coverage. |
| C, F, G, H | Denial, authentication, missing resource and throttling each describe the recorded request's outcome. |
| D, E, N | Listing secret or version metadata and reading vault properties differ from a value response. |
| I, J | Missing status and missing rows leave different evidence gaps. |
| K, M | A management operation and a successful call on another vault establish no value response for the scoped vault. |

Expect `14/14 Key Vault evidence cases matched.` For a negative control, copy the JSON and change case A's `http_status` from 200 to 403. Run the script with that copied filename as its argument. Expect A to become `access-denied-response`, with 13 matches and exit code 1. If inputs fail to load, check the filenames, Python 3 and JSON syntax. If A still passes, confirm that you changed the record's status and left the expected outcome unchanged.

The original and altered fixtures were executed in cloud Python. Azure logging behavior, query columns and REST results were reviewed against official documentation. The exercise did not query a real workspace or retrieve any secret.

## 6. Check your understanding

1. **A role assignment succeeded and the identity signed in. Was a value retrieved?** Look for the data-plane operation and result on the correct vault. Management and authentication evidence establish earlier stages.
2. **Why does a successful listing differ from a successful Get?** The listing returns identifiers and metadata. The Get operation returns the requested value when successful.
3. **Which version did the service get on an unversioned request?** It requested the latest version at the time. Use reliable response, application or service metadata for its exact identifier.
4. **A permitted workload used a credential without a new Key Vault event. What could explain it?** A cached or previously retrieved value is possible. Check diagnostic coverage and the application and dependent-service timeline.

**Completion.** Reproduce both fixture outcomes. For A, B, D, J and K, name the evidence source, what it establishes and the additional evidence needed. Explain why a value response and credential use are separate findings.

## Official references

Reviewed 2026-11-26. REST behavior follows Microsoft Key Vault Secrets API version **2025-07-01**. Azure Monitor and Key Vault authorization details follow current Microsoft documentation. Check the deployed permissions and export mode for the actual vault.

- Operation and result definitions. [Get Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01) · [List Secrets](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets?view=rest-keyvault-secrets-2025-07-01) · [List Secret Versions](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions?view=rest-keyvault-secrets-2025-07-01) · [Key Vault error codes](https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes)
- Audit fields and export. [Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging) · [AZKVAuditLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs) · [Diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/diagnostic-settings)
- Access and management history. [Key Vault RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide) · [Azure Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log) · [Managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

[Previous · Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}) · [Next · AWS KMS evidence]({{ '/wiki/aws-kms-evidence/' | relative_url }})
