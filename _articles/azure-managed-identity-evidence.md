---
title: "Azure Managed Identity Evidence · From Assignment to Resource Access"
description: "Distinguish workload assignment, Entra sign-ins, and resource requests using stable identifiers and six offline cases."
category: cloud
tags: [Azure, Microsoft Entra ID, Managed Identity, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/azure-managed-identity-evidence/
---

**Learning path** · [Microsoft Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}) → managed identity evidence → [Azure Key Vault secret reads]({{ '/wiki/azure-key-vault-read-evidence/' | relative_url }}).

## 1. What Azure manages

A **managed identity** lets a supported Azure workload authenticate to a service that accepts Microsoft Entra tokens. Azure manages the identity's credentials. In Entra, a **service principal** represents the identity in the tenant. The workload obtains an **access token** for an API and presents it to that API. The API evaluates the token and its own authorization controls. **Azure role-based access control (RBAC)** grants a principal actions at a scope, such as one resource. The effective decision can also depend on the service's configuration and network rules.

A **system-assigned identity** belongs to one Azure resource and its service principal is tied to that resource's lifecycle. A **user-assigned identity** is a separate Azure resource. It can be attached to multiple workloads and persists when a workload is deleted. A shared identity can simplify deployment, but its service principal alone identifies the identity rather than the particular workload using it. Reusing a display name after a rebuild can hide that the principal ID changed.

| Identifier | How to use it | Common mix-up |
|---|---|---|
| Tenant ID and identity principal ID | Compare the assignment's `principalId` with Entra's caller `ServicePrincipalId` in the corresponding tenant. | An application/client ID, display name or IP address identifies a different thing. |
| Workload ARM resource ID | Find the compute, app or other resource with the identity attached at the relevant time. | A single user-assigned identity can appear on multiple workload resources. |
| Audience / resource service principal | Identify the intended API service. Entra has fields such as `ResourceIdentity` and `ResourceServicePrincipalId`. | An API service such as Key Vault can serve many individual resources. Use the target service's logs to identify the actual vault and operation. |
| Target ARM resource ID and request ID | Identify the target instance and correlate its response with a request. | Do not assume an Entra `CorrelationId` matches a resource-side request ID. Compare documented mappings or other independently observed evidence. |

## 2. Read a normal sequence

**Fictional example.** At 09:00 UTC the Azure Activity Log shows an approved identity change on `report-vm-a`. An inventory snapshot records that workload attached to a user-assigned identity whose principal ID ends in `0042`. An approved Key Vault data-plane role is assigned at the training vault. At 09:02 the Entra managed identity report shows that principal signing into the Key Vault service. At 09:04 the training vault records a successful read with the same tenant and principal. A workload trace carries the vault's request ID for that operation.

The records support assignment, authentication to a target API, and a successful resource request. The workload trace and matching request ID support attribution of that particular request to `report-vm-a`. The Entra portal can group multiple sign-ins with matching identity, status and resource. Expand the group to read the recorded times. A grouped row cannot serve as an API call count.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/azure-managed-identity-evidence-en.svg' | relative_url }}" alt="Azure inventory and Activity Log show assignment. Entra shows managed identity sign-ins to an API. Target resource logs record the operation and result. Workload request telemetry links activity to a specific workload." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Collect each evidence source around the same UTC window. Identity helps join records, and a service request ID can connect an operation to a workload trace.</figcaption>
</figure>

## 3. Investigate misuse and gaps

| Observation | Supported interpretation | Next check |
|---|---|---|
| Successful managed identity sign-in, no matching target record | Authentication evidence to an API. The target request remains unconfirmed. | Confirm target audit coverage and look for the request in the relevant service. |
| Successful resource operation, no fresh sign-in in the window | The target accepted the operation. A cached token, a different time window or a logging gap can explain the missing sign-in. | Check Entra export, retention and a wider window. Compare workload and target telemetry. |
| Same principal attached to two workloads | A resource log that identifies the principal leaves more than one candidate workload. | Inventory as of the event. Join service request IDs to workload traces or other independent network evidence. |
| Successful sign-in followed by a target denial | The API can reject an authenticated identity. | Read the service's error reason. Check role scope, target, audience and network rules as applicable. |
| Expected name but principal ID differs | Identity replacement or wrong scope can explain the change. | Compare historical assignments and directory object IDs, then reconcile approved changes. |

A workload using a powerful identity can perform the actions the target grants it. A shared identity or overly broad role can enlarge the affected scope when a workload or assignment changes unexpectedly. Treat a previously unseen identity-target pair as a lead. Compare with approved releases, automation and a stable baseline before assigning cause.

Microsoft documents an infrastructure token cache per resource URI and notes that managed identity group or role membership changes can take several hours to appear in token claims. Treat its approximately 24-hour cache description as implementation context, not a guaranteed cutoff for access. Correcting a direct resource role assignment and changing membership reflected in a token involve different evaluation paths. Verify containment using a controlled request and the target service's response.

## 4. Collect, detect and respond

Use a read-only account in the approved Azure tenant and subscription. These Azure CLI inventory commands query a VM's identity assignment and a user-assigned identity resource. Use actual approved names and sufficient read access to both resources. The VM command applies to Azure VMs. For other compute services, use their own identity inventory. These are current snapshots.

~~~sh
az account show --query '{tenant:tenantId,subscription:id}' -o json
az vm identity show --resource-group rg-training --name report-vm-a -o json
az identity show --resource-group rg-training --name report-worker \
  --query '{id:id,principalId:principalId,clientId:clientId,tenantId:tenantId}' -o json
~~~

For Log Analytics, route the Entra **ManagedIdentitySignInLogs** diagnostic category to the workspace and give the analyst read access to the resulting `AADManagedIdentitySignInLogs` table. Use the time and identity from the incident. The example uses a fictional principal ID and a recent 24-hour lookback. Confirm workspace time range, export health and retention before treating zero rows as an observation about coverage. `CreatedDateTime` is the activity time. Keep `TimeGenerated` separately rather than assuming the two are identical.

~~~kusto
let principal = "00000000-0000-4000-8000-000000000042";
AADManagedIdentitySignInLogs
| where CreatedDateTime >= ago(24h)
| where ServicePrincipalId =~ principal
| project CreatedDateTime, TimeGenerated, AADTenantId,
          ServicePrincipalId, AppId, ResourceDisplayName,
          ResourceIdentity, ResourceServicePrincipalId, ResultType,
          ResultDescription, CorrelationId, IPAddress
| order by CreatedDateTime asc
~~~

1. **Collect.** Preserve workload and identity inventory, Activity Log changes to identity assignment and role scope, Entra sign-ins, and the target's independently configured data-plane logs. Record UTC, tenant, subscription, identifiers and coverage. Store raw logs with restricted access. Do not collect access-token strings or secret values for this comparison.
2. **Detect.** Prioritize an unexpected attachment or broad role change when it overlaps target activity. Compare prior inventory with what was effective during the request. Track new principal-resource pairs and repeated failures by result and operation. An unknown IP or matching display name alone gives weak attribution.
3. **Respond.** Coordinate with the identity and resource owners. Preserve evidence, identify every workload attached to a shared identity, and narrow the affected target access according to the approved incident procedure. Check the target service's successful and denied operations after the change. Record any gap where absence of events prevented verification.

## 5. Offline exercise · Six fictional case files

Use Python 3 in your authorized workspace and save both downloads in one directory. The JSON has normalized evidence and an answer key. It represents an analyst's comparison window, not raw Azure records. The script sends no network requests. It matches tenant, principal and API for sign-ins, and tenant, principal, target and operation for resource records. It also checks workload-attachment count and a request trace, if one is supplied.

- <a href="{{ '/assets/downloads/azure-managed-identity-evidence/inspect_identity.py' | relative_url }}" download>Download the Python checker</a>
- <a href="{{ '/assets/downloads/azure-managed-identity-evidence/identity_cases.json' | relative_url }}" download>Download the six fictional cases</a>

~~~sh
python3 inspect_identity.py identity_cases.json
~~~

| Case | Expected interpretation |
|---|---|
| Correlated success | Matching sign-in, resource success and workload request trace. |
| Sign-in only | Authentication matches, resource operation remains unconfirmed. |
| Resource without fresh sign-in | A resource success remains valid while authentication inside the window is unobserved. |
| Shared identity | Two workload candidates remain when no request trace identifies the caller. |
| Target denies | One matching resource denial is recorded, separately from authentication. |
| Reused display name | A sign-in and resource record from a different principal must not match, even with the expected name. |

Copy the JSON and change the first case's target request ID without changing its workload trace or answer key. The first case should fail and exit status should be 1. If the checker cannot start the comparison, verify the working directory, filenames and JSON syntax. The published checker was run on these fictional cases. The Azure CLI and KQL were reviewed against official documentation.

## 6. Check your understanding

- **Does a Key Vault sign-in identify the exact vault?** It identifies the API service. Use the vault's operation logs for the target instance and verdict.
- **Can two hosts share the principal?** Yes, with a user-assigned identity. Compare attachments at the event time and use request-level evidence for workload attribution.
- **Does no sign-in during a successful resource request prove an audit failure?** No. Review token reuse, service and tenant scope, retention and export health.

Finish by tracing one request through the three evidence sources, making the changed fixture fail, and identifying which evidence would resolve an ambiguous workload.

## Official references

Reviewed **2026-11-27**. Product behavior and CLI syntax follow the Microsoft Learn documentation available at review time. The managed identity report was updated in February 2026 and the queried table schema in August 2026. Check your tenant's current export, retention and resource-specific settings.

- [Microsoft Entra managed identities for Azure resources · Identity types and lifecycle](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [Microsoft Learn · Managed identity security and authorization caching](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
- [Microsoft Learn · Managed identity sign-ins and grouped records](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-managed-identity-sign-ins)
- [Microsoft Learn · Managed identity sign-in table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)
- [Microsoft Learn · Entra diagnostic routing](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings)
- [Azure Monitor · Activity Log](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log)
- Azure CLI reference · [VM identity](https://learn.microsoft.com/en-us/cli/azure/vm/identity#az-vm-identity-show) and [user-assigned identity](https://learn.microsoft.com/en-us/cli/azure/identity#az-identity-show).
