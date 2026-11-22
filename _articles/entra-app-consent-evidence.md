---
title: "Microsoft Entra App Consent Evidence · From Grant to Resource Activity"
description: "Distinguish delegated consent, app-only assignments, token use and API responses in twelve offline investigation cases."
category: cloud
tags: [Microsoft Entra, OAuth 2.0, App Consent, Microsoft Graph, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/entra-app-consent-evidence/
---

When an unfamiliar app appears in a consent audit, ask two questions. **What authority was granted, and what did the app actually do?** Consent is an authorization decision recorded in the directory. Later authentication, token issuance and a protected API operation produce separate evidence. Use the [OAuth and OpenID Connect chapter]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}) to review the protocol roles.

## 1. Identify the objects and the authority

An **application registration** describes the app. A **service principal** is its identity in a particular tenant. A multitenant app can have one application ID (`appId`, often called the client ID) but different service principal object IDs across tenants. The client and the resource API each have their own service principal. Resolve object IDs in the correct tenant. Display names can change or collide.

A **delegated scope** authorizes the app to call a resource on a user's behalf. The API can also evaluate that user's authority and additional policies. An `oAuth2PermissionGrant` records the client service principal object ID in `clientId`, the resource service principal object ID in `resourceId` and the space-separated `scope` values. `Principal` is for the user identified by `principalId`. `AllPrincipals` is consent on behalf of users in the tenant, with `principalId` null. The latter is still delegated.

An **application permission** is an app role granted to the client service principal for app-only use. Read `appRoleAssignment.principalId`, `principalType`, `resourceId` and `appRoleId`. Resolve the role ID on the resource service principal. Assignments can also name users or groups. Confirm the principal type before interpreting an assignment as an app-only permission. Permissions listed in app registration describe configuration. Check the corresponding grant or assignment to establish effective approval.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/entra-app-consent-evidence-en.svg' | relative_url }}" alt="Identify tenant and service principals, read directory permission changes, check sign-in and token evidence, find the resource response, then verify its effect.">
  <figcaption>Keep the grant record, any token and sign-in evidence, and the resource outcome separate throughout the timeline.</figcaption>
</figure>

| Evidence | Supports | Verify next |
| --- | --- | --- |
| Delegated grant for one principal | Approved scopes for the named user and API | Actual user, scopes and resource response |
| Delegated grant for AllPrincipals | Tenant-wide delegated consent | Which user and API policy applied to each request |
| App role assigned to a service principal | App-only role assignment for the named API | Workload context, role value and API result |
| Graph activity or resource audit | A request or resource action reported by that observer | Request semantics, downstream effect and observation coverage |

## 2. Follow a normal and an unexpected case

In a fictional reporting app, user U8 consents for their own account under the tenant's approved policy to a `Reports.Read` scope defined by an example Reports API. At 09:02 UTC the directory captures a successful grant. At 09:07 the resource observes the same tenant, client service principal, resource and U8 conducting a read. The request records the expected scope and returns HTTP 200. The authorization and request records support two different findings. To establish which data was returned, consult resource logs suitable for that purpose. The fictional API and scope are not Microsoft Graph permissions.

A consent screen can misrepresent the context of a request to someone or present an app with broader permissions than expected. That can result in a real grant even if the user's password was never disclosed. Conversely, a standard vendor rollout or an approved automation can generate the same audit activity. Verify who initiated the change, what authority they had, and whether its exact client, resource, permission and scope match an approved change. Then investigate any downstream API use. The initiating actor for the grant and the token's user can differ.

## 3. Collect and correlate records

1. **Find the change.** Within Entra directory audit logs, examine ApplicationManagement events. Microsoft documents `Consent to application`, `Add delegated permission grant` and `Add app role assignment to the service principal`. Check result, time, initiating actor and targets or modified properties when available. A failed consent event supports an attempt. Validate recorded permissions and scope, and check current objects. A current object can omit grants that existed and were removed.
2. **Follow authentication evidence.** Review user or service principal sign-ins as appropriate. Record tenant, client and resource IDs and timestamps. A sign-in or token-related event alone does not show the downstream operation. Sign-in records can be missing for some sources. In token-related logs, delegated scopes are commonly shown in `Scopes` and roles in `Roles`. A roles value by itself cannot prove app-only use, because role claims can also describe a user. Use principal and token context. Never include bearer tokens in investigation notes.
3. **Find the actual response.** In Microsoft Graph activity logs, use the resource tenant and confirmed app object mapping. Collect request ID, method, status and scoped path if authorized. `AadTenantId` represents the directory tenant in this table. `TenantId` represents the Log Analytics workspace ID. Where supported, the official Graph example links `SignInActivityId` to the corresponding sign-in `UniqueTokenIdentifier`. A missing match can reflect coverage. Keep a request with no match and check the resource's own logs for workload-specific impact. See [Entra sign-in investigation]({{ '/wiki/entra-signin-evidence/' | relative_url }}) for identity and policy context.

For an **approved read-only workspace**, this query retrieves candidate Graph requests for a known client service principal over 24 hours. It assumes Graph activity collection was already enabled for that resource tenant and routed to the queried workspace, a supported Entra P1 or P2 license and permission to read the data. Replace the placeholder IDs and use the incident's bounded UTC time range. Validate schema and ingestion in your workspace. Records lacking the selected ID are outside this filter. This example was reviewed against provider documentation.

```kusto
let resourceTenant = "replace-with-resource-tenant-id";
let clientObject = "replace-with-client-service-principal-object-id";
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(24h)
| where AadTenantId == resourceTenant and ServicePrincipalId == clientObject
| project TimeGenerated, AppId, ServicePrincipalId, UserId, TokenIssuedAt,
          RequestId, RequestMethod, ResponseStatusCode, Scopes, Roles
| order by TimeGenerated asc
```

## 4. Decide, contain and check again

Prioritize successful unexpected changes that widen the user population or give app-only access to a sensitive API. Compare against consent policy, change approvals, application ownership and expected background jobs. A display name, User-Agent, IP address or a verified publisher indicator alone cannot determine intent. Graph logs cover Graph requests observed for the resource tenant. They cannot show this multitenant app's operations in other tenants or every resource-side effect. A 403 documents a rejection. A 202 can acknowledge receipt without completion. For a batch, examine each relevant operation's response.

Preserve grant and role snapshots and accessible audit records. Coordinate any approved permission removal or temporary app disablement with the incident lead and application owner. Identify affected users, dependent workloads and issued token or session exposure. Existing token behavior depends on expiry, service and revocation handling. Verify the resulting directory state and watch for fresh requests or re-grants. Avoid reporting containment from a single change record.

## 5. Offline lab · twelve fictional observations

Download both files to the same folder and run with Python 3.10 or later. No tenant, OAuth grants, access tokens or connections are required. Each JSONL row contains one fictional normalized grant and a candidate read. The tuple combines tenant plus client and resource service principal object IDs. The API resource identity and token mode are already resolved in this training data. The time window represents observed grant evidence, in relative seconds. The script checks consistency with that window. It does not prove that a particular grant caused a request or that access ended at removal time.

<a href="{{ '/assets/labs/entra-app-consent-evidence.py' | relative_url }}" download="entra-app-consent-evidence.py">entra-app-consent-evidence.py</a> · <a href="{{ '/assets/labs/entra-app-consent-evidence-cases.jsonl' | relative_url }}" download="entra-app-consent-evidence-cases.jsonl">entra-app-consent-evidence-cases.jsonl</a>

```bash
python3 entra-app-consent-evidence.py entra-app-consent-evidence-cases.jsonl
```

```text
normal_delegated: matching_success_response
tenant_wide_delegated: matching_success_response
app_only: matching_success_response
no_resource_observation: grant_only
same_name_other_tenant: different_identity_or_resource
wrong_user: different_delegated_user
outside_observed_grant: outside_grant_window
denied_read: matching_denied_response
wrong_resource: different_identity_or_resource
missing_mode: request_context_missing
other_token_permission: different_token_permission
accepted_async: inspect_response_semantics
```

If the command fails, check the working directory and filenames. If the result surprises you, compare tenant and object IDs first, then the permission type, user, time and status. In `outside_observed_grant`, the request warrants checking a previously issued token, another grant or a timing error. The supplied evidence supports no single cause. The offline exercise was executed with Python 3.12. Entra, Microsoft Graph and the query were reviewed against official documentation.

## 6. Check your reasoning

- **Is AllPrincipals app-only?** No. It widens delegated consent to users in the tenant. Inspect app role assignments for app-only permissions.
- **Does an authorized grant prove data access?** Identify the request at the target resource. Check the response and any additional resource audit needed for the data effect.
- **What if the same app name appears in another tenant?** Compare tenant and object IDs. On a multitenant app even a matching application ID can correspond to different tenant service principals.

Complete the exercise by reproducing all twelve outputs and naming the next source for `grant_only` (the `no_resource_observation` case), `outside_observed_grant` and `accepted_async`.

## Official references

Reviewed 2026-11-22. The permissions model below refers to Microsoft Graph v1.0. Verify your cloud environment, licenses, schema and enabled log destinations before interpreting coverage.

- April 2025 reference for Entra audit activity names. [Microsoft Learn · Application permission audit activities](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs)
- Delegated grant object, consent scope and IDs. [Microsoft Learn · Microsoft Graph v1.0 · oAuth2PermissionGrant](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0)
- Role, resource and principal types. [Microsoft Learn · Microsoft Graph v1.0 · appRoleAssignment](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0)
- Collection prerequisites, joins and resource tenant boundary. [Microsoft Learn · Microsoft Graph activity log overview](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
- October 2026 MicrosoftGraphActivityLogs schema. [Microsoft Learn · Azure Monitor table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)
- Evidence collection, containment and recovery for compromised or malicious apps. [Microsoft Learn · Application investigation playbook](https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-compromised-malicious-app)

[Previous · OAuth and OpenID Connect]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}) · [Related · Entra sign-in investigation]({{ '/wiki/entra-signin-evidence/' | relative_url }})
