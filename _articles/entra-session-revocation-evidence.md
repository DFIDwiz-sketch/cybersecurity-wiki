---
title: "Microsoft Entra Session Revocation · Verify Access at the Resource"
description: "Distinguish directory revocation, refresh failure, a claims challenge and actual enforcement on an existing session."
category: cloud
tags: [Microsoft Entra, IAM, OAuth 2.0, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/entra-session-revocation-evidence/
---

An administrator revokes a user's sign-in sessions after a lost device. The change appears in the directory audit log. The incident responder still needs to know what the existing client can do. Answer that question by following the affected session to the token service and to each resource that may still accept it.

## 1. Identify the credential and the decision point

An **access token** is presented to a resource API. A **refresh token** is used with the issuer to request new tokens. An **Entra sign-in cookie** lets the browser continue an identity-provider session. After sign-in, a service can issue its own **application session cookie**. That session has a separate lifetime and may have to be ended by the application. OAuth app-only access belongs to a service principal or managed identity. User-session revocation addresses a different principal.

| Observation | What it supports | Next evidence |
| --- | --- | --- |
| Directory audit shows a successful revocation | The administration operation succeeded for the recorded tenant and target | Check the session cutoff and downstream observations |
| Token service rejects a refresh as revoked | That specific refresh attempt could no longer obtain a token | Check existing access tokens and app sessions separately |
| Resource issues a claims challenge | That request did not satisfy the resource's current requirements | Inspect the original request and any reauthentication or final resource response |
| Resource returns an authenticated success for an existing session | The tested path still served the request | Confirm the credential lineage, precise action and application-side result |
| Application session is terminated or denied | Enforcement at that service for that observed session | Check other apps and user or workload identities as applicable |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/entra-session-revocation-evidence-en.svg' | relative_url }}" alt="After a directory revocation, check refresh at the token service and existing access at the resource independently. Check any application-owned session at the app. Each check supplies evidence for its own path." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Control-plane changes and enforcement at each resource answer separate questions.</figcaption>
</figure>

## 2. Follow a normal session, then a revocation

In a fictional tenant, a user signs in at 09:00 UTC and reads a test document. The client calls the resource with an access token and can renew its tokens through Entra. Another browser app establishes its own session after sign-in. At 09:10 an administrator revokes the Entra sessions. Microsoft Graph v1.0 documents that `revokeSignInSessions` moves `signInSessionsValidFromDateTime` to the current time and invalidates existing refresh tokens and Entra sign-in cookies, with a possible short propagation delay.

At 09:12 the token service rejects the existing refresh token with a revocation-related reason. At 09:13 a resource without Continuous Access Evaluation (CAE) still accepts a request using an already issued access token. Until expiration, resource-specific checks matter. At 09:14 an independent application session still serves a request and needs its own termination workflow. Refresh failure, continuing bearer-token use and a continuing app session can coexist. All these timestamps and observations are fictional.

**Continuous Access Evaluation** allows a supporting resource to evaluate selected events and policies before the ordinary token expiration. For the documented critical-event path Microsoft notes possible propagation latency of up to 15 minutes. The relevant resource, client capabilities and scenario must support CAE. Do not treat the timing figure as proof of protection for every app. On a supported API, a claims challenge arrives as a 401 with a Bearer `WWW-Authenticate` challenge including `insufficient_claims` and a claims directive. This shows the original call required updated claims. A later reauthentication and successful new request are possible if policy allows them.

## 3. Decide what the evidence actually proves

A compromised client may continue presenting a cached access token or a separate application session after an administrative action. A legitimate client can also use a cached credential briefly, reauthenticate, or silently switch to a session that was established later. Show evidence of *which* account, issuer and session lineage the resource evaluated before attributing activity to the original session or to an attacker. A later HTTP 200, a failed sign-in, an IP address, or a User-Agent in isolation cannot answer that question.

Microsoft Graph documents a boundary for external users. A resource tenant's call to this API does not revoke the guest's home-tenant sign-in sessions. Coordinate with the home tenant when appropriate, and verify the host tenant's own access controls and app sessions. Similarly, investigate app-only activity under the workload identity and its grants or credentials. Password change, disabling an account and revocation are different operations in the response timeline. Preserve each action and verify its applicable effect.

## 4. Collect, detect and respond

1. **Anchor the control-plane timeline.** In an authorized tenant with access to Entra audit logs, preserve the UTC time, activity, result, target object ID, initiating identity and tenant. Graph `directoryAudit` exposes fields such as `activityDateTime`, `initiatedBy`, `targetResources`, `result` and `correlationId`. With approved Microsoft Graph read access and the correct user object, request the cutoff property explicitly using `$select`. A current property value is a snapshot and can have advanced after the incident. Do not collect bearer tokens, cookies, or refresh tokens into tickets or shared logs.
2. **Follow the issuer and resource separately.** Record the affected user and token issuer tenant, client application, resource, operation and source time. Inspect applicable Entra sign-in categories and resource audit records. In dashboards, verify retention and export coverage before treating the absence of an entry as evidence. A token issued earlier can be reused without another sign-in event. Use trusted request IDs to correlate where they are designed for that purpose. IDs in different services need not match without an established link.
3. **Check enforcement under approved conditions.** Use a benign read in an owned test tenant with an approved account and application. Record whether the old session reached the resource, whether the resource challenged it, and whether a later action used a fresh session. Test different app session paths separately and confirm the expected scope with the owner. A denial with an unrelated access rule does not establish that revocation caused it.
4. **Track residual access.** Review post-action successful operations for the affected identity and separate old sessions, fresh sign-ins and other principals. Keep an open finding for unobserved resources or ambiguous sessions. When needed, coordinate application-side session expiry or account and device response under the incident plan, and verify each outcome at the resource.

## 5. Authorized offline exercise

Download the <a href="{{ '/assets/labs/entra-session-revocation-evidence.py' | relative_url }}" download>Python checker</a> and the <a href="{{ '/assets/labs/entra-session-revocation-evidence.json' | relative_url }}" download>fictional timeline data</a> together. Run with Python 3 in your own or approved environment. Fictional rows use explicit `tenant`, `user`, `surface` (the path under test) and `session` labels. These are pre-correlated exercise labels, not Entra field names or token values. The checker performs no authentication or network calls.

~~~bash
python3 entra-session-revocation-evidence.py
~~~

| Cases | Expected observations |
| --- | --- |
| A, B, C | Revoked refresh, accepted old access at the resource, accepted application session |
| D, E | Claims challenge without a final outcome, and attributable denial on the tested resource |
| F, G | Control success without downstream evidence, and an out-of-scope home-tenant session |
| H, I, J | Different session, unproven denial reason, and action failure |

Expect `10/10 cases matched.` For a negative control, change case B's `observation.session` from `old-session` to `new-session` in a copy, leaving its expected value in place. Pass the copy as an optional filename. B should change to `different-session` and the program should exit 1. If execution fails unexpectedly, check the fixture location and UTC timestamp format. Only the synthetic exercise was executed. Microsoft Graph, Entra and application enforcement were checked in documentation, without operating a live tenant.

## 6. Check your reasoning

1. **Does a successful revocation audit record prove an app can no longer read data?** It confirms the administrative action. Obtain evidence from the token service and affected resource or application session path.
2. **A 401 has an `insufficient_claims` challenge. Is access denied indefinitely?** It establishes the challenge on that request. Verify whether a subsequent approved request could satisfy it.
3. **A fresh session reads a document after revocation. Did the old session survive?** Compare session lineage and issuer. The fresh request cannot answer that question.
4. **Why can a guest or workload require a different investigation?** The guest's home tenant owns its sign-in session, while app-only traffic belongs to a workload principal. Use the authority and resource controls that apply to that path.

**Completion criterion.** Reproduce the ten outcomes and negative control. For a revocation, explain the affected identity and credential, the strongest observation at each hop, and the evidence you still need. Continue with [Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}) and [OAuth and OpenID Connect evidence]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-27. The scope is Microsoft Graph v1.0 and the Microsoft Learn documentation for current Entra emergency access revocation and supported CAE paths. Application sessions depend on the service. Check the applicable product version and tenant settings when narrowing an incident.

- [Microsoft Graph v1.0 · revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) and [user properties](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [Microsoft Entra · Revoke user access](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) and [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Microsoft identity platform · Claims challenges](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge)
- [Microsoft Graph v1.0 · directoryAudit](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0) and [Entra sign-in log activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)
