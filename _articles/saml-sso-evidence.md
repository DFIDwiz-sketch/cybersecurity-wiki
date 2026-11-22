---
title: "SAML SSO Evidence · From Identity Provider to Application Access"
description: "Trace SAML issuer trust, assertion checks, session creation and application authorization with ten fictional investigations."
category: cloud
tags: [SAML, SSO, IAM, Microsoft Entra, Cloud Security, Blue Team]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/saml-sso-evidence/
---

A SAML sign-in can succeed at the identity provider while the application rejects the response, declines to create a session, or denies a later action. Learn to locate the first missing or failed decision using evidence from both sides. The chapter follows SP-initiated SAML 2.0 Web Browser SSO with an HTTP POST response.

## 1. Who trusts whom?

**Security Assertion Markup Language (SAML)** is an XML-based federation standard. Federation lets an application rely on an identity system it has agreed to trust. The user signs in to the **identity provider (IdP)**. The **service provider (SP)** is the application that receives the result and decides whether to start its own session. An **assertion** contains statements about a subject, such as an authentication event and attributes. The **response** is the protocol envelope carrying a status and, on the successful path here, an assertion.

The SP and IdP establish trust before a sign-in. The SP’s **entity ID** identifies the service logically. Its **Assertion Consumer Service (ACS)** is the endpoint that receives the response. Federation metadata can describe identifiers, endpoints and signing keys. Obtain it through the agreed, authenticated channel and scope it to the correct tenant and app. The certificate used by a browser to establish HTTPS and the key configured by an SP to verify SAML signatures serve separate roles.

## 2. Follow an ordinary sign-in

Imagine a training expense portal with entity ID `urn:example:expenses` and ACS `https://expenses.example.test/sso/acs`. These are fictional identifiers. The portal saves request `req-17` and sends an `AuthnRequest` through the browser. The IdP authenticates the user or applies its existing session and policy, then issues a response. The browser delivers it to the ACS. For an SP-initiated flow the SP correlates the response to the pending request and evaluates the assertion against its configured trust and policy. It then attempts to map the subject to a local account. On success the portal can create a session. Opening an expense report still requires the portal’s own authorization.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/saml-sso-evidence-en.svg' | relative_url }}" alt="The SP sends a request, the IdP issues a response, and the SP checks it at the ACS. An accepted response goes through account mapping and session creation before the app evaluates access. A rejected response stops before a session.">
  <figcaption>Each step can produce its own evidence. For browser POST, the browser carries the response from IdP to SP.</figcaption>
</figure>

| Check | Question answered |
| --- | --- |
| Issuer and signature | Does the signed content used by the SP verify under the key trusted for this issuer and connection? |
| Audience | Is this SP's logical identifier within the assertion’s allowed audience? |
| Recipient and Destination | Does bearer confirmation name the receiving ACS? Does the response destination, when supplied or required, match the receiving endpoint? |
| InResponseTo | Does the response correspond to this SP’s outstanding request? Check the response and bearer confirmation according to the profile and binding. |
| Conditions and bearer expiry | Was the assertion usable at receipt, allowing only configured skew? The Conditions window and bearer confirmation deadline are separate. |
| Replay protection | Has this assertion already been accepted in the applicable replay scope? |
| Local mapping and authorization | Which local identity and roles were selected, was a session created, and was the operation permitted? |

An ID can occur in several places. The request ID identifies the original request, the response ID identifies the envelope, and the assertion ID identifies the claim set. A session reference is generated and logged according to the application. The unsolicited IdP-initiated profile lacks the original SP request, so its enabled flows and investigation expectations need a separate baseline.

## 3. Understand failures and misuse

An audience mismatch can follow a copy of staging settings into production. An ACS mismatch can appear after a host or path migration. At either boundary of a time window, compare the SP receipt timestamp, time synchronization and configured tolerance with the assertion’s conditions and bearer expiry. `NotOnOrAfter` is an exclusive upper bound before any allowed skew. Assertion expiry governs acceptance. An already established application session has its own controls and lifetime.

A bearer assertion is sensitive because possession matters. Replay is an attempt to use one again. A duplicate rejection can also reflect browser resubmission or an application retry. Look for the previously accepted event and confirm the replay records cover the nodes that handled the requests. A signing key compromise undermines trust in apparently valid signatures. A key mismatch immediately after planned rotation can also arise because an SP has stale metadata or still trusts only the old key. A signature also needs to cover the data the application actually consumes. Use a maintained SAML library and the signing configuration agreed for that integration.

## 4. Collect, detect and respond

| Source | Fields to ask for |
| --- | --- |
| IdP and change audit | UTC, tenant, app, identity reference, outcome, policy and authentication context, federation configuration or certificate changes if audited |
| SP federation or ACS diagnostics | UTC, tenant/connection, app and node, safe request or assertion reference, validation reason, key reference, metadata version and endpoint |
| App session and business audit | UTC, scoped transaction or session reference, mapped account, role, action, resource and decision |

Confirm diagnostics are enabled, access-controlled, time-synchronized and retained across all receiving nodes before treating a missing record as a gap. Field and reason names in this chapter are conceptual. Entra sign-in logs show the IdP side; collect the application’s audit separately. Do not assume that the Entra correlation ID is the SAML request ID or present in the SP. Use a documented shared reference where available. With only matching app, time and identity, describe a candidate association and record the remaining uncertainty. Keep raw assertions, cookies and unnecessary identity attributes out of routine tickets and test exports. Use restricted originals and approved, consistently pseudonymized references when investigating.

Baseline acceptance and rejection reasons per integration and deployment. A rise in unknown signing keys across one application after a change calls for a comparison of the key reference, active metadata and change ticket. Repeated accepted references across nodes warrant checking the replay control and distinguishing retries, duplicate log shipping and distinct sessions. An accepted assertion followed by a role escalation warrants checking local account mapping and business audit. Preserve the configuration versions and event timeline, involve the IdP and application owners, and address the affected trust and sessions through the incident process. When investigating suspected key exposure, scope which SPs trust the key, coordinate rotation and determine how to invalidate application sessions. Recheck expected access after containment.

## 5. Offline exercise with fictional records

Save the <a href="{{ '/assets/labs/saml-sso-evidence.py' | relative_url }}" download="saml-sso-evidence.py">Python analysis script</a> and <a href="{{ '/assets/labs/saml-sso-evidence-cases.json' | relative_url }}" download="saml-sso-evidence-cases.json">fictional JSON cases</a> in one directory. Run this in your own approved workspace with Python 3. It reads local JSON and reports the furthest supported stage for each case. It uses preassigned ACS verdicts and a fictional correlation reference. It neither processes SAML messages nor contacts a service.

```bash
python3 saml-sso-evidence.py saml-sso-evidence-cases.json
```

The numbered fixtures represent a normal protected read, an IdP result with no ACS evidence, an ACS audience rejection, an accepted assertion with no session evidence, an explicitly rejected replay, an application denial after session creation, a transaction from another connection, a business record before session creation, a role-mapping denial, and an ACS record with a mismatched request. Predict the stages before comparing your output.

```text
normal: action_allowed
idp_only: acs_unobserved
wrong_audience: acs_rejected:audience
session_missing: session_unobserved
duplicate: acs_rejected:replay
action_denied: action_denied
other_connection: session_unobserved
early_action: action_unobserved
mapping_denied: session_denied
wrong_request: acs_unobserved
```

If the script reports a missing file, confirm both downloads and your current directory. If a record looks unlinked, inspect the tenant, connection, reference and event order. In a real exercise, collect these fields from both sides of an approved test tenant and compare the test’s isolated account and protected read operation to the observations. The publication check executed the synthetic analyzer. SAML message validation, Entra login and SP session controls were reviewed in documentation and require separate product testing.

## 6. Check your understanding

- **The IdP logs success and the ACS rejects the audience. Did the app log in?** That response was rejected by the ACS. Check for other transactions or a preexisting session before drawing conclusions about wider access.
- **The assertion signature verifies. What else is needed?** Check issuer trust, target, request binding, time and replay according to the profile. Then check local mapping, session creation and application authorization separately.
- **An action appears one second before its linked session. What can you report?** This exercise does not link it. In production, examine event-time semantics, clock offsets and connection scope before associating it.

Finish when your results match all ten lines and you can name the next source for `idp_only`, `session_missing` and `early_action`.

## Official references

Reviewed 2026-11-22. The OASIS standard and approved errata describe the protocol. NIST’s 2025 revision addresses federation assurance. The Microsoft references describe Entra product behavior for the documented SAML flow and configuration.

- Assertion, condition and protocol semantics. [OASIS SAML 2.0 Core (2005)](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- Browser SSO profile and POST processing, sections 4.1.4 and 4.1.5. [OASIS SAML 2.0 Profiles (2005)](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) · [Approved Errata 05 (2012)](https://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.html)
- Federation trust, replay protection and verification. [NIST SP 800-63C-4 (2025)](https://pages.nist.gov/800-63-4/sp800-63c.html)
- Microsoft Entra SAML request and response behavior. [Microsoft Learn · SAML SSO protocol](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol)
- Signing certificate rollover and metadata. [Microsoft Learn · Manage federation certificates](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on)
- Scope of Entra sign-in logs. [Microsoft Learn · Sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)

[Related · OAuth and OpenID Connect evidence]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}) · [Next · Microsoft Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }})
