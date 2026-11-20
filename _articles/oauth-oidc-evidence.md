---
title: "OAuth 2.0 and OpenID Connect: From Sign-in to API Evidence"
description: "Follow an authorization code flow, distinguish token purposes, and trace eight synthetic API decisions to application audit records."
category: cloud
tags: [OAuth 2.0, OpenID Connect, JWT, IAM, Cloud Security, Blue Team, Purple Team]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/oauth-oidc-evidence/
---

**Learning goal.** Explain why a signed-in user can still get an API denial, identify the check involved, and find the evidence for what the application did.

## 1. Four roles, two different questions

Imagine opening a Reports Portal and reading one report. The **user** signs in. The **client** (Reports Portal) sends requests on the user's behalf. The **authorization server** authenticates the user as needed, evaluates the grant, and issues credentials. The **resource server** (Reports API) decides whether to accept an API call. In OpenID Connect (OIDC), the authorization server also acts as the **OpenID Provider** and the client is the **relying party**.

**OAuth 2.0** lets the client obtain limited access to a protected service. **OIDC** adds an identity layer so the client can establish who signed in. A **claim** is an assertion such as the issuer or audience. A **scope** is a permission label defined by the service, such as the fictional `reports.read`. The API can apply additional rules, such as whether this user may read this particular report.

| Credential | Who uses it and where | Purpose |
| --- | --- | --- |
| Authorization code | Client presents it to the authorization server's token endpoint | Short-lived, single-use intermediary exchanged for tokens |
| ID token | Client validates it for its own client identifier | Evidence of the user's authentication for that client |
| Access token | Client presents it to its intended API | Credential the API evaluates for the requested operation |
| Refresh token, if issued | Client presents it to the authorization server's token endpoint | Obtain new access tokens subject to server policy |

A **JWT** is a format that can carry claims. An ID token uses JWT. An OAuth access token may use JWT or be opaque to the client. A **bearer** token can be used by whoever possesses it, subject to its validity and the API's authorization rules. A sender-constrained token also requires proof tied to the authorized sender. Treat token values and authorization codes as credentials.

## 2. A successful request, step by step

![Four steps: client starts sign-in, authorization server returns a code, client exchanges it for tokens, API validates access and checks permission before the app records its result.]({{ '/assets/diagrams/oauth-oidc-flow-en.svg' | relative_url }})

1. Ada opens Reports Portal. The client starts an OIDC authorization code request containing the `openid` scope. The browser goes to the authorization server, which signs Ada in and obtains consent if policy requires it.
2. The browser returns to the client's registered callback with a code. The client matches this response to the initiating transaction. With **PKCE**, the token endpoint checks a verifier against the challenge bound to the authorization request. This ties redemption to the client instance that initiated it.
3. The client exchanges the code, with the verifier, at the token endpoint. It validates the ID token and establishes the application session. The expected audience at this step is the client ID. The client sends the access token to Reports API over TLS using the Authorization header.
4. Reports API evaluates the access token for its own audience and checks the permission for the route and the report. On the normal path, the resulting read is logged by the application. The identity provider's sign-in record, API decision, and report audit record answer different questions.

For example, suppose the Portal's client ID is `reports-portal` and the API identifier is `reports-api`. In this configuration the ID token's `aud` identifies `reports-portal`, and the access token's `aud` identifies `reports-api`. Access still depends on `reports.read` and the policy for the particular report. The labels are illustrative. Verify audience values against the real issuer and API configuration.

RFC 9700 (January 2025) recommends the code flow for this pattern. It requires PKCE for public clients and recommends it for confidential clients. A public client cannot keep a shared client secret confidential. Treat the implicit flow in older diagrams as historical guidance for most deployments. The resource owner password credentials grant must no longer be used under this BCP.

## 3. What does a valid signature buy you?

A signature checked against a trusted key helps verify integrity and provenance. A readable payload establishes only that it could be decoded. For a JWT access token, the API should rely on a maintained library and its issuer's token contract. Configure the issuer, trusted verification keys and permitted algorithms. Evaluate the expected **token type**, **issuer** (`iss`), **audience** (`aud`), and the validity window (such as `exp` and `nbf` when applicable). A JWKS is a set of public keys. Use the keys advertised for the configured issuer and plan for rotation. A token's key identifier (`kid`) can assist selection within that set.

RFC 9068 specifies `at+jwt` (or `application/at+jwt`) for its access token profile. Issuers using other profiles have their own contracts. An opaque token needs the API's supported validation mechanism, such as authorized introspection, followed by the API's permission checks. An OIDC client separately checks the ID token according to OIDC, including issuer, its own audience, expiry and the matching nonce if requested. **Nonce** ties an ID token to a specific authentication request.

| Question | What the result establishes |
| --- | --- |
| Is the credential acceptable for this API? | Token validation. A signed token for another service can fail here. |
| Is this operation permitted? | Authorization. Scope, roles or permissions and resource rules can differ by route and identity type. |
| Did the requested action occur? | Application or worker audit. A permit can be followed by a downstream error or an asynchronous action. |

### How misuse appears to a defender

A token leaked into a debug log can permit replay while it remains usable. A service that accepts the wrong token purpose or audience can cross a trust boundary. An overly broad grant can also let an otherwise valid client perform more actions than its workflow requires. Look for validated evidence in the API and app, changes in grant or client configuration in the identity provider, and correlated logging or tracing exposure. Avoid ranking an IP address, repeated request, or unusually timed grant as proof by itself. Authorized control validation can use known test principals and check the expected deny outcomes and audit coverage before a release.

## 4. Collect the decision, then verify the effect

| Source | Collect if available | Interpretation |
| --- | --- | --- |
| Identity provider | UTC time, tenant and client IDs, sign-in or grant outcome, session or correlation ID, changes to consent or scopes | Explains authentication, grant or administrative context. Refreshes and workload flows may occur without a fresh user sign-in. |
| API gateway or API middleware | Resolved environment and service, server-generated request or trace ID, route template, status, validation category and authorization decision | Explains which check the API reports. Capture only trusted or allowlisted metadata. Treat pre-validation claim values as untrusted. |
| Application or worker audit | Scoped request or job ID, pseudonymous subject and object identifiers as approved, operation and result | Confirms the outcome for the event and system covered by this audit source. |

Start at the observed request and expand by UTC time and trusted IDs, checking that identifiers propagate through services and are scoped to the correct environment and tenant. Record whether logs are enabled, retained, complete for this route and sampled. Preserve original audit records with restricted access. Redact Authorization headers, cookies, codes and token values from logs, trace payloads and tickets. Keep externally returned errors coarse and restrict access to detailed internal reasons. Do not paste live credentials into token viewers.

For a bearer API, RFC 6750 recommends HTTP 401 for an invalid token and 403 for insufficient scope. In actual deployments, proxies and API policies can change the response. Compare the middleware reason to the HTTP status. A burst of expiry denials could reflect stale credentials or clock drift. A wave of signature or key-selection failures after a rollout may warrant checking issuer metadata, cache behavior and key rotation. Confirm volume and baseline, then inspect the relevant deployment or identity audit. If exposure is corroborated, use the service's incident procedure to contain the affected grant, credentials or session, check resource activity, and verify when access ceases. Revocation coverage and timing depend on the issuer, token and API design.

## 5. Offline experiment · eight API requests

Download [the synthetic event log]({{ '/assets/labs/oauth-oidc-events.jsonl' | relative_url }}) and [the Python evidence reader]({{ '/assets/labs/oauth-oidc-evidence.py' | relative_url }}). Place them in one folder and run the following with Python 3. The timestamps in 2030 UTC and all decisions are fictional. The reader performs no token generation or validation and makes no network requests.

```sh
python3 oauth-oidc-evidence.py
```

Before running it, write down which cases should establish an app action. The reader matches audits by **environment, service and request ID**. Here both sources already share a synthetic identifier by design. Real systems may require a trace or job ID mapping from another source.

| Request | API observation | What the app evidence adds |
| --- | --- | --- |
| r-01 | Token and authorization pass, 200 | A matching record confirms the test read. |
| r-02 | Wrong token purpose, 401 | Expected denial at validation. |
| r-03 | Audience mismatch, 401 | Separate from token purpose. The token was intended elsewhere in this fixture. |
| r-04 | Expired, 401 | Check token renewal and clocks in a real investigation. |
| r-05 | Required scope absent, 403 | Token validation passed. Scope authorization denied the request. |
| r-06 | Permitted and queued, 202 | The audit with the same ID is from another environment. The final result remains unconfirmed. |
| r-07 | Permitted, 503 | A matching error record shows this attempt failed downstream. |
| r-08 | Scope passed, 403 | The application denied access to this particular object. |

**Expected result.** Eight API decisions, two matching audit records and one unmatched audit. Of the matches, one confirms a completed read and one records an error. If the files cannot be opened, confirm both names and the working directory. If a row is rejected, check its line number and that the file remains JSON Lines (one object per line). If the join count changes, compare the whole key and the input file; a bare request ID gives a false match in r-06.

The offline reader was run on the published fixture in a cloud environment. The protocol and vendor workflows were reviewed against documentation. No identity provider or live API was used. In a service you own or are explicitly authorized to test, verify the normal path with a test user and test object. Have the service team provision a second test identity without the required scope or resource grant, and confirm the deny reason and downstream audit behavior against the baseline. Keep the test credentials in the approved client and collect only disposition and request identifiers.

## 6. Check your understanding

1. **The client accepted an ID token. Should the API accept that same credential?** The API needs an access token under its own validation policy and audience. The ID token is intended for the client.
2. **Can the API return 403 after validating the access token?** Yes. Inspect route scope, roles and object rules. r-05 and r-08 differ at the authorization check.
3. **Does 202 prove the report was read?** It shows request acceptance for processing. Inspect a matching worker or application record before concluding the read happened.
4. **Can the same request ID prove activity in r-06?** Only with corroborated scope and propagation. This fixture has a collision across environments.

You are done when you can explain the two 403 decisions, distinguish the downstream error from the missing evidence, and cite a source and matching field for each confirmed action.

[Previous · Microsoft Entra sign-in investigation]({{ '/wiki/entra-signin-evidence/' | relative_url }}) · [Related · HTTP request and response evidence]({{ '/wiki/http-evidence/' | relative_url }}) · [Practice · Authorized validation and scope]({{ '/wiki/red-team-basics/' | relative_url }})

## Official references

Reviewed November 20, 2026. The dates below identify the editions used.

- January 2025 OAuth security BCP and current flow guidance. [IETF RFC 9700, sections 2.1–2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2)
- December 2023 OIDC Core with errata set 2; code flow and ID token validation. [OpenID Foundation, section 3.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
- October 2021 JWT access token profile; February 2020 JWT BCP on algorithms, trust and explicit typing. [IETF RFC 9068, section 4](https://www.rfc-editor.org/rfc/rfc9068.html#section-4) · [IETF RFC 8725, section 3](https://www.rfc-editor.org/rfc/rfc8725.html#section-3)
- October 2012 bearer usage and error semantics, as updated by RFC 9700; October 2015 token introspection. [IETF RFC 6750, section 3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1) · [IETF RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)
- May 2025 vendor documentation on Microsoft identity platform access tokens, including profile and metadata considerations. [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

## Passkeys and WebAuthn Sign-in Evidence

[Distinguish public-key verification, access policy and app sessions]({{ '/wiki/passkey-signin-evidence/' | relative_url }})
