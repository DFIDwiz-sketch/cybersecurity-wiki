---
title: "Kubernetes Service Account Evidence · Trace a Pod Token to an API Decision"
description: "Trace token projection, audience, expiry and object binding, then distinguish authentication, authorization and API outcomes in nine offline cases."
category: cloud
tags: [Kubernetes, Cloud Security, Service Accounts, RBAC, Audit Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/kubernetes-service-account-evidence/
---

A **ServiceAccount** is a namespaced identity for software. A **service account token** is a credential that software can present to prove that identity. The same account can be assigned to several Pods. A token is a bearer credential, so the username in a request establishes the accepted identity, while the actual caller still has to be investigated. Using short-lived, audience-limited credentials and tightly scoped permissions limits what a leaked credential can do.

## 1. Follow the credential and the permission check

1. A Pod's `spec.serviceAccountName` selects an account in its namespace. Kubernetes assigns the namespace's `default` account if no account is specified. Check the actual Pod, since its configuration may differ from the deployment template.
2. On modern clusters, Kubernetes normally adds a projected volume for API credentials. Kubelet uses the TokenRequest API to obtain and refresh a Pod-bound token. The application reads that file. A stale in-memory copy can outlive the file it was read from. The Pod's `automountServiceAccountToken` setting takes precedence over the account setting for automatic mounting. Also inspect explicitly configured projected volumes.
3. The API server verifies the token. It checks the issuer and signature, whether the token is within its validity period, whether an audience is accepted by that API, and the applicable object bindings. A UID identifies an object instance. Deleting and recreating a same-name Pod or ServiceAccount creates a different UID. Inspect the token review evidence available from the intended verifier, along with the object lifecycle.
4. Authentication establishes a username such as `system:serviceaccount:reports:reader`. Authorization checks the action. For RBAC, a role's rules describe permitted verbs and resources and a binding grants those permissions to the subject. Use the target namespace when inspecting namespace-scoped grants. Admission and subsequent processing can still affect the outcome. Correlate the final audit stage and response with the earlier decision.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-service-account-evidence-en.svg' | relative_url }}" alt="The Pod selects an account, kubelet requests an object-bound token, and the app reads that token. The API authenticates it, an authorizer checks the action, and the audit event records the outcome.">
  <figcaption>Follow ownership and token lifecycle first, then check the action and its recorded result.</figcaption>
</figure>

| Observation | What it supports | What to check next |
| --- | --- | --- |
| Pod spec names a ServiceAccount | Intended identity for that Pod | Pod UID, actual projection and relevant token audience |
| `create` on `serviceaccounts/token` | An issuance request was observed | Requesting identity, target account and response code |
| Signature, audience and lifetime checks pass offline | JWT checks passed for that verifier | Current bound-object validity, if required |
| API authorizer allows a named read | Authorization permitted the action | Final response, target and workload context |

## 2. A normal read and two distinct failures

In a fictional cluster the `reporter` Pod in `reports` uses ServiceAccount `reader`. A RoleBinding in `reports` grants that subject a Role permitting `get` on the named ConfigMap `render-options`. At 09:02 UTC the application reads its projected credential and the API accepts it for the expected audience. An audit event records `verb=get`, the intended ConfigMap, an authorization allow when that annotation is available, and `responseStatus.code=200`. These observations support a successful named read by the accepted account. The workload's own logs and controller records can help establish which replica ran it.

A copy retained after expiry can instead produce a 401. Check credential refresh, client clock and verifier diagnostics if available. A current credential can receive 403 for a resource outside the role. Inspect the final status and any authorization annotation. A 403 paired with an allow requires looking beyond the authorization decision, including the response reason and admission for an applicable write. Kubernetes and intermediary HTTP responses can have different causes. Confirm which component returned the status.

## 3. Object binding and a verifier's view

The **audience** identifies the intended recipient, such as a particular Kubernetes API or a specific external service. The **expiry** bounds the token's lifetime. Kubernetes validates the relevant object UIDs for a bound credential. The bound object must exist and its UID must match. For an object pending deletion, the documented check rejects authentication once 60 seconds have elapsed since its deletion timestamp. Record deletion state, observation time and actual verifier evidence before judging whether a token should still work.

An external application using only discovery keys and JWT checks can continue accepting a token whose signature, audience and time still pass after the associated Pod is gone. The Kubernetes documentation calls for **TokenReview** when the external verifier needs current validation of the binding. The application should explicitly provide its expected audience and check the authentication result and returned audience. This decides whether the presented credential is accepted for that verifier. The application still needs its own authorization policy.

## 4. Collect, investigate and respond

- **Collect a bounded record.** Preserve cluster identity, time, namespace, account and Pod UIDs, and approved workload ownership. From the API audit backend preserve `auditID`, relevant stage, `user`, `impersonatedUser` if present, verb, object/subresource, status and authorization annotations if available. Confirm that policy and retention cover this resource, subresource and stage. For sensitive token endpoints use metadata-level collection where supported and approved. TokenRequest responses and TokenReview requests can carry credentials in bodies. Keep raw bearer strings out of tickets, lab files and diagnostic output.
- **Triage abnormal issuance and use independently.** Compare `create` on `serviceaccounts/token` and workload activity against known kubelet rotation, approved automation, then account ownership and RBAC history. Flag successful reads outside the workload's purpose even when the identity is expected. Account reuse across replicas, rollouts or shared egress can explain activity changes. IP, User-Agent or a ServiceAccount name alone cannot establish a compromised Pod or a person. Use application logs, deployment history and endpoint evidence.
- **Limit exposure with the service owner.** Preserve the event and binding histories, scope who could read the credential, and identify each intended and actual accepting service. Review least-privilege grants and automatic mounting for workloads that need no API access. Coordinate containment or workload replacement with the owner. Verify acceptance again at each relying service, especially when external verification checks expiry independently. Long-lived Secret-backed credentials are a legacy option with a different lifecycle. Automatic creation stopped by default in v1.24, and manually provisioned legacy tokens can still exist.

## 5. Offline lab · nine fictional observations

Download both files into one folder and run from that folder with Python 3.10 or later. The JSONL contains **fictional normalized observations**. It contains no token strings and the Python reader performs no authentication or network activity. `null` is missing evidence, not a failed check. Each exercise row describes one decision rather than all log events needed to form it.

<a href="{{ '/assets/labs/kubernetes-service-account-evidence.py' | relative_url }}" download="kubernetes-service-account-evidence.py">kubernetes-service-account-evidence.py</a> · <a href="{{ '/assets/labs/kubernetes-service-account-evidence-cases.jsonl' | relative_url }}" download="kubernetes-service-account-evidence-cases.jsonl">kubernetes-service-account-evidence-cases.jsonl</a>

```bash
python3 kubernetes-service-account-evidence.py kubernetes-service-account-evidence-cases.jsonl
```

```text
expected_read: read_observed
wrong_audience: wrong_audience
expired_copy: outside_validity
deleted_pod: pod_binding_rejected
recreated_account: account_binding_rejected
external_after_delete: jwt_checks_only
outside_grant: authorization_denied
admission_denied: inspect_after_allow
incomplete_binding: insufficient_evidence
```

In `external_after_delete`, the offline verifier observes only issuer/signature, audience and time. It reports the scope of its checks. In `admission_denied`, the fictional case has a 403 after authorization allow. A real analyst would need the status reason and admission or component logs before naming the cause. If the commands fail, check the working directory and filenames. If you get a different classification, inspect the verifier field and distinguish a missing fact from a false one. The offline cases were executed with Python 3.12. Cluster behavior was reviewed against official documentation.

## 6. Check your understanding

- **Why might a recreated same-name Pod still be rejected?** The old credential is bound to an object instance. The new object's UID differs.
- **Why is an offline pass consistent with a failed TokenReview?** The offline checks don't resolve live bindings. TokenReview can check object existence and identity against the cluster.
- **Does a 403 prove a missing RBAC grant?** Use the responding component and decision evidence. A request can pass authorization and fail later.

Complete the exercise by reproducing all nine outputs, stating the next source needed for `incomplete_binding`, and separating account identity, token validity and authorization in `outside_grant`.

## Official references

Reviewed 2026-11-22. The projected bound token mechanism has been stable since v1.22. The task reference below is pinned to v1.36. Confirm managed-cluster audit exports and policy against the provider and deployed version.

- ServiceAccount identity, short-lived and legacy credentials. [Kubernetes · Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/)
- Bound-token validation, UID and deletion checks, offline verification limits. [Kubernetes · Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- Token projection, audience and kubelet refresh in Kubernetes v1.36. [Kubernetes · Configure Service Accounts for Pods (v1.36)](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- Authorization decisions and admission order. [Kubernetes · Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- Audit stages, levels and backend requirements. [Kubernetes · Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

[Previous · Kubernetes API audit logs]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) · [Related · OAuth and OpenID Connect]({{ '/wiki/oauth-oidc-evidence/' | relative_url }}) · [Related · Kubernetes NetworkPolicy]({{ '/wiki/kubernetes-network-policy-evidence/' | relative_url }})

## Trace the RBAC grant

Use [Kubernetes RBAC evidence]({{ '/wiki/kubernetes-rbac-evidence/' | relative_url }}) to trace binding scope, subresource rules, and historical evidence of use.
