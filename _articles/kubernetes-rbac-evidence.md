---
title: "Kubernetes RBAC Evidence · Trace an API Permission"
description: "Trace Role and ClusterRole grants across namespaces, distinguish subresources, and verify effective access against audit evidence."
category: cloud
tags: [Kubernetes, RBAC, Cloud Security, Audit Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/kubernetes-rbac-evidence/
---

A service account can read a Pod in `reports` but cannot read its logs. Another account receives the same rules in a different namespace. To explain the difference, identify the exact API operation and trace the binding that applies to the caller at that time.

## 1. How the grant is assembled

**Authentication** identifies the requester and their groups. **Authorization** evaluates whether that identity may perform the API operation. With **role-based access control (RBAC)**, a rule describes a permission and a binding assigns it to one or more **subjects**: users, groups or ServiceAccounts. A **namespace** scopes objects and bindings within one cluster. An **API group** distinguishes groups of resources. The core group is the empty string, while deployments belong to `apps`. A **subresource** is a separate API target on a resource, such as `pods/log`. A resource's name and its resource type are different fields.

| Object | What it supplies | Where the grant applies |
| --- | --- | --- |
| Role | Rules maintained in a namespace | Through a RoleBinding in that same namespace |
| ClusterRole | Reusable rules with no namespace on the definition | Scope depends on its binding |
| RoleBinding | Subjects and a reference to a Role or ClusterRole | The binding's namespace, including for namespaced rules from a ClusterRole |
| ClusterRoleBinding | Subjects and a reference to a ClusterRole | Cluster-scoped resources or namespaced resources across namespaces, as covered by the rules |

Applicable RBAC grants add together. An absent rule makes that path insufficient, and a narrower binding cannot cancel a broader one. The API server can be configured with authorizers in addition to RBAC, so a missing RBAC match in a snapshot and the server's actual decision are separate findings.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-rbac-evidence-en.svg' | relative_url }}" alt="The API request identifies a caller and target. Check matching subjects, the binding's scope and the referenced rule. Compare the resulting RBAC grant with the live authorization decision and the audit outcome.">
  <figcaption>Trace who matches, where the binding applies and which rule covers the request. Then check the API response separately.</figcaption>
</figure>

## 2. Follow an ordinary grant

In this fictional example, the ServiceAccount `summarizer` exists in `reports`. A RoleBinding in `reports` references ClusterRole `pod-inventory` and names that ServiceAccount as a subject. The referenced rule is core group `""`, resource `pods` and verbs `get` and `list`.

1. `get` on `pods/daily` in `reports` matches the subject, namespace, verb and resource. Here `daily` is the object's name. In a rule the resource is written as `pods`.
2. Listing all Pods in `reports` also matches this rule. A request for `get` on `pods/log` in `reports` does not match it. To evaluate log access, use `get` on the `log` subresource. A separate binding may supply the missing permission.
3. A read of Pods in `archive` has no grant through the original binding, even though the definition is a ClusterRole. A separate RoleBinding in `archive` could name the same ServiceAccount, with `reports` in the subject's namespace. The scope still comes from the binding in `archive`.
4. A second Role in `reports` allows `get` on the ConfigMap `public-settings` using `resourceNames`. The same role does not grant access to other named ConfigMaps. Kubernetes permits some name-restricted list/watch requests only with a matching `metadata.name` field selector. Inspect the actual request and rule rather than assuming that a named read implies listing access.

For a permission check on an approved cluster, use your current training identity, already configured by the lab owner. Confirm the intended context first. These commands ask the API server about the permission and do not retrieve the named objects or read Pod logs.

```bash
kubectl config current-context
kubectl auth can-i get pods/daily -n reports
kubectl auth can-i get pods/daily --subresource=log -n reports
kubectl auth can-i get pods/daily -n archive
```

If the training identity has exactly the Pod grant described above, the answers are `yes`, `no` and `no`. A different answer calls for checking context, current identity and groups, other bindings, and configured authorizers. A connection, authentication or access-review error is a failed check. A successful check speaks to the current authorization decision for that request. It does not show whether a historical request reached storage, passed admission where applicable, or succeeded. These commands were reviewed against the official documentation.

## 3. Collect the evidence of change and use

Look for unexpectedly broader scope when a workload's access changes. For example, replacing a namespaced assignment with a cluster-wide binding can grant access beyond a deployment's intended namespace. Wildcards or changes to a shared ClusterRole can affect more subjects or resources than the change author intended. Kubernetes recommends the narrowest necessary grants. Treat high-risk permission changes as an investigation lead and verify ownership and approval before attributing intent.

- **Start with the policy change.** Preserve a time-stamped export of relevant Roles, ClusterRoles and bindings, their UID and resource version, plus change history and identity-provider group membership for the period. Check changes to both sides of a binding. A ClusterRole edit can affect many bindings, and aggregated ClusterRole rules can change when a contributing role changes. A live export only describes current state.
- **Correlate the API activity.** With control-plane audit collection configured for the relevant resources and stages, join records by cluster and `auditID`. Compare authenticated `user` and, if present, `impersonatedUser`, timestamps, `verb`, `objectRef` (API group, resource, subresource, namespace, name), relevant authorization annotations, and `responseStatus` at `ResponseComplete`. Where available, tie the request to an approved change ID. The metadata level can identify operations on RBAC objects, but it does not preserve the changed binding subjects or rules. Use authorized configuration history or narrowly scoped audit request capture when detailed before/after evidence is necessary. Keep credentials and response bodies out of routine exports.
- **Find the reason for failure.** A 403 alone can reflect authorization failure or a later rejection such as admission. When available, compare authorization decision and reason with the returned error and the operation's context. A successful access review is a decision about a planned action. A successful audit response to an actual operation is a separate observation. Neither by itself identifies the human behind a shared or automated identity.
- **Respond with the service owner.** Compare the subject and scope against intended access. Preserve the policy snapshot and audit interval before an approved correction. After narrowing a grant, check an intended allowed operation and a previously excessive operation and inspect workload health. If the subject was already used, review actual requests and affected resources over the exposure window separately.

## 4. Offline exercise

Use Python 3.8 or later in an approved training workspace. Download the <a href="{{ '/assets/labs/kubernetes-rbac-evidence.py' | relative_url }}" download="kubernetes-rbac-evidence.py">RBAC trace script</a> and the <a href="{{ '/assets/labs/kubernetes-rbac-evidence.json' | relative_url }}" download="kubernetes-rbac-evidence.json">fictional snapshot and requests</a> into the same directory.

```bash
python3 kubernetes-rbac-evidence.py kubernetes-rbac-evidence.json
```

The snapshot uses abbreviated fields. It is not a Kubernetes manifest. The script evaluates exact resource rules, exact verbs and API groups, and exact or unrestricted object names for named GETs. It uses the caller groups and request scope supplied in the fixture. It does not simulate authentication, wildcard rules, selector semantics, ClusterRole aggregation, admission, or other authorizers. It performs no network calls and prints the matching binding names for each request.

| Fictional case | Expected trace |
| --- | --- |
| `pod_in_reports` | `reports/pod-inventory` grants the named Pod read |
| `pod_in_archive` | No grant found for this ServiceAccount in `archive` |
| `pod_log` | No grant found for the `log` subresource |
| `wrong_serviceaccount_namespace` | No grant found for a same-named ServiceAccount from another namespace |
| `named_configmap` | `reports/public-config` grants the named read |
| `different_configmap` | No grant found for the other ConfigMap |
| `group_cluster_read` | `node-inventory` grants the cluster-scoped read through group membership |
| `overlapping_grants` | Both `reports/pod-inventory` and `reports/support-read` grant the action |

If the JSON file cannot be opened, check both filenames and the working directory. If a case unexpectedly prints `no_grant_found`, check the subject namespace, binding namespace, core group as an empty string, and the subresource. Try adding the existing fictional `support` group to `pod_in_archive` without changing the binding's namespace. The added group still has no matching grant there. The eight published cases were executed offline. No cluster was modified or queried for this exercise.

## 5. Check your understanding

1. **Does a RoleBinding that references a ClusterRole grant access in every namespace?** The RoleBinding applies within its own namespace. Check for other grant paths separately.
2. **Why can an account read a Pod object and still be unable to read its logs?** `pods` and `pods/log` are distinct rule targets. Evaluate the exact verb and subresource.
3. **How do you establish that unexpected access was actually used?** Find matching historical audit activity from the identity and relevant response stage. Join a time-appropriate policy and group history with the request, and identify what the response proves.
4. **A read persists after one grant is removed. What do you check?** Look for another applicable binding, including group membership and cluster-wide scope. Then check the configured authorizers and perform a current access review.

Complete the chapter when you can explain the matching binding for one allowed request, the missing permission for a subresource, and the evidence needed to move from possible access to observed use.

## Official references

Reviewed November 23, 2026 against the Kubernetes v1.37 documentation. Confirm behavior and audit availability against the cluster's actual version and provider.

- [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) covers rules, subjects and binding scope.
- [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) and [kubectl auth can-i](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/) cover access reviews.
- [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) covers least privilege.
- [Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) covers audit stages and policy.

[Previous · Kubernetes service-account identity]({{ '/wiki/kubernetes-service-account-evidence/' | relative_url }}) · [Next · Kubernetes API audit logs]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) · [Related · Pod Security Admission]({{ '/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }})
