---
title: "Kubernetes Pod Security Admission Evidence · From Template to Running Pod"
description: "Distinguish warnings, audit annotations, Pod admission and runtime evidence, then classify eight fictional cases offline."
category: cloud
tags: [Kubernetes, Pod Security Admission, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/kubernetes-pod-security-admission-evidence/
---

A Deployment can exist while its controller is unable to create any Pods. That becomes easier to investigate once you separate the template request, the Pod request, and evidence from a running workload. This chapter focuses on the built-in Kubernetes **Pod Security Admission (PSA)** controller and its audit evidence.

## 1. Where Pod Security Admission acts

A **Pod** is the unit that Kubernetes schedules to a node. A **namespace** scopes names and policy for resources such as Pods and Deployments. **Admission** evaluates an API request after authentication and authorization and before persistence. PSA evaluates a Pod’s declared security settings against **Pod Security Standards (PSS)**. This is one policy layer. RBAC determines who may make the request. NetworkPolicy and runtime telemetry answer different questions about allowed traffic and observed activity.

The standards define three levels. **Privileged** adds no PSS restrictions. **Baseline** limits several common routes to elevated privileges while supporting typical workloads. **Restricted** adds hardening requirements. For example, a Linux container under a recent Restricted policy needs `allowPrivilegeEscalation: false` and must be required to run as non-root. This is a partial example. The full requirements depend on the policy version, fields and OS.

| PSA mode | What happens on a violation |
| --- | --- |
| `enforce` | Blocks the violating Pod request evaluated for enforcement. Workload templates are evaluated separately. |
| `audit` | Adds a violation annotation to the Kubernetes audit event when recorded. The mode itself allows the request to continue. |
| `warn` | Returns a user-facing warning. The mode itself allows the request to continue. |

Namespace labels use `pod-security.kubernetes.io/<mode>` and optionally `pod-security.kubernetes.io/<mode>-version`. Modes can have different levels or versions. Pin versions during a rollout to make the intended comparison reproducible. Unlabeled namespaces can inherit cluster-configured defaults. Check the admission configuration and exemptions before judging an unlabeled namespace.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-pod-security-admission-evidence-en.svg' | relative_url }}" alt="A Deployment template can be checked for warnings and audit annotations. Its controller later submits a separate Pod request. Enforcement may block that request, or the Pod may be created and continue to scheduling and runtime.">
  <figcaption>Collect the Deployment and resulting Pod requests separately. They have different callers and audit IDs.</figcaption>
</figure>

## 2. Follow an ordinary staged rollout

In the fictional `reports-lab` namespace, a team enforces Baseline and uses Restricted for both audit and warning. The three modes are pinned to the same supported policy version. A Deployment called `month-end` uses a Linux Pod template that meets Baseline but does not specify non-root execution. The deployer gets a Restricted warning and the Deployment can be stored. The controller later requests a Pod. That Pod meets Baseline, so PSA can let it proceed, and audit can record a Restricted violation. Pod creation still has to pass other controls. Confirm its UID, scheduling and container status separately.

Suppose the team later moves enforcement to Restricted while the template still has that missing setting. The Deployment can still be accepted by PSA. Enforcement runs on the Pods the controller requests, so replacements can be rejected. Changing a namespace’s enforcement labels can return warnings about existing Pods. The change does not itself evict those Pods. Verify the behavior of the next creation and review currently running Pods separately.

## 3. Read the evidence at the correct layer

| Evidence | What to inspect |
| --- | --- |
| Namespace config and change history | Per-mode labels, policy version, server defaults and exemptions at the time. A current label screenshot is a current observation. |
| API audit event | Cluster, audit ID, stage, verb, object reference, user, response status and annotations. Match the Pod request, which often has a controller identity. |
| CLI warning or API status message | The actual violation or rejection for that request. Preserve the reference and time. Authorization allowed plus HTTP 403 can have several causes. |
| Workload and runtime | Deployment and ReplicaSet owner references, controller events, Pod UID and status. If no Pod was created, look for the controller’s failed Pod request. |

On an audit event, `pod-security.kubernetes.io/enforce-policy` identifies the enforcement level and version used. Its presence alone does not identify a denial. `pod-security.kubernetes.io/audit-violations` gives violation details for the audit policy. `pod-security.kubernetes.io/exempt` can indicate a user, namespace or runtime-class exemption. An exemption skips all three modes for the matching request. Exempting a controller can affect every user who can trigger it, so investigate unintended exemptions with the platform owner. Audit annotations are fields on API audit events. Kubernetes workload Events are a separate evidence source and may have short retention.

## 4. Collect, detect and respond

1. Start with cluster, namespace, workload, policy version and a UTC window. Obtain the namespace labels and change history. Confirm the plugin is enabled and ask the platform owner for effective defaults and exemptions if you cannot inspect the control plane.
2. Verify that audit policy and backend retain the relevant Pod, workload and namespace requests. Preserve completed stages, exact response status and audit annotations. Body capture requires higher audit levels than Metadata. Use it only where approved and protect sensitive request content. Missing annotations can reflect scope, stage or collection gaps.
3. Investigate namespace policy changes, unexpected exemptions and recurring denials. Compare changes with rollout approvals. Trace Deployment to ReplicaSet and Pod using owner references or controller status, then match the scoped audit records. If the Pod request was rejected, preserve the rejection and check the template. If it was admitted, check actual Pod status and runtime evidence.
4. When available, use API-server metrics `pod_security_evaluations_total`, `pod_security_exemptions_total` and `pod_security_errors_total` for baselines. These counters describe evaluations, exemptions or errors. They cannot identify a specific workload or prove that a container ran. After a fix, verify a compliant control and observe actual controller-created Pods.

Use these read-only commands on an approved cluster. Replace `reports-lab` and `month-end` with the approved namespace and workload. You need `kubectl` and permission to read the named namespace, Deployment, ReplicaSets, Pods and Events.

```bash
kubectl config current-context
kubectl get namespace reports-lab --show-labels
kubectl -n reports-lab describe deployment month-end
kubectl -n reports-lab get replicasets,pods
kubectl -n reports-lab events --types=Warning
```

In a disposable, approved lab namespace, compare two reviewed Pod manifests that differ only in the Linux non-root requirement. A server-side dry run of creation, using `kubectl -n reports-lab create --dry-run=server -f pod-reviewed.yaml`, can test the admission path if your role has create permission and the involved admission plugins support dry run. Use the name of each reviewed file. Record the effective labels, client response and corresponding audit record if enabled. The dry run creates no stored Pod, so it cannot test controller reconciliation or node runtime. The Kubernetes commands and behavior were reviewed against upstream documentation. A live cluster was outside this run.

## 5. Offline exercise · classify eight fictional observations

Save the <a href="{{ '/assets/labs/kubernetes-pod-security-admission-evidence.py' | relative_url }}" download="kubernetes-pod-security-admission-evidence.py">Python script</a> and <a href="{{ '/assets/labs/kubernetes-pod-security-admission-evidence-cases.json' | relative_url }}" download="kubernetes-pod-security-admission-evidence-cases.json">fictional JSON inputs</a> together. Run Python 3 in your own approved workspace. Cases combine normalized, fictional audit and client observations. Fields such as `storedPodUid` and `denialSource` represent separate corroboration and are supplemental to native audit event fields. The script reads local data only and does not evaluate Pod manifests.

```bash
python3 kubernetes-pod-security-admission-evidence.py kubernetes-pod-security-admission-evidence-cases.json
```

```text
template_warning: template_accepted_check_pod
pod_denied: psa_denied
audit_only: pod_stored_audit_violation
other_403: rejection_source_unconfirmed
exemption: exempt_request
server_dry_run: dry_run_no_persistence
pod_stored: pod_stored_check_runtime
partial_event: outcome_unobserved
```

If the script cannot open its file, verify both names and your current folder. For an unexpected classification, check whether the resource was a Deployment or a Pod, whether the final stage is available and whether corroboration establishes PSA as the source. Python was executed against these fixtures.

## 6. Check your understanding

- **A Deployment returned 201 with a Restricted warning. Was a Pod admitted?** Check the separate Pod request and controller reconciliation.
- **A Pod request has an enforce-policy annotation and returned 403. Does that prove PSA blocked it?** Obtain the denial reason or other corroboration. The annotation indicates the policy that applied to the evaluation.
- **One Pod was created successfully. Does that show its container ran?** Check scheduling and container status or runtime telemetry.

Finish when all eight results match and you can name the additional evidence required for `template_warning`, `other_403` and `pod_stored`.

## Official references

Reviewed 2026-11-22. PSA is stable since Kubernetes v1.25. Behavior was checked against upstream documentation including the v1.36 reference. Check the server release, mode version and provider logging availability for your environment.

- Policy modes, workload scope and exemptions. [Kubernetes v1.36 · Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- Policy levels, OS-specific and versioned restrictions. [Kubernetes · Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- Namespace label changes and server dry run. [Kubernetes · Enforce Pod Security Standards with Namespace Labels](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)
- Audit policy, stages and PSA annotation names. [Kubernetes · Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Audit Annotations](https://kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/)
- Workload Events command and options. [Kubernetes · kubectl events](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_events/)

[Previous · Kubernetes audit evidence]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) · [Next · Kubernetes NetworkPolicy evidence]({{ '/wiki/kubernetes-network-policy-evidence/' | relative_url }})
