---
title: "Kubernetes ResourceQuota · Trace Admission and Scheduling Failures"
description: "Distinguish namespace quota, per-container constraints and scheduler fit using API, controller and Pod evidence."
category: cloud
tags: [Kubernetes, ResourceQuota, LimitRange, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/kubernetes-quota-evidence/
---

A Deployment exists and its previous replicas still serve traffic, but none of its new Pods appear. The Deployment request and the controller’s Pod creation requests are separate API operations. Finding the first failed operation tells you whether to inspect the namespace’s policy, scheduler capacity, or something later in the rollout. This chapter follows ordinary Deployment-managed Pods on a cluster with the applicable admission controllers enabled.

## 1. Separate policy, placement and runtime

A **namespace** scopes objects and policy. A container’s CPU **request** is an amount the scheduler uses when fitting a Pod to a node. A **limit** is a runtime bound for the resource where supported. CPU can be expressed in millicores. `250m` is a quarter of a CPU and `1000m` equals one CPU. ResourceQuota can account for requested or limited amounts independently. Live usage in a metrics dashboard is a separate quantity.

| Mechanism | Scope and decision | What to look for |
| --- | --- | --- |
| ResourceQuota | Aggregate accounting in one namespace, optionally scoped to selected objects. Can constrain compute requests, limits, or counts such as non-terminal Pods | Quota name and affected resource. Compare applicable `status.used` and `status.hard` with the attempted accounting change |
| LimitRange | Defaults and per-object constraints for targeted object types, such as a Container or Pod. Can specify minimum, maximum, and limit-to-request ratio | The submitted resources, any defaults applied during admission, and the precise policy constraint |
| Scheduler | Matches an existing Pod’s requests and placement requirements to eligible nodes | Pod UID, scheduling condition and scheduler event message. A node can fail the fit even when there is room in the quota |
| Runtime | After scheduling, the kubelet and runtime act on the assigned Pod | Container status and events, such as `OOMKilled` or a failed readiness check. Check the node and relevant runtime observations |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-quota-evidence-en.svg' | relative_url }}" alt="A Deployment triggers a separate Pod create request. If Pod admission rejects it, investigate the API response or the controller event. If a Pod is persisted, investigate scheduling and then runtime separately." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. A successful Deployment request does not settle the outcome of its child Pod requests.</figcaption>
</figure>

## 2. Follow a normal rollout, then change one number

In this fictional namespace, `requests.cpu` has a hard quota of `2000m` and current accounted use of `1500m`. The Pod template has one container, no init containers or special overhead, CPU request `250m` and limit `500m`. Assume these satisfy the applicable LimitRange and all other checks. The Deployment’s ReplicaSet asks to create one Pod. Admission can accept this request, since `1500m + 250m = 1750m`. The API creates a Pod with its own UID. A scheduler can assign it only if an eligible node fits. The kubelet then starts the container and reports readiness.

Now change the attempted CPU request to `750m` and its limit to `1000m`, still within this fictional LimitRange. With accounted use still `1500m`, the prospective total is `2250m`. Quota admission rejects that Pod request. The ReplicaSet can surface a `FailedCreate` event. The earlier Deployment can still be stored successfully and previous replicas may still run. During a rolling update, include the old replicas and any intended surge when estimating simultaneous usage. Snapshot values can change as other Pods arrive or leave, so recover the values included in the original refusal where available.

## 3. Locate the first supported failure

- **Read the subject and actor.** A Deployment creation by a human or deployment service and a Pod creation by the controller have different audit IDs. Use the namespace, workload and controller owner references, Pod name or UID when available, and time. A rejected create may never have a Pod UID. Trace it from the ReplicaSet and the failed request.
- **Read the full reason.** A quota violation and a LimitRange violation can both return HTTP `403`. Authorization, Pod Security, or a webhook can also deny the request. An explicit quota response with `requested`, `used` and `limited` can support an exceeded-quota diagnosis. A quota response saying a resource request is missing points to incomplete specification or defaulting instead. `FailedCreate` alone identifies a controller failure to create, with the cause in the detail.
- **Check whether the Pod exists for this attempt.** A stored Pod UID plus `PodScheduled=False` and a matching scheduler event can support a scheduling diagnosis. `Pending` alone is broad. Even `FailedScheduling` names a stage, and its message may identify insufficient CPU, placement requirements, or several causes.
- **Treat a rehearsal as a rehearsal.** A server-side dry-run can exercise relevant admission checks without saving an object. Its success does not create a Pod, start a controller sequence, or reserve quota for a future request.

Abuse can include an unauthorized quota increase or workloads consuming more of a shared namespace budget than approved. Missized requests, legitimate traffic growth and rolling updates can have the same availability impact. Avoid inferring intent from the quota event. Restrict who can change quota policy and review change provenance. Existing Pods are not automatically removed when a quota is lowered. A next create may be blocked while current Pods continue running.

## 4. Collect, detect and respond

In the authorized cluster context, collect the Deployment and ReplicaSet status including the owner chain, generation and UTC times. Preserve events early because retention and aggregation vary. For an existing Pod, use the UID to distinguish a replacement with the same name. These examples are read-only and require `kubectl`, kubeconfig, and suitable `get`/`list` permissions in the target namespace. Replace the example names with the authorized objects:

```bash
kubectl -n team-a get resourcequota,limitrange -o yaml
kubectl -n team-a describe rs reports-6cf7c79c4b
kubectl -n team-a get events --sort-by=.metadata.creationTimestamp
kubectl -n team-a describe pod reports-6cf7c79c4b-abcde
```

Use the last command only if the Pod exists. For control-plane evidence, collect the completed Pod request’s timestamp, actor, verb, resource, namespace, audit ID, response code and any reason that survived export. The cluster must have audit collection with a policy covering those requests and the relevant stages. Body access depends on the configured audit level and provider export. A moderate retention policy and focused fields help avoid exporting unnecessary sensitive data. Inspect successful quota and LimitRange updates as well as denials.

For detection, track unique denied creation requests by namespace and controller, then compare them with rollout progress. Audit IDs group stages of **one** API request, not all retries of a rollout. Event series counts and audit request counts represent different units. Check request inflation and rollout overlap before changing a hard quota. If the quota or a template changed unexpectedly, preserve the prior and current configuration and the change actor. Roll back through the approved deployment path if needed. Confirm recovery with creation of the intended Pod, assignment, and readiness. A missing audit record may reflect a collection gap.

## 5. Authorized offline exercise

Download <a href="{{ '/assets/labs/kubernetes-quota-evidence.py' | relative_url }}" download>the Python checker</a> and <a href="{{ '/assets/labs/kubernetes-quota-evidence-cases.json' | relative_url }}" download>the ten fictional observations</a> into the same directory. Use Python 3 in an environment you own or are authorized to use. The exercise never calls Kubernetes. The JSON stores normalized triage facts, with the refusal type established separately from raw response detail. It is not a raw Kubernetes log parser.

```bash
python3 kubernetes-quota-evidence.py
```

| Compare | Expected finding |
| --- | --- |
| CPU quota and Pod-count quota | Both have an identified quota refusal, but the units differ |
| Missing request and per-container LimitRange refusal | Two different admission causes, even if both had `403` |
| Existing unscheduled Pod and existing Pod with `OOMKilled` | Scheduling and runtime respectively |
| Unknown `403`, dry-run success and Deployment-only evidence | Respectively unresolved cause, evaluation without storage, and no child outcome yet |
| Quota refusal with a conflicting numeric example | Keep the stated rejection and flag that the provided numbers do not establish an excess |

The checker uses integer millicores or object counts already normalized to the same unit. Expect `10/10 evidence cases matched.` If a field or JSON error appears, confirm both files came from the same edition and are stored together. If a case fails after editing, inspect its response, refusal reason and facts about an existing Pod before adjusting the expected label. Test a negative control by changing case A’s `requested` value from `750` to `500` while keeping its prior expectation. The checker should report a contradiction because exactly meeting the hard value is insufficient to explain an exceeded-quota response. Kubernetes API, scheduler, and logging examples in this chapter were reviewed against upstream documentation. The checker is an offline exercise with fictional input.

## 6. Confirm your understanding

1. **The Deployment exists, but the controller’s Pod creation returned `403`. Which source settles why?** The completed response detail and matching policy at that time. An authorization allow for another request will not resolve it.
2. **The Pod has a UID and its event says `Insufficient cpu`. Is namespace quota the immediate blocker?** That event describes scheduler fit for an already created Pod. Inspect eligible-node requests and constraints.
3. **Live CPU usage is low but `requests.cpu` quota is full. How can that happen?** The quota accounts for declared requests of applicable objects. Low measured activity need not lower requests.

**Completion criterion.** Reproduce all ten cases and the negative control. For one refused Pod, name the actor, stage and evidence you would still need. Continue with [Kubernetes API Audit]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) for request identity and [Kubernetes Probes]({{ '/wiki/kubernetes-probe-evidence/' | relative_url }}) for what happens after a Pod starts.

## Official references

Reviewed 2026-11-26. Policy definitions use the Kubernetes v1.36 documentation snapshot. The other upstream pages cover the applicable API and runtime concepts. Check the version and enabled admission plugins on your cluster.

- [ResourceQuota v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/) and [LimitRange v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/policy/limit-range/)
- [Admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) and [API dry-run and authorization](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)
- [Container resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) and [Debug Running Pods](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [Audit stages and policies](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
