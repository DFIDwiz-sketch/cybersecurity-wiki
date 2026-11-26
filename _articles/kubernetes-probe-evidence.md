---
title: "Kubernetes Probe Evidence · Startup, Readiness and Liveness"
description: "Follow a probe from the kubelet to Pod status and Service endpoints, then tell a traffic withdrawal from a container restart."
category: cloud
tags: [Kubernetes, Cloud Security, Kubernetes Probes, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/kubernetes-probe-evidence/
---

**Learning goal.** A Pod is `Running`, users see errors and someone notices a restart. Learn to establish which container and Pod were involved, whether Service traffic was affected and what evidence links a probe to a restart.

## 1. Three probes answer three questions

A **Pod** is a unit Kubernetes assigns to a node. One Pod can contain several **containers**, each with its own lifecycle. The node's **kubelet** runs the configured probes, which are checks against a container. A **Service** gives clients a stable address. For a Service with a selector, the controller records matching backends in **EndpointSlices**, including conditions the traffic path can use when choosing an endpoint. A **UID** identifies one lifetime of a Kubernetes object. A container runtime ID identifies one container instance within that timeline.

| Probe | Question | What happens after the failure threshold |
| --- | --- | --- |
| Startup | Has this instance initialized? | The kubelet stops the affected container. Its effective restart policy governs the next step. When configured, this probe gates readiness and liveness until startup succeeds. |
| Readiness | Can this container accept work now? | The kubelet marks the container unready. This can make the Pod unready and its matching Service endpoint ineligible for normal traffic. The readiness check keeps running. |
| Liveness | Is the container still able to make progress? | The kubelet stops the affected container. Its effective restart policy determines whether it restarts. |

A check can use an HTTP request, a TCP connection, a gRPC health check or a command inside the container. A TCP success means the port accepted a connection. An HTTP success describes the configured path and response at that moment. Choose the check that measures the condition you need. Keep liveness focused on a condition a restart can fix. A readiness check can include dependencies needed for serving, with a bounded cost and timeout, so that checks themselves leave enough capacity for users.

`periodSeconds` controls the check interval, `timeoutSeconds` bounds each attempt and `failureThreshold` counts consecutive failures. `initialDelaySeconds` delays starting a probe. Readiness can require multiple consecutive successes using `successThreshold`. Startup and liveness require that value to be 1. Use the settings on the actual Pod, since different revisions can have different values. Base startup allowance on measured initialization under load. The period and threshold give a planning budget. Scheduling, execution and termination can change the elapsed time.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-probe-evidence-en.svg' | relative_url }}" alt="A startup probe blocks readiness and liveness until it succeeds. Readiness updates Pod and endpoint conditions. A failed startup or liveness threshold leads to a container stop, with subsequent behavior governed by restart policy." width="480" height="496">
  <figcaption>The kubelet drives the container checks. Endpoint conditions and the client's experience are recorded at separate observation points.</figcaption>
</figure>

## 2. Read a normal timeline

Consider a fictional selector-based Service `checkout` with two replicas. A rollout adds a new Pod with the ordinary app container `api`. Its startup probe succeeds at 18 seconds, readiness at 21 seconds. Before readiness succeeds, the established replica continues serving. Afterwards the new Pod's `Ready=True` and its matching EndpointSlice reports `ready: true`. A fresh client request can reach the new replica once its traffic path has applied the update.

At 70 seconds a needed dependency becomes slow. The new replica's readiness checks reach the configured failure threshold. Its container now reports `ready: false`, the Pod reports `Ready=False`, and the endpoint stops receiving normal new Service traffic after the state propagates. Its container ID and restart count stay the same. After recovery they remain the same and the endpoint becomes ready again. In a separate case, a deadlocked process exhausts the liveness threshold. The kubelet stops that container. Under `Always` restart policy the same Pod UID can acquire a new container ID and higher restart count.

Pod phase `Running` is broad. Compare `status.containerStatuses[].{name,started,ready,restartCount,containerID,lastState}` with the Pod's `ContainersReady` and `Ready` conditions. A custom `readinessGate` can keep a Pod unready even when all its containers are ready. Examine the actual Service and its EndpointSlices. For example, `publishNotReadyAddresses: true` makes endpoints count as ready for publication even if their Pods are unready. For ordinary Services, terminating endpoints typically have `ready: false`. `serving` and `terminating` convey separate information. Some Service proxies can use a serving, terminating endpoint when all available endpoints are terminating. Controllers and proxies update asynchronously, so verify traffic from a relevant client when the impact matters.

## 3. How failures and misuse look

| Pattern | Why it matters | Evidence to compare |
| --- | --- | --- |
| Liveness checks a shared dependency | An upstream slowdown can restart many otherwise recoverable processes and deepen an outage. | Probe definition, dependency timing and old container termination on more than one affected Pod. |
| Readiness continually passes on a shallow check | Clients can see errors even though a port responds or a simple route returns success. | Readiness result and fresh client errors, keyed to the same destination workload and revision. |
| Health behavior changes after an unexpected deployment write | A change to a probe, image or Service setting can suppress routing or cause restarts. The same pattern can follow an approved rollout or a configuration error. | Before and after specs, allowed deployment identity, API audit result and the resulting Pod UID. |
| Restart and probe failures occur close together | A memory kill or process exit can overlap failed checks. A single Event reason or high restart count leaves the cause open. | Old runtime ID, previous termination reason and time, and kubelet evidence for that instance. |

## 4. Collect, detect and respond

1. **Freeze the window.** Record UTC, cluster, namespace, Pod UID, node, revision, container name and runtime ID. Export current and previous state promptly. The same name can refer to a replacement Pod. If the container name is shared by many replicas, join by cluster, namespace, Pod UID, container and instance lifetime.
2. **Follow each layer.** Review the Pod spec and status, Service configuration and all labeled EndpointSlices. For controller-managed Pod endpoints, compare `targetRef.uid` where available. Use timestamps, clock offset and collection time before ordering observations. Use client-side errors or gateway/backend records to estimate traffic impact.
3. **Look for the proximate cause.** Keep raw kubelet Events and available workload, node or runtime telemetry. Compare the action and termination time with the previous instance. Kubernetes Events are best effort, have limited retention and can be aggregated. A missing Event leaves a gap. An `Unhealthy` reason is a cue to read details. API audit logs, when enabled with adequate policy and retention, can establish a request to change an object. They answer a different question from runtime evidence.
4. **Validate the alert and mitigate.** For a restart alert, compare a counter increase and runtime IDs for the same Pod UID and container. Enrich with termination type and probe data. For a traffic alert, track unready selected endpoints plus user-facing errors and use a window that accounts for expected rollout warmup. Test both alerts with ordinary startup, isolated readiness failure, liveness failure and OOM controls. During an incident, preserve evidence before replacing Pods where practical. Route confirmed dependency, rollout and resource failures to the respective owners. Investigate any unexplained change using the approved configuration and audit trail before attributing intent.

In an approved namespace, these read-only examples require a compatible `kubectl` and access to get Pods and Services, list EndpointSlices and Events, and read the Pod logs subresource. Replace all training names. Confirm the target context first.

```sh
kubectl config current-context
kubectl -n training get pod checkout-0 -o json
kubectl -n training get svc checkout -o json
kubectl -n training get endpointslices \
  -l kubernetes.io/service-name=checkout -o json
kubectl -n training events --for pod/checkout-0 -o json
kubectl -n training logs checkout-0 -c api --previous --timestamps
```

Save the capture times beside the outputs. A name filter on Events can match retained records for an earlier UID. Depending on the Event representation, compare `involvedObject.uid` or `regarding.uid`, and the container field when present. `--previous` requests logs for the previous terminated instance of the selected container, if those logs are still available. It does not automatically search older instances, replaced Pods or a central log archive. Record `Forbidden`, missing logs and collection gaps as such. Export only approved evidence and keep sensitive log contents in the incident store.

## 5. Offline validation lab

Download <a href="{{ '/assets/labs/kubernetes-probe-evidence.py' | relative_url }}" download>the Python 3 checker</a> and <a href="{{ '/assets/labs/kubernetes-probe-evidence-cases.json' | relative_url }}" download>the synthetic cases</a> into one directory. Use a directory you control. The script reads a local JSON file and requires no packages, network access or cluster credentials. Cases model normalized snapshots from one clock and one Service per case. The synthetic `kubelet-probe-stop` label stands for corroborated node evidence with a known instance and time. It is a training field. Several real Event schemas and node logs may be needed to establish that association.

Predict each case's container lifecycle, restart evidence and endpoint condition. Then run:

```sh
python3 kubernetes-probe-evidence.py
```

| Case | Evidence to explain |
| --- | --- |
| A | An initializing container becomes ready within the same instance. |
| B | Readiness fails. The endpoint is unready and the container keeps its ID. |
| C | The liveness stop matches the instance that terminated. The new instance is now ready. |
| D | Startup stops the first instance. Its replacement is still unready. |
| E | `OOMKilled` is reported for the old instance alongside a separate readiness failure. |
| F | The container is ready. The custom gate leaves the Pod and endpoint unready. |
| G | In this Service the endpoint reports ready even though the Pod is unready. |
| H | The Pod name is reused. The retained stop observation and endpoint refer to the old UID. |
| I | The endpoint is serving and terminating. Document both conditions before drawing a routing conclusion. |
| J | A restart is visible. One stop record has the wrong instance and the other is too late. |

Expect `10/10 probe evidence cases matched.` For a negative control, make a copy of the JSON and change case C's stop observation `instance_id` to `runtime://other`. Run the checker with the copied filename as its argument. C should now report `restart-cause-open`, and the checker should return exit code 1 with nine matches. If the original fails to load, check the two filenames, Python 3 and whether the downloaded cases are valid JSON. If the copy still passes, confirm that you changed C's event field and passed the copy to the script.

The original fixture and the negative control were run in a cloud Python environment. Product behavior and the collection commands were reviewed against the upstream documentation. The exercise models comparisons and evidence gaps. No live Kubernetes cluster or traffic path was exercised.

## 6. Check your understanding

1. **A Pod is Running with two containers, and the API container is unready. Can normal Service traffic still flow to it?** Check Pod Ready, the Service settings and the endpoint conditions first. Ordinary ready-only endpoint selection may exclude it. Published unready endpoints, convergence delays and existing connections can change what a client sees.
2. **The restart count rose and an older kubelet Event mentions liveness. What would support causation?** Match cluster, Pod UID and container name, then tie the stop action to the terminated runtime instance and termination window. Check competing causes such as a process exit or reported OOM.
3. **How do you tell a readiness gate from a readiness probe failure?** Compare container readiness with Pod Ready, then inspect `spec.readinessGates` and its condition. A missing or false gate can hold back an otherwise ready Pod.
4. **Does an endpoint reporting ready show that a transaction succeeded?** It shows the endpoint's published eligibility at that observation point. Use client or request traces to confirm the transaction.

**Completion.** Explain the three probe decisions from memory. For B, C, E, H and J, name the decisive fields and one remaining unknown. Reproduce the original and altered fixture outcomes.

## Official references

Reviewed 2026-11-26 against current upstream Kubernetes v1.37 documentation. Check the documentation for your deployed version, especially for managed-cluster collection, feature gates and traffic implementation.

- Probe types, lifecycle and thresholds. [Kubernetes Probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/) and [Configure Liveness, Readiness and Startup Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- Pod phases, conditions, readiness gates and restart policy. [Kubernetes Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- Service endpoint condition semantics and termination. [Kubernetes EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
- Event retention and evidence collection commands. [Kubernetes Event API](https://kubernetes.io/docs/reference/kubernetes-api/core/event-v1/), [kubectl events](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_events/) and [kubectl logs](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/)

[Previous · Kubernetes NetworkPolicy evidence]({{ '/wiki/kubernetes-network-policy-evidence/' | relative_url }}) · [Next · Linux cgroup memory evidence]({{ '/wiki/linux-cgroup-memory-evidence/' | relative_url }}) · [Related · Kubernetes API audit evidence]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }})

## Check quota and scheduling evidence

If a rollout stalls, use [Kubernetes ResourceQuota]({{ '/wiki/kubernetes-quota-evidence/' | relative_url }}) to locate policy refusals and distinguish them from scheduler fit.
