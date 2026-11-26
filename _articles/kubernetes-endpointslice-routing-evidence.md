---
title: "Kubernetes EndpointSlice Evidence · Verify Service Backends and Ports"
description: "Trace a Service port to all matching EndpointSlices, explain backend identity and locality, and validate six offline cases."
category: cloud
tags: [Kubernetes, EndpointSlice, Cloud Security, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/kubernetes-endpointslice-routing-evidence/
---

**Learning path** · [Pod readiness and probes]({{ '/wiki/kubernetes-probe-evidence/' | relative_url }}) → Service backend evidence → [NetworkPolicy and packet delivery]({{ '/wiki/kubernetes-network-policy-evidence/' | relative_url }}).

## 1. From a stable Service to changing backends

A **Service** provides a stable way to address an application while its Pods start, move and stop. An **EndpointSlice** lists part of that Service's backends. A backend is an actual destination address and port. The **control plane** publishes these objects through the Kubernetes API. A **Service proxy** such as kube-proxy observes them and configures forwarding in the **data plane**, the path that carries traffic. The client reaches a backend only if forwarding, network access and the application listener work.

This guide follows normal ClusterIP forwarding. Headless Services (`clusterIP: None`) and ExternalName Services rely on DNS in different ways and need a DNS-first investigation. For external load balancers, add the load balancer's target and health telemetry.

## 2. Follow the address, port and identity

1. Find the Service by cluster, namespace and name. Preserve its **UID** (unique ID for that lifetime), selector, client-facing port, protocol, targetPort and traffic policy. A Service port's **name** identifies the port within the Service. A string **targetPort** is a name to resolve on the target Pods. These names can differ.
2. List **all** EndpointSlices in that namespace with `kubernetes.io/service-name` equal to the Service name. Check `endpointslice.kubernetes.io/managed-by` and owner references. For a Slice with a Service owner reference, compare its owner UID with the Service UID. For a Pod-backed entry, use `targetRef.uid` when present and compare the address with that Pod's status. A missing reference calls for additional evidence. A selectorless Service can legitimately have separately managed slices, including targets outside the Pod network.
3. In each matching slice, find a port entry whose **name and protocol** match the Service port. Read its numeric port. All listed endpoints in that slice share its port set. Preserve address family, endpoint conditions and node. Dedupe the same address, port and protocol within the Service port and address family when aggregating multiple slices, but preserve conflicting fields and provenance for investigation.
4. Identify the client and relevant forwarding implementation. Apply the client-facing address family and policy before deciding whether a candidate could be used. For `internalTrafficPolicy: Local`, a kube-proxy client on a node with no local endpoints can fail even if viable endpoints exist on other nodes. A backend access log or authorized connection observation, correlated to a request and time window, is needed to establish what happened to that traffic.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/kubernetes-endpointslice-routing-evidence-en.svg' | relative_url }}" alt="Service port and protocol lead to all associated EndpointSlices. Slice addresses, target UIDs and resolved ports provide API candidates. The client or forwarding node and backend records show actual delivery." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Three joins connect Service intent to observed delivery. Keep the API state and the data-plane observation time with each join.</figcaption>
</figure>

## 3. Read normal and unexpected configurations

**Fictional rollout.** `checkout` serves TCP 443 under the Service port name `https`. Its `targetPort` is the Pod port name `app-tls`. The blue release declares `app-tls` on 8443 and the green release uses 9443. Both Pod generations match the selector. The controller can publish distinct slices with port name `https` and their respective numeric ports. A fresh request to the Service's 443 might therefore reach either numeric backend port. Suppose a matching backend request record tied to the client's request ID shows green on 9443. That supports delivery to green **for that request**.

| Finding | What it supports | Evidence to collect next |
|---|---|---|
| Same port name, different numeric ports across slices | Separate Pod port resolutions can be valid during rollout | Pod specs, release history and app listener. |
| Slice's Service owner UID differs from current Service UID | Association needs review, such as after a Service was recreated | Earlier Service and Slice versions, controller logs and accepted API writes. |
| Selectorless Service uses a separate manager | Manually or independently managed backends are possible | Approved destination inventory, owning automation and network records. |
| `ready=false`, `serving=true`, `terminating=true` | The backend is draining and still marked serving | Proxy version and policy. Serving terminating endpoints may be used when no alternative exists in the applicable set. |
| Healthy remote slices but zero node-local candidates | A Local traffic policy can account for node-specific failure | Client node, endpoint `nodeName` and a same-time observation from that node. |

For a Pod-backed endpoint, `serving` normally tracks Pod readiness and `terminating` reflects deletion in progress. `publishNotReadyAddresses: true` can publish endpoints as ready regardless of Pod readiness. The v1 API interprets omitted `ready` and `serving` as true and omitted `terminating` as false. Keep omitted and explicit values distinct in raw evidence. An API default does not demonstrate application health.

An unexpected selector or slice change can send requests to an unintended destination. Deployment mistakes, stale objects and unauthorized changes can look alike in a snapshot. Compare the accepted API change with its approved owner and release. If traffic reached an unexpected backend, use request-level evidence to bound the impact. A controller-name label is a declaration on the object. To identify who changed it, use an available audit event and the request identity.

## 4. Collect and respond in the right order

These read-only commands require a compatible `kubectl`, an authorized context, and permission to get the Service, list EndpointSlices and get the named Pod in the namespace. Substitute names from your authorized environment. Use `targetRef.name` to retrieve the Pod, then compare its actual UID. Save full JSON outputs separately with collection timestamps.

~~~sh
kubectl config current-context
kubectl -n checkout get service checkout -o json
kubectl -n checkout get endpointslices.discovery.k8s.io \
  -l kubernetes.io/service-name=checkout -o json
kubectl -n checkout get pod checkout-green -o json
~~~

1. **Collect.** Record UTC, cluster, namespace, client address and node, Service UID, each Slice UID and resourceVersion, and backend address and port. resourceVersion identifies an API version for change tracking. Use collection timestamps and audit timestamps for incident chronology. These reads are separate snapshots.
2. **Detect.** Compare successive API snapshots and the approved rollout. Prioritize unknown backend destinations, unexpected port shifts outside change windows and missing node-local endpoints paired with fresh client failures. Use [Kubernetes API audit evidence]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) if the audit policy covered the resource and time. Request body availability depends on audit level.
3. **Respond.** Preserve before making changes. If the candidate set is correct and only one node fails, check the Service proxy's view and sync health on that node and the workload-side connection verdict. Use fresh connections or a unique request ID. An existing connection can keep using an old backend. Work with the Service owner to restore the approved selector, port or managed endpoint configuration. Confirm recovery at both the API and client levels.

## 5. Offline exercise · Six fictional API snapshots

Use Python 3 in your authorized workspace. Download both files into the same directory. The JSON contains fictional API-like records and expected output. The checker joins snapshots locally and sends no traffic. Its scope is a teaching subset for one TCP Service port and IPv4. It shows ready non-terminating candidates, flags draining endpoints separately and does not emulate kube-proxy or prove reachability.

- <a href="{{ '/assets/downloads/kubernetes-endpointslice-routing-evidence/inspect_slices.py' | relative_url }}" download>Download the Python checker</a>
- <a href="{{ '/assets/downloads/kubernetes-endpointslice-routing-evidence/slice_cases.json' | relative_url }}" download>Download six fictional snapshots</a>

~~~sh
python3 inspect_slices.py slice_cases.json
~~~

| Case | Expected reading |
|---|---|
| Two port generations | Two candidate tuples, even though the Service port name is the same. |
| Duplicate entry | One candidate tuple and an explicit duplicate finding. |
| Recreated Service | An owner UID mismatch. The checker identifies an issue even if the address is marked ready. |
| Local policy | An eligible remote backend exists but yields no candidate for the given client node. |
| Draining endpoint | A serving/terminating entry is recorded separately from ordinary ready candidates. |
| Selectorless service | A separately managed backend is present and needs independent inventory. |

All six cases should match. Copy the JSON, change the first case's first numeric slice port to `7443`, and keep the expected output unchanged. The checker should flag that one case and exit with status 1. If it never starts comparing, check the working directory, JSON syntax and companion file version.

## 6. Check your understanding

- **Which names do you join if Service `name: https` points at `targetPort: app-tls`?** Join `https` and the protocol to Slice ports. `app-tls` resolves to the numeric port on the Pod.
- **EndpointSlice shows a destination. Did it receive a specific request?** Verify it with a correlated client and backend observation. The API snapshot supplies candidates.
- **A UID differs. Who changed it and was it malicious?** Look for the accepted API write, actor and approved change. The mismatch alone leaves both questions open.

Complete the exercise by producing the expected mismatch after changing the port, explaining why Local policy can differ across nodes, and naming the additional evidence needed to prove delivery.

## Official references

Reviewed **2026-11-27** against Kubernetes v1.36 documentation. Consult the version and forwarding implementation deployed in your cluster. EndpointSlice has been stable since v1.21. The older Endpoints API was deprecated in v1.33 and may omit addresses for high-backend-count Services.

- [Kubernetes v1.36 EndpointSlices · grouping, identity and conditions](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
- [Kubernetes EndpointSlice v1 API · fields and omitted condition values](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/discovery/endpoint-slice-v1/)
- [Kubernetes v1.36 Services · ports, selectorless and headless Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
- [Kubernetes v1.36 Service proxies · sync, Local policies and terminating endpoints](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/)
