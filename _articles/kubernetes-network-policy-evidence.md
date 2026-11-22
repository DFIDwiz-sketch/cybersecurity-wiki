---
title: "Kubernetes NetworkPolicy Evidence · Follow Both Sides of a Pod Connection"
description: "Read Pod selectors and ingress and egress rules, then separate policy intent, enforcement and application outcomes."
category: cloud
tags: [Kubernetes, Cloud Security, Network Security, NetworkPolicy, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/kubernetes-network-policy-evidence/
---

**Learning goal.** A Kubernetes API audit event shows that a policy changed. A caller says its request timed out. Learn to decide what the policy should allow, what the network actually did and what the application received.

## 1. What a NetworkPolicy controls

A **Pod** is the unit Kubernetes schedules to run one or more containers. A **namespace** groups namespaced resources. A **label** is a key and value attached to an object. A **selector** identifies matching objects, such as Pods with `app=api`. A **Service** presents a stable address or name for an application. A selector-based Service associates its backends with **EndpointSlice** objects. A backend can change even while the Service name stays the same.

A **NetworkPolicy** describes permitted traffic for selected Pods at the IP and transport layer. **Ingress** is traffic entering the destination Pod. **Egress** is traffic leaving the source Pod. The API server can store a NetworkPolicy even if the cluster's network implementation does not enforce it. Confirm support and configuration with the network owner. **CNI** is the interface many Kubernetes networking plugins use to configure Pod networking. The plugin or associated data plane determines what is actually enforced and what you can observe. Basic NetworkPolicy does not identify an HTTP user, path or method. Those decisions belong to other controls.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/kubernetes-network-policy-evidence-en.svg' | relative_url }}" alt="A new connection from the source Pod must pass its egress rules and the destination Pod's ingress rules. A deny on either side blocks the connection in the model. If both permit it, application checks follow.">
<figcaption>Read both policy directions for new Pod-to-Pod connections. An allowed path can still fail at Service routing, the listener or application authorisation.</figcaption>
</figure>

## 2. Read the selectors and both directions

First find the source and destination Pods and their namespaces. Then review policies selecting each Pod in the relevant direction. A Pod is non-isolated in a direction if no standard NetworkPolicy selects it for that direction. If one or more policies select it, evaluate the union of allowances for that direction. For a new connection between ordinary Pods, both the source's egress and the destination's ingress must permit the traffic. Replies to allowed connections are implicitly allowed. This model sets aside implementation and documented node-traffic exceptions.

| Policy element | Which objects it selects | What to check |
| --- | --- | --- |
| Top-level `spec.podSelector` | Pods in the policy's own namespace | An empty selector matches all Pods there. It identifies the protected side, not its peer. |
| `from`/ `to` entry with just `podSelector` | Peer Pods in the policy's namespace | Identical Pod labels in another namespace do not match. |
| `namespaceSelector` and `podSelector` in one entry | Peer Pods matching the Pod labels inside matching namespaces | The conditions are combined with AND. Separate list entries match independently with OR. |
| `policyTypes` selects a direction and the corresponding rule list is empty | Isolated Pods have no allowance from this policy in that direction | A second applicable policy can still permit traffic. Policy order does not decide the result. |

For example, a fictional `shop/web` Pod calls a Service named `orders` on TCP 80. The Service directs it to `shop/api` on TCP 8080. Assume the endpoint is ready and listening, and DNS already resolved the Service. Start evaluation with the actual backend and port. Service translation and IP-based rules can be implementation-dependent. Check the plugin before interpreting the observed address and port.

The following illustrative policy selects `app=api` in `shop` and grants ingress on TCP 8080 from `app=web` in the same namespace. It is an excerpt for study. For the normal connection, assume a separate policy selecting `web` also permits egress to `api` on TCP 8080. The ingress policy cannot supply that egress allowance.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: orders-api-ingress
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
      ports:
        - protocol: TCP
          port: 8080
```

## 3. Separate misconfiguration, misuse and other failures

| Observation | Plausible explanations | Evidence to discriminate |
| --- | --- | --- |
| Policy saved, traffic apparently unchanged | Plugin has no policy support, selector misses the Pod, broad allowance in a second policy, or connection already existed | Network capability, historical labels, all applicable policies, fresh connections and data-plane observations |
| Client timeout | Policy drop, DNS failure, unhealthy or absent backend, or another network problem | DNS result, selected EndpointSlice, target port, flow disposition and service health |
| HTTP 403 response | Application or intermediary denied the request after a connection succeeded to the responder | Identify the actual responder, inspect request or trace ID, application policy and logs |
| Unexpected new caller can reach an API | Overbroad namespace selection, an added allowance, or label or deployment drift | Before-and-after policies and labels, API audit records, observed source and backend, approved change records |

Unintended access can arise if someone with edit rights widens a policy or changes labels. A permitted connection is evidence of network reachability. Verify account, HTTP authorisation and application effects separately. A timeout has several possible causes. Even if a CNI records a policy drop, confirm which Pod, direction and time it describes before attributing the reported outage to that drop.

## 4. Collect evidence at three layers

1. **API intent and history.** Record cluster identity and UTC, policy UID and resourceVersion, affected namespaces and Pod UIDs, labels, Service ports and EndpointSlices. A current snapshot may differ from the incident state. Preserve historical manifests or change events where available. If API auditing captured the change, review user, verb, object, response and UTC. The request body or previous state can be missing depending on audit level and retention. See [Kubernetes API audit evidence]({{ '/wiki/kubernetes-audit-evidence/' | relative_url }}) for these limits.
2. **Effective path and enforcement.** Resolve the Service name from the affected workload or use retained resolver records. Check the selected backend addresses, readiness and target port. Identify the network plugin and confirm whether it supports policy, plus telemetry coverage. In deployments with Cilium and Hubble enabled, flow records can help identify the involved workloads, direction and verdict. Record observation point, timestamp, protocol, source and destination identity and port, and the reported drop reason if provided. Retention and visibility vary. An ordinary API audit record does not report the packet verdict.
3. **Application outcome.** Compare the caller result and destination application logs with request or trace IDs and timestamps. A response could come from a proxy or different backend. Confirm who answered before escalating. Preserve the independent views with timezone and identity context. If a policy change broadened access, coordinate correction through the approved configuration workflow and confirm whether any requests actually reached the service.

The following are read-only Kubernetes inventory commands. Run only in an authorised context. You need `get` or `list` rights as appropriate for Pods, Services, EndpointSlices and NetworkPolicies in the named namespace. Replace the fictional names with the approved objects. For cross-namespace traffic, collect both sides. These commands read current state.

```bash
kubectl config current-context
kubectl -n shop get pods --show-labels -o wide
kubectl -n shop get networkpolicies -o yaml
kubectl -n shop get service orders -o yaml
kubectl -n shop get endpointslices -l kubernetes.io/service-name=orders -o yaml
```

For a real defensive validation, establish one known-allowed source and one known-blocked source in a dedicated, approved test namespace. Use a harmless request to your own test service and start a fresh connection for each case after the network implementation has converged. Record each source and backend, the application result and any policy verdict. Include required DNS and health traffic in the design. Avoid changing production policy as a troubleshooting shortcut. Policy changes are not guaranteed to close existing connections across implementations.

## 5. Offline lab · predict eight outcomes

Download <a href="{{ '/assets/labs/kubernetes-network-policy-lab.py' | relative_url }}" download>the Python policy matrix</a> and run `python3 kubernetes-network-policy-lab.py`. Work through the following predictions first. The fixture treats Pods as namespace/label pairs, rules as explicit TCP peer/port allowances and the frontend Service as already resolved to a backend except in G. It models a union of allow rules per direction. It does not parse Kubernetes YAML or query a live cluster. No network or administrator privileges are needed.

| Case | Difference from the example | Expected interpretation |
| --- | --- | --- |
| A | Web to API, matching both rules on TCP 8080 | Permitted in the model |
| B | Same-namespace `worker`, non-isolated for egress | Destination ingress blocks |
| C | `app=web` in `dev`, non-isolated for egress | Destination ingress blocks because the namespace differs |
| D | Web is isolated for egress with no allowance | Source egress blocks while ingress would allow |
| E | Web uses TCP 9090 | Both directions block |
| F | An ops probe has its own additional allowance at API ingress | Permitted because matching allowances combine |
| G | The assumed Service has no selected backend in this fixture | No destination Pod to evaluate |
| H | API ingress is isolated with an empty allow list and no other allowance | Destination ingress blocks |

Expect `8/8 policy matrix controls matched.` If the script cannot run, check Python 3 and the downloaded filename. If B or C seems permitted, check the peer label and namespace separately. If D seems permitted, recheck egress on the source. The script ran in the cloud with the fictional fixtures. Kubernetes commands, Service handling and CNI behaviour were checked against official documentation. No live cluster or data plane was exercised.

## 6. Check your reasoning

1. **An API request successfully saved a NetworkPolicy. Can you conclude that traffic was dropped?** Check plugin support and observe a new connection on the applicable data plane.
2. **One policy denies all ingress to the selected Pod and another allows TCP 8080 from web. What happens for that caller?** The empty allow list contributes no allowance. The other policy can allow ingress, and source egress still matters.
3. **Which records distinguish a policy drop from a Service with no ready backend?** Start with the Service and EndpointSlices. Then correlate fresh connection and network verdict records at the relevant nodes or workloads.
4. **Does a network allow identify a legitimate HTTP user?** Use application authentication and authorisation records and verify the actual responder.

**Completion criteria.** Identify the policy's protected Pod and its peer selector, explain why both directions matter, classify all eight cases and report one additional record needed to prove enforcement.

## Official references

Reviewed 2026-11-21. Kubernetes policy and EndpointSlice behaviour was checked against the v1.36 documentation. Use the documentation for your deployed version and network implementation.

- Kubernetes v1.36 [Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) and [EndpointSlices](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/endpoint-slices/).
- Kubernetes official [Debug Services](https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/) and [kubectl get](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/) for read-only investigation.
- Cilium 1.20 documentation on [network observability with Hubble](https://docs.cilium.io/en/stable/observability/hubble/index.html), an implementation-specific example.

## Follow workload identity and token lifecycle

Follow [Kubernetes Service Account Evidence]({{ '/wiki/kubernetes-service-account-evidence/' | relative_url }}) from Pod credential issuance through API authentication and authorization.
