#!/usr/bin/env python3
"""Evaluate a small fictional Pod-to-Pod policy matrix without a cluster."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Pod:
    namespace: str
    app: str


@dataclass(frozen=True)
class Rule:
    namespace: str
    app: str
    tcp_port: int

    def matches(self, peer, port):
        return (self.namespace, self.app, self.tcp_port) == (peer.namespace, peer.app, port)


def allows(rules, peer, port):
    # None means no policy selected this direction. An empty tuple means
    # isolation with no allow rules. Nonempty tuples contain the union.
    return rules is None or any(rule.matches(peer, port) for rule in rules)


def predict(source, destination, port, egress, ingress):
    if destination is None:
        return "no selected backend in fixture"
    outgoing = allows(egress, destination, port)
    incoming = allows(ingress, source, port)
    return {
        (True, True): "permitted by both directions",
        (True, False): "blocked by destination ingress",
        (False, True): "blocked by source egress",
        (False, False): "blocked by both directions",
    }[outgoing, incoming]


def main():
    web = Pod("shop", "web")
    api = Pod("shop", "api")
    worker = Pod("shop", "worker")
    other_web = Pod("dev", "web")
    probe = Pod("ops", "probe")
    web_egress = (Rule("shop", "api", 8080),)
    api_ingress = (Rule("shop", "web", 8080),)
    extra_ingress = (Rule("ops", "probe", 8080),)
    cases = [
        ("A", web, api, 8080, web_egress, api_ingress, "permitted by both directions"),
        ("B", worker, api, 8080, None, api_ingress, "blocked by destination ingress"),
        ("C", other_web, api, 8080, None, api_ingress, "blocked by destination ingress"),
        ("D", web, api, 8080, (), api_ingress, "blocked by source egress"),
        ("E", web, api, 9090, web_egress, api_ingress, "blocked by both directions"),
        ("F", probe, api, 8080, None, api_ingress + extra_ingress, "permitted by both directions"),
        ("G", web, None, 8080, web_egress, api_ingress, "no selected backend in fixture"),
        ("H", web, api, 8080, web_egress, (), "blocked by destination ingress"),
    ]
    for label, source, destination, port, egress, ingress, expected in cases:
        answer = predict(source, destination, port, egress, ingress)
        if answer != expected:
            raise SystemExit(f"FAIL {label}: {answer!r} does not match {expected!r}")
        print(f"PASS {label}: {answer}")
    print(f"{len(cases)}/{len(cases)} policy matrix controls matched.")


if __name__ == "__main__":
    main()
