---
title: "Velociraptor Endpoint Collection: From a Network Alert to Host Evidence"
description: "Scope a request to one endpoint and interpret collection coverage, zero results, missing files and SIEM delivery using nine fictional cases."
category: dfir
tags: [Velociraptor, Endpoint Collection, Blue Team, DFIR, Incident Response, SIEM]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/endpoint-collection-evidence/
---

**Learning goal.** Turn a network lead into an authorized host evidence request. Explain the difference between a useful empty result, an unfinished request, an uncovered source, and a delivery gap.

## 1. What does an on-demand collection do?

**Velociraptor** is an endpoint visibility and collection tool. A **client** is the enrolled agent on an endpoint. A Velociraptor **organization** is a server-side administrative and data scope. The **client ID** identifies the agent enrollment. Confirm the corresponding asset before using it as an investigation target. An **artifact** defines a task in Velociraptor Query Language (VQL), including the sources, parameters and any eligibility checks. A **flow** is one collection and has its own ID. Results can include structured **rows** and separately **uploaded files**. Which of those to expect depends on the artifact.

| Mode | Best first question | Important evidence limit |
| --- | --- | --- |
| Collection on one client | What evidence does this specific approved host still have? | Runs on demand. It can recover historical records only when the host and artifact expose the requested history. |
| Hunt | Does the same approved question apply across a defined group? | Schedules separate collections for eligible endpoints. Labels and expiration affect participation. Check per-client flows and denominators. |
| Client Monitoring | Should this class of events be collected going forward? | Uses configured client event queries. Offline results may buffer and arrive after reconnecting, subject to configuration and limits. It requires coverage at the time of the event. |

Use a single-client collection first when you have one confirmed endpoint. A hunt's scheduled or stopped state cannot tell you what every client actually returned. Review eligibility, check-in, per-host execution and reason codes. A snapshot collected today is useful for current state. To answer what happened yesterday, use an artifact that reads the relevant historical source and verify that its retention reaches yesterday.

## 2. Follow a normal investigation

![From network alert to host evidence. Verify the host candidate, scope the collection, inspect endpoint execution and results, then preserve originals and verify SIEM delivery.]({{ '/assets/diagrams/endpoint-collection-flow-en.svg' | relative_url }})

A sensor flags an outbound connection at 10:02 UTC from a training network. An address assignment record narrows the source to the lab workstation, and the asset inventory confirms which client ID is currently enrolled for it. The analyst verifies the assignment and asset scope at the time of the connection. The question is whether an existing, retained endpoint log records the connection and its process context in 10:00–10:05 UTC. A current list of open sockets would answer a different time question.

1. **Preserve the network lead.** Keep the sensor name and observation point, original time and timezone, address and port tuple, and the alert or connection identifier. Resolve NAT and DHCP scope when relevant. Neither an alert nor an IP alone establishes the host or who used it.
2. **Define the request.** In the case record, specify the authorized organization and client ID, source and UTC window. Review the artifact's installed definition: OS eligibility, expected channels and sources, timezone, filters, row/file limits, privilege requirements and collection footprint. Pick the smallest relevant source. Record parameters and the version of any custom definition.
3. **Verify execution on the collection server.** Record the flow ID and status. Review **Logs** for the query messages, the correct result set for rows and **Uploaded Files** for actual transferred files where expected. A launch or client check-in is distinct from completion. Confirm that the source was readable and that the requested window was covered. Look for timeouts, configured limits or gaps.
4. **Corroborate and deliver.** A returned row that aligns with the network time, remote endpoint and process identity supports a connection hypothesis. Verify the timestamp and scope and look at legitimate workflow context. Keep a restricted raw export with source identifiers and checksums where applicable. If the operation forwards results to a SIEM, confirm the record lands in the expected index and time range independently of server collection.

For a deployment where only network events stream continuously, write down the collection request time, flow completion time, original endpoint event time and SIEM ingestion time as separate fields. A Splunk search over the alert minute may miss a forwarded record indexed by collection time. Check the data source’s time mapping and compare a known source-row identifier in the server export and destination. Where a forwarder maps field names, verify the mapping before searching by organization, client and flow.

In the example, a signed update process and its scheduled job explain the returned rows. Record the evidence supporting that explanation. A missing endpoint row could instead mean the log was disabled, had rolled over, or did not include connection events. Use a narrow question about the recorded source. The absence of evidence in one source does not close the incident.

## 3. Why zero rows needs context

| What you observe | What can be reported | What to check next |
| --- | --- | --- |
| Queued or running | No completed review yet | Last check-in, intended scope and the case deadline. |
| Completed, no rows, verified source and time | No rows matched this specific query in the covered source | Verify filters and preserve the exact query and coverage evidence. |
| Completed, source skipped or retention gap | The question about that source or interval remains open | Artifact precondition, enabled channels, retention and alternate sources. |
| Timeout or limit with some rows | Partial evidence | Preserve what arrived. Use a smaller authorized time range or a different source. |
| Rows present, required attachment missing | Structured results arrived, the file expectation was not met | Compare artifact behavior, upload logs and file limits. |
| Matching server rows, missing in SIEM | Collection exists, downstream visibility is unverified | Forwarder state, routing, index rights, parsing and event-time vs ingest-time search. |

**Misuse and defensive checks.** Endpoint collection can reach sensitive files and may run with substantial agent privileges. An unauthorized broad request, a changed artifact or a misapplied group label can expose data or affect endpoints. Restrict collector roles and approval scope, review artifact definitions, and correlate sensitive requests with server audit events and change records. The vendor documents `Server.Audit.Logs` as one place to review auditable actions. Check availability and retention. Independently watch for sudden changes in collection volume or label membership. One slow flow may reflect routine endpoint load. If a request is confirmed unauthorized, stop it using the approved incident process, preserve its audit and flow evidence, and check which endpoints and downstream copies were affected.

## 4. Offline exercise · review nine fictional flow manifests

Download [the case data]({{ '/assets/labs/endpoint-collection-cases.json' | relative_url }}) and [the Python reviewer]({{ '/assets/labs/endpoint-collection-review.py' | relative_url }}) into one directory. With Python 3, run:

```sh
python3 endpoint-collection-review.py
```

The JSON has a request under `expected` and a reviewed observation under `observed` for each case. Its state names and `coverage` flags are fictional normalized values, not product API fields. In a real case, write down the evidence for coverage instead of inferring it from a status or this script. All IDs, times and row counts belong to the exercise. No service or network is contacted.

| Case | Expected conclusion | Why |
| --- | --- | --- |
| C01 | Results available | Scope and coverage match, two rows present. |
| C02 | Covered zero | Scope and coverage match, no query matches. |
| C03 | Pending | Queued, with no final result. |
| C04 | Coverage gap | A source was skipped by its precondition. |
| C05 | Incomplete | One row landed before timeout. |
| C06 | Missing attachment | One required file is absent even with a row. |
| C07 | Scope mismatch | The organization differs despite matching client and flow labels. |
| C08 | Delivery gap | Two rows exist on the server, SIEM receipt is unverified. |
| C09 | Coverage gap | The relevant historical interval was no longer retained. |

Expect **nine cases in eight categories**. If the files cannot be opened, check the filenames and directory. For a data error, check the case ID in the message and compare request and observed fields. If you get unexpected covered-zero results, inspect whether the fixture marks the correct source and window as verified. A case can have several problems. This exercise reports the first checkpoint that fails.

### Optional check in an authorized lab

On one approved enrolled test client, use **Collected Artifacts → New Collection** and inspect the installed `Generic.Client.Info` definition before launch. The vendor's built-in definition gathers system details such as hostname, OS and interfaces. It may also refresh the server's client information index. Use the matching client ID in the lab organization and approved permissions. Review the resulting flow status, **Logs** and the expected system-information result set, then compare the hostname and OS to your known test asset. This tests the collection path. It does not validate historical connection logging or SIEM forwarding. If the flow does not run, check last check-in and permissions. If there are no rows, check which result source is selected and which sources apply to your OS. Do not export real system identifiers to a public report.

The offline script was run against the fictional cases in the cloud. The live product workflow was reviewed against vendor documentation and was not run in a Velociraptor deployment.

## 5. Check your understanding

1. **An endpoint appears in a hunt but has no result. Is it clean?** Check eligibility, whether it checked in within the hunt's active period, and the corresponding flow. A missing result is a coverage question.
2. **Why does C02 support a stronger statement than C04?** C02 has confirmed source and time coverage. C04 did not run the expected source.
3. **Does a present server row prove the SOC can search it?** Verify the forwarding and destination separately, as C08 illustrates.
4. **Is a present-day socket snapshot enough for a connection from yesterday?** Persisted historical evidence is needed for that question.

To finish, classify C02, C05 and C08 and name the source that supports each conclusion. Write a short scope note with organization, client, flow, artifact, time window, coverage and what still needs corroboration.

[Previous · Network monitoring]({{ '/wiki/network-monitoring/' | relative_url }}) · [Next lesson · Windows investigation practice]({{ '/wiki/windows-incident-response-lab/' | relative_url }}) · [Related · Preserving digital evidence]({{ '/wiki/evidence-preservation/' | relative_url }})

## Official references

Reviewed November 20, 2026. The workflow is based on the online manuals available at review and the 0.77 release family (May 2026 release notes). Confirm GUI labels, permissions and definitions on the installed build.

- Client collection, request review, logs, results and uploads. [Velociraptor Collecting Artifacts](https://docs.velociraptor.app/docs/clients/artifacts/)
- Collection across clients and expiration, and ongoing client-side event collection. [Hunting](https://docs.velociraptor.app/docs/hunting/) · [Client Monitoring](https://docs.velociraptor.app/docs/clients/monitoring/)
- Built-in definition and client inventory/index behavior. [Generic.Client.Info](https://docs.velociraptor.app/artifact_references/pages/generic.client.info/) · [Client Interrogation](https://docs.velociraptor.app/docs/clients/interrogation/)
- Server roles and auditing, plus release-family scope. [Security Configuration](https://docs.velociraptor.app/docs/deployment/security/) · [Velociraptor 0.77 release notes](https://docs.velociraptor.app/blog/2026/2026-05-31-release-notes-0.77/)
