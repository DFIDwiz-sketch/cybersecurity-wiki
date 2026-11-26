---
title: "Network Time Security (NTS) and chrony Evidence"
description: "Trace NTS key establishment, authenticated NTP samples and source selection, then triage six fictional chrony cases offline."
category: network
tags: [NTP, NTS, TLS, Network Security, Blue Team, DFIR, Linux]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/nts-time-source-evidence/
---

**Learning path** · [NTP clock evidence]({{ '/wiki/ntp-clock-evidence/' | relative_url }}) → NTS and chrony evidence. Review [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) when investigating a failed key exchange.

## 1. What problem does NTS solve?

A host uses Network Time Protocol (NTP) samples to estimate and correct its clock. That clock supplies timestamps to services such as authentication, logging and incident timelines. Unauthenticated NTP does not cryptographically identify the responding server or protect its timestamps against modification in transit. **Network Time Security (NTS)** adds cryptographic authentication for NTP client/server exchanges. **chronyd** is the daemon that measures and adjusts time, and **chronyc** queries its state.

Keep four questions separate. Did the client establish keys with the expected service? Did the daemon authenticate and accept a recent measurement from the intended time source? Which source did the daemon select, and which others contributed? How much clock disagreement or uncertainty does the workload tolerate?

## 2. Follow the evidence from TLS to the clock

1. **Establish keys.** NTS Key Establishment (NTS-KE) uses TLS and validates the key service's certificate. Client and server negotiate an authenticated encryption with associated data (AEAD) algorithm. They derive keys for each direction from TLS, and the client receives opaque cookies. TCP 4460 is the standard key-establishment port.
2. **Measure time.** The client sends an NTP request with a cookie. The time server uses it to recover the information needed for authentication and sends a protected response, which can replenish the client's cookie supply. NTP uses UDP 123 by default. The key service can designate a different NTP host or port. The AEAD tag protects the integrity and authenticity of the regular timestamps, which remain readable on the wire.
3. **Select and combine.** chronyd checks measurements and selects a reference. It may combine eligible measurements from other sources. A valid response may still fail measurement checks or come from a source that is ineligible for selection.
4. **Assess the clock.** Check the reported reference time, clock correction and uncertainty against the workload's requirements. An authenticated source can itself be inaccurate. Delays or asymmetric paths can bias measurements even when packet authentication succeeds.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/nts-time-source-evidence-en.svg' | relative_url }}" alt="NTS key establishment over TCP 4460 supplies keys and cookies. Authenticated NTP over UDP follows. chronyd evaluates and selects sources, then reports clock state and uncertainty." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Test each stage separately. NTS-KE can designate the endpoint for NTP traffic.</figcaption>
</figure>

## 3. Read a healthy sequence and its alternatives

**Fictional example.** A host's approved NTS source resolves to `192.0.2.10`. The same source reports `NTS` and available cookies. After three polls the last valid response shows `Authenticated: Yes` and `Total good RX` has risen from 17 to 20 with no daemon restart or source change. The source remains `^*`. `tracking` reports a recent reference time and a clock-error estimate within this workload's budget. Together these observations support a recent authenticated measurement and selection of the expected reference. They leave the upstream reference's absolute accuracy and the exact ordering of events on other hosts to be checked independently.

| Observation | What it supports | What to check next |
|---|---|---|
| `authdata` reports `NTS` and available cookies | NTS mode and cached state for that source | Check the age of last successful NTS-KE and whether fresh NTP samples arrive. |
| `Authenticated: Yes` with `Total good RX` rising | Last valid response was authenticated, and additional measurements passed checks in this interval | Match the source to `authdata` to distinguish NTS from a shared key. Track both fields together. The counter alone does not describe how each packet was authenticated. |
| `^*` or `^+` in `sources -v` | `^*` is the best source in use, and `^+` is combined with it | Compare the selected and contributing sources with the effective policy. `^?` has several possible reasons, including reachability or insufficient samples. |
| Recent reference, low estimated error | The daemon reports clock health relative to its reference and its model | Check path changes and disagreement against an independent reference. For incident timelines, include the time window and uncertainty of both hosts. |

For a synchronized reference, the chrony manual estimates a bound by adding the absolute `System time` offset, `Root dispersion` and half of `Root delay` (all in seconds). For example, 0.4 ms + 0.7 ms + 1.0 ms gives 2.1 ms. Treat it as conditional on the primary reference being correct and the timing model holding. If `Leap status` reports `Not synchronised`, investigate synchronization before using the estimate.

A failed TLS certificate time check can arise after a cold boot with a badly wrong clock. A certificate name or trust error can instead indicate a configuration problem or an unexpected endpoint. If NTS-KE succeeds while NTP measurements stall, investigate the negotiated UDP destination and path. When the path is healthy but a different source wins, look at the source selection policy. chrony 4.9's default `authselectmode mix` can use both authenticated and unauthenticated sources subject to selection constraints. Earlier behavior and overrides can differ. Report a policy mismatch only after checking what the host was meant to use.

## 4. Collect, detect and respond

Run these read-only reports on an authorized host with chronyd and access to its chronyc monitoring interface. The commands below were reviewed against the chrony 4.9 manual. The offline lab does not run a daemon. Replace the example address with the corresponding resolved NTP source from `sources`. For unknown addresses, `authdata -a` can show unresolved sources too.

~~~sh
chronyc -n authdata -a
chronyc -n sources -v
chronyc -n ntpdata 192.0.2.10
chronyc tracking
~~~

- **Collect.** Record UTC capture time and its provenance, host and daemon version, effective source configuration and selection options, and configured names versus resolved addresses and ports. Preserve daemon logs and available DNS or firewall records. Record a second set after enough polls to judge freshness. Compare counters only across the same source and daemon lifetime. Preserve the raw output and restrict access to internal names and configuration.
- **Detect.** For hosts meant to use NTS, correlate the selected source, actual auth mode and recent accepted samples. Look for a change to an unexpected source or loss of fresh accepted measurements over several expected polls. In `authdata`, `Last` describes the age of successful key establishment, `Atmp` counts attempts since then and `NAK` records whether chronyd saw an NTS negative acknowledgment since its last request. None by itself locates the fault.
- **Respond.** Preserve logs and clock estimates before changing the host. Check DNS, certificate chain/name, and current UTC against a trusted independent reference if key establishment fails. If the UDP stage stalls, compare flow records at the actual client and upstream boundary with the documented path. Review the configuration change history if a source changes. Escalate through the time-service owner and annotate affected timestamps with uncertainty. Confirm recovery by observing fresh accepted samples, approved source selection and convergence over successive polls.

## 5. Offline exercise · Six fictional snapshots

Use an authorized lab workspace with Python 3. Download both files into the same directory. The JSON contains normalized observations and answer keys. It is synthetic training data with documentation-only addresses. The script compares JSON fields and performs no network requests. It takes the illustrative clock-error budget from the fixture (10 ms here) and reports independent flags. It does not parse chronyc output or verify packets and certificates.

- <a href="{{ '/assets/downloads/nts-time-source-evidence/inspect_nts.py' | relative_url }}" download>Download the Python checker</a>
- <a href="{{ '/assets/downloads/nts-time-source-evidence/nts_snapshots.json' | relative_url }}" download>Download six fictional snapshots</a>

~~~sh
python3 inspect_nts.py nts_snapshots.json
~~~

| Case | Expected result |
|---|---|
| Healthy | Selected approved source, recent accepted and authenticated evidence, error estimate within budget. |
| Key exchange only | KE observed, NTP measurement not established in the window. |
| Cached report | Historical authenticated response, accepted counter unchanged. |
| Different selected source | Expected NTS source responds, another source wins. Investigate policy and track the winner's auth separately. |
| Unauthenticated selection | Selected source is observed and lacks authentication despite a small reported error. |
| Clock quality alert | Authenticated reference is selected, but the estimated clock error exceeds its budget. |

The checker reports a failed fixture comparison with a nonzero exit code. To test that check, make a copy of the JSON and change only the healthy case's `good_after` to match `good_before`, keeping the expected flags unchanged. Run the checker on the copy. If inputs are missing or the script fails before comparing any case, check the working directory, valid JSON syntax and the downloaded file versions.

## 6. Check your understanding

- **TCP 4460 succeeded. Why could NTP still fail?** A connection is transport evidence. Even successful NTS-KE leaves UDP delivery and measurement checks to be verified. The NTP host or port may differ.
- **Does `Authenticated: Yes` prove NTS is in use and currently disciplines the clock?** Match the last valid response to the source's authentication mode, observe freshness and compare it with the selected and combined sources.
- **Can two authenticated hosts disagree on event order?** Yes. Clock error, path asymmetry and source error remain possible. Compare their uncertainty and seek independent ordering evidence such as shared request IDs.

You have completed the exercise when you can explain which stage each flag comes from, make the changed fixture fail, and name a second observation you would request before diagnosing each failure.

## Official references

Reviewed on **2026-11-27**. The protocol terms follow the 2020 standard. Command fields and selection defaults refer to the released chrony 4.9 documentation, so use the manual for the installed version when collecting production evidence.

- [IETF RFC 8915 §§4–5 and 8–9 · NTS exchange, delay, certificate bootstrapping and privacy, September 2020](https://datatracker.ietf.org/doc/html/rfc8915)
- [chrony 4.9 chronyc manual · Monitoring reports](https://chrony-project.org/doc/4.9/chronyc.html)
- [chrony 4.9 chrony.conf manual · Authentication and source selection](https://chrony-project.org/doc/4.9/chrony.conf.html)
- [chrony project release notes · Version 4.9, August 2026](https://chrony-project.org/news.html)
