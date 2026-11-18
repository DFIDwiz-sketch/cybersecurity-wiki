---
title: "User-Agent field guide: legitimate clients and malware associations"
description: "Six connected chapters and 100 sourced reference entries covering names, meanings, malware associations, collection and investigation."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/ko/wiki/user-agent-guide/"
user_agent_series: true
---
{% include ua-series.html %}

## Scope and how to use this guide

A User-Agent (UA) describes how software **introduces itself** in an HTTP request. Browsers, API clients, update services, crawlers, scanners and malware can all send it. Servers use it for compatibility, analytics and troubleshooting. Defenders use it as one clue when investigating unusual traffic.

This reference contains **100 entries reviewed on 17 November 2026**: 34 legitimate-client entries and 66 malware-associated, overlapping or detection-rule candidates. Some entries are complete values; others are product tokens or prefixes. This does not mean 100 malware families or 100 independent complete UA strings.

There is no complete global list of every abnormal UA: arbitrary strings, private observations, changing samples and configurable profiles make that impossible. Observations here belong to the cited public reports, **not a review of your organisation's logs**. Malware can use a perfectly ordinary browser UA, and absence from this reference establishes neither safety nor lack of compromise.

## Learning path

| Chapter | Outcome |
| --- | --- |
| [Anatomy and meanings]({{ '/wiki/user-agent-anatomy/' | relative_url }}) | Separate compatibility tokens, product versions and platform claims |
| [Legitimate clients]({{ '/wiki/user-agent-normal-reference/' | relative_url }}) | Recognise browser, library, crawler and security-tool identities |
| [Malware associations]({{ '/wiki/user-agent-malware-reference/' | relative_url }}) | Record source, period, matching semantics and attribution limits |
| [Collection and hunting]({{ '/wiki/user-agent-hunting/' | relative_url }}) | Check visibility and correlate network, authentication and process evidence |
| [Synthetic lab]({{ '/wiki/user-agent-lab/' | relative_url }}) | Analyse 20 events and distinguish fact, hypothesis and missing evidence |

## Essential distinctions

- Mozilla does not necessarily mean Firefox. Safari also appears in Chromium compatibility strings.
- curl, PowerShell and Requests are legitimate tools. Their use in an attack does not make every request malicious.
- A security-product name in a UA is not an authenticated signature. BunnyLoader samples have impersonated such names.
- HTTPS encrypts HTTP headers. A passive TAP normally cannot read the UA without decrypted traffic or endpoint/server telemetry.
- A string match identifies an investigation candidate, not a malware family, actor or successful infection.

## Downloads and maintenance

[CSV]({{ '/assets/data/user-agents.csv' | relative_url }}) · [JSON with sources]({{ '/assets/data/user-agents.json' | relative_url }})

Every entry includes an ID, category, pattern, match mode, associated name, explanation, evidence type, source URL, source period, review date and limitations. `reviewed` is an editorial check date, not a first/last-seen infection date. Historical reports do not establish present prevalence. These files are references, **not automatic blocklists**.

When adding an observation, preserve exact spelling, punctuation, whitespace and event identifiers. Distinguish the downloader's request from the final payload's C2. Do not assign one UA to every payload in a multi-malware incident. Add the original source, scope, match mode and a legitimate-traffic comparison. Leave unverified associations pending instead of inventing a family name.

## Sources

[RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#name-user-agent) · [MDN reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent) · [Splunk detection updated in 2026](https://research.splunk.com/network/8c4866e4-f488-4253-8537-7dc4f954c292/)

{% include ua-series.html %}

## HTTP requests and web logs

[HTTP status codes and proxy-to-app log correlation]({{ '/wiki/http-evidence/' | relative_url }})
