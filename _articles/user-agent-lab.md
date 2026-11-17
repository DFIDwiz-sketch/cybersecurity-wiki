---
title: "User-Agent investigation lab: 20 synthetic events and worked answers"
description: "Compare approved tools, malware-associated strings, browser impersonation and missing encrypted visibility without external traffic."
category: "tools"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/ko/wiki/user-agent-lab/"
user_agent_series: true
---
{% include ua-series.html %}

## Prerequisites and scope

Use Python 3's standard library. All events, assets, destinations and process contexts are **synthetic**. Reserved .example names and documentation IPs are not real IOCs. No malware runs and no external connection is made. The dataset compares several techniques; it is not a claim that one real incident involved every family.

[20-event JSONL]({{ '/assets/labs/user-agent/events.jsonl' | relative_url }}) · [Analyzer]({{ '/assets/labs/user-agent/analyze.py' | relative_url }}) · [Reference JSON]({{ '/assets/data/user-agents.json' | relative_url }}) · [Worksheet]({{ '/assets/labs/user-agent/worksheet.md' | relative_url }})

Save events.jsonl, analyze.py and user-agents.json in one directory. The events use a simplified educational schema, not a product-native export.

## 1. Run the analyzer

```bash
python analyze.py events.jsonl user-agents.json
```

```text
events=20
ua_present=18 ua_empty=1 ua_unavailable=1
association_candidates=10
candidate_ids=E04,E05,E06,E07,E08,E09,E10,E11,E12,E20
```

Ten candidates do not mean ten infections. The script compares source-reference strings; it does not judge approvals, executable authenticity or family attribution. Matching is case/whitespace preserving and respects exact, prefix and contains. Empty and unavailable values are excluded.

## 2. Worked interpretation

| Events | Observation | Interpretation and next check |
| --- | --- | --- |
| E01–E03 | Browser, approved CI curl and backup Requests | Context supports legitimate use; UA does not prove safety |
| E04 | Approved backup with python-requests/2.32.3 | Matches a published campaign value; review business evidence rather than declare malware |
| E05–E06 | TeslaBrowser, new external POST destination | Lumma-associated candidate; collect process and transfer evidence |
| E07–E08 | Two Raccoon-associated strings | Association does not establish a shared incident or actor |
| E09 | Windows Defender name, unusual executable location | Investigate impersonation; validate BunnyLoader hypothesis |
| E10 | Axios and an authentication request | Inspect outcomes, sessions and accounts before attributing AiTM |
| E11–E12 | Identical Edge-shaped UA | Suspicious versus approved process context cannot be separated by UA |
| E13 | Passive TLS, unavailable UA | Visibility gap; collect endpoint/proxy evidence |
| E14 | Logged empty header | Different from unavailable; check application/logging configuration |
| E15–E16 | Same Nmap identity, different approvals | Separate authorised scanning from unapproved reconnaissance, not malware families |
| E17 | Claims Googlebot | Claim is unverified; do not run real origin validation on synthetic IPs |
| E18 | recording-client/2 | Does not equal record; negative control for substring false positives |
| E19 | Approved Go service | Standard library identity alone is not suspicious |
| E20 | Developer test called Project1 | Collides with a historical rule candidate; not confirmed DarkCloud |

## 3. Separate facts, hypotheses and missing evidence

For E05, record observed raw facts, the public-source association and additional evidence needed. POST and traffic volume do not identify the transmitted content. Check destination ownership, process, request/response and file evidence.

Compare E11 and E12: the UA is identical but the process context differs. Compare E13 with E14: unavailable is different from a recorded empty value. E18 demonstrates why substring searches and exact detections must not be confused.

## 4. Worksheet and completion criteria

Record candidate/source IDs, match mode, observation point, asset/account, destination, process, legitimate explanation, corroboration, uncertainty and follow-up action. Write a bounded finding rather than a definitive malware label.

**Complete when:** you reproduce 20 events and ten candidates; explain legitimate overlaps E04/E12/E20; identify the E18 substring trap and E13 visibility gap; and propose additional collection for at least two events.

## Validation limits

The repository validator checks catalogue/CSV consistency, event schema, match modes, expected IDs and string byte length. It does not claim execution of this synthetic dataset on Splunk, Suricata, Zeek or Arkime. Real deployment needs separate parser, logging and engine validation.

{% include ua-series.html %}
