---
title: "Getting Started with Splunk Security Investigations"
description: "Learn a practical approach to reviewing indexes, time ranges, event fields, and potential security incidents."
category: tools
tags: [Blue Team, DFIR, Splunk, SIEM, Logs]
level: Beginner
updated: "2026-10-17"
translation_url: /ko/wiki/splunk-basics/
---
## Verify telemetry first
Before searching for suspicious behavior, establish which indexes and sourcetypes exist, the relevant time window, and any ingestion delays.

```spl
| tstats count where index=* by index
```

Your results depend on access permissions and the environment's indexing configuration.

## Investigation checklist
1. Confirm that the required log sources are searchable.
2. Narrow the search using relevant user accounts, hosts, and IP addresses.
3. Correlate events before and after the initial indicator.
4. Record observed facts separately from hypotheses.
