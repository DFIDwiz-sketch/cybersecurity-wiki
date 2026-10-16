---
title: "Introduction to Windows Security Event Analysis"
description: "Learn to correlate authentication and process events when investigating Windows security incidents."
category: dfir
tags: [DFIR, Blue Team, Windows, Event Logs]
level: Beginner
updated: "2026-10-17"
translation_url: /ko/wiki/windows-logs/
---
## Important event IDs
- **4624:** Successful logon
- **4625:** Failed logon
- **4688:** Process creation (requires the appropriate auditing policy)
- **4769:** Kerberos service ticket request

Whether an event is recorded depends on the system's audit policy. Avoid drawing conclusions from a single event without corroborating evidence.
