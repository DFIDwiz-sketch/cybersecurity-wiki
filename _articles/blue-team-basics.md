---
title: "Blue Team Fundamentals: Detection to Response"
description: "An introduction to security monitoring, triage, investigation, incident response, and detection improvement."
category: blue-team
tags: [Blue Team, SOC, DFIR, Detection Engineering]
level: Beginner
updated: "2026-10-17"
translation_url: /ko/wiki/blue-team-basics/
---
## What does a Blue Team do?
Blue Teams protect systems through a continuous cycle: **visibility → detection → triage → investigation → response → validation**.

## Where to start an investigation
- Identify which logs are collected and where visibility is missing.
- Understand the conditions that triggered the alert.
- Collect evidence to distinguish false positives from security incidents.
- Record the likely impact, affected systems, and unresolved questions.

## Related article
- [Detecting Kerberoasting]({{ '/wiki/kerberoasting/' | relative_url }})

## HTTP User-Agent

[User-Agent field guide and detection lab]({{ '/wiki/user-agent-guide/' | relative_url }})

## Linux authentication investigation

[SSH, PAM and sudo logs with an offline timeline]({{ '/wiki/linux-auth-evidence/' | relative_url }})

## AWS IAM Roles and CloudTrail Investigation

[Temporary role sessions and the CloudTrail evidence lab]({{ '/wiki/aws-iam-role-evidence/' | relative_url }})

## Detection Validation · From Event Generation to Alert Delivery

[Evidence and offline detection validation lab]({{ '/wiki/detection-validation/' | relative_url }})
