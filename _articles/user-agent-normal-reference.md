---
title: "Legitimate User-Agent reference: browsers, libraries and crawlers"
description: "34 documented product tokens and identities with meanings, verification steps and legitimate-use limitations."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/ko/wiki/user-agent-normal-reference/"
user_agent_series: true
---
{% include ua-series.html %}

## A legitimate product name does not authenticate a request

This table explains identities used by legitimate software. It is not an allowlist. Verify the actual executable, signature/path, user or job owner, approved destination, timing and business purpose. Malware can impersonate the same value, and legitimate software can be abused.

## Interpret browsers and embedded applications

1. Prefer specific Edg, OPR or SamsungBrowser markers over an embedded Chrome token.
2. Consider embedded web views. Android's common `; wv` marker can be overridden.
3. Separate product versions from compatibility numbers: Safari/537.36 is not a Safari app release.
4. Compare platform claims with asset inventory rather than accepting them as facts.
5. Several UAs from one host can reflect multiple applications, updates or parallel jobs, rather than evasive rotation.

Some Chromium products, including Brave, do not always offer a distinct product token. App versions and embedded engines also affect Teams, Slack and Discord requests. Product names need not appear in their UAs. Build a baseline for your deployed versions instead of expecting a perfect product identifier.

## Interpret libraries and command-line clients

curl, Requests and PowerShell support legitimate backup, deployment, monitoring and API integration. Their UAs do not reveal script authors, executable paths or command lines. Go-http-client/1.1 is not a Go compiler version. Traditional Java networking and other Java HTTP libraries may use different identities.

Node's HTTP adapter, bundled Fetch, standalone Undici and manually constructed HTTP requests can differ. Axios running in a browser may send the browser identity instead of the server-side axios token. Verify a default against the relevant source and your installed version.

## Verify crawlers

A request claiming Googlebot should not automatically bypass controls. Compare with published source ranges, or verify the reverse-DNS domain boundary and resolve it forward back to the original IP. A suffix such as googlebot.com.attacker.example is not Google's domain. Only trust original-client headers from approved intermediaries.

GPTBot, OAI-SearchBot and ChatGPT-User have different purposes. Check the provider's current documentation, ranges and policy scope. robots.txt is a cooperative crawling policy, not authentication or access control. An unfamiliar crawler is not automatically malware.

## Searchable legitimate-client table

All entries were reviewed on 17 November 2026. `exact` means full-value equality; `prefix` means start-of-value; `contains` means token inclusion. The search box performs text search for navigation and is not a detection engine.

{% include ua-catalog.html kind='normal' %}

## Other familiar forms and scoped exceptions

You may also encounter okhttp/, Apache-HttpClient/, CFNetwork/, Darwin/, Electron/, HeadlessChrome/, git/ and AzureCLI/. These are recognition examples, not version-specific defaults validated as catalogue entries here. Confirm vendor documentation, source and a sample from your deployed version before adding them to your baseline. Browser automation can also resemble an ordinary browser, so absence of a headless marker does not establish human activity.

Scope exceptions to asset group, owner, approved destination, scheduled time, expected identity range and expiry date. Requests on a backup server can be expected, while its first appearance on a workstation posting to a new external destination warrants investigation. Apply similar reasoning to storage-transfer and remote-management software.

[Verify Google requests](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests) · [OpenAI bots](https://developers.openai.com/api/docs/bots) · [Requests header overrides](https://docs.python-requests.org/en/stable/community/faq/) · [Malicious overlaps]({{ '/wiki/user-agent-malware-reference/' | relative_url }})

{% include ua-series.html %}

[Brave 공식 UA 안내 / Brave UA documentation](https://github.com/brave/brave-browser/wiki/Detecting-Brave-%28for-Websites%29)
