---
title: "User-Agent collection and hunting with Splunk, Zeek, Suricata and Arkime"
description: "Check encrypted visibility, preserve raw fields, find rare values and correlate candidates with process and authentication evidence."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/ko/wiki/user-agent-hunting/"
user_agent_series: true
---
{% include ua-series.html %}

## 1. Establish the observation point

| Source | UA visibility | Check first |
| --- | --- | --- |
| Clear HTTP TAP/SPAN | Available if parsed/logged | Bidirectional capture, loss, ports and logging |
| Passive HTTPS TAP | Normally unavailable | Decrypted feed or permitted key-based inspection |
| Proxy, WAF, web server | At the point that parses/logs the request | TLS termination, truncation, address/header rewriting |
| Endpoint or application | Product/event-dependent | HTTP headers are not present in every network event |
| Cloud sign-in service | What that service records | Collection, normalisation and authentication-flow semantics |

TLS 1.3, HTTP/2 and HTTP/3 can carry the UA inside encryption. Confirm parser and decryption support for your version. Port 443 does not make a plaintext HTTP rule decrypt TLS. SNI, certificates and TLS fingerprints are different evidence, not recovered UA text.

With continuous network collection and on-demand Velociraptor Hunts, historical process evidence may already be gone. Sysmon 1/3 and Security 4688 depend on policy, collection and retention and do not generally contain the HTTP UA. No current socket during a later Hunt is not proof of no earlier connection.

## 2. Normalise without destroying evidence

| Source | Example field | Correlation |
| --- | --- | --- |
| Zeek JSON | user_agent | id.orig_h, uid, trans_depth and time |
| Suricata HTTP EVE | http.http_user_agent | src_ip, flow_id and transaction ID if present |
| Splunk CIM Web | http_user_agent | src, dest, url, http_method |
| ECS-mapped logs | user_agent.original | Actual source/destination mapping |
| Arkime | http.user-agent | Session, endpoints and time; potentially multiple values |

Keep the raw value and add a normalised analysis field. Missing fields, null, an empty header and Zeek TSV's unset marker are different. Mark truncation. Escape untrusted values in dashboards and never execute log text. Collecting UA evidence does not justify indiscriminate collection/sharing of cookies or authentication tokens.

## 3. Splunk field coverage and rarity

These are illustrative SPL searches, not rules executed on a live Splunk server. Replace YOUR_WEB_INDEX and adapt field extraction; check sourcetypes/spath if nested JSON is not extracted.

```spl
index=YOUR_WEB_INDEX earliest=-24h
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original'),
       src=coalesce(src,src_ip,'id.orig_h'), dest=coalesce(dest,dest_ip,'id.resp_h')
| eval ua_state=case(isnull(ua),"not_recorded",len(ua)=0,"empty",true(),"present")
| stats count dc(src) as hosts values(sourcetype) as feeds by ua_state
```

If everything is not_recorded, fix collection before tuning a detection. Then compare identity frequency, host spread and destinations:

```spl
index=YOUR_WEB_INDEX earliest=-7d
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original'),
       src=coalesce(src,src_ip,'id.orig_h'), dest=coalesce(dest,dest_ip,'id.resp_h')
| where isnotnull(ua) AND len(ua)>0
| stats count dc(src) as hosts dc(dest) as destinations min(_time) as first_seen max(_time) as last_seen by ua
| sort 0 hosts count
```

Low host count is a review priority, not a malicious verdict. Compare asset roles, scheduled jobs and a suitable baseline, initially perhaps 14–30 days depending on operations. Preserve both raw values and parsed families; removing every digit can merge unrelated identities. min(_time) within a query is not an organisation's historical first-ever sighting.

## 4. Exact candidates and richer correlation

```spl
index=YOUR_WEB_INDEX earliest=-24h
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original')
| where ua IN ("TeslaBrowser/5.5","record","rc2.0/client","Mozilla/4.08 (Charon; Inferno)")
| table _time src src_ip dest dest_ip ua http_method method url
```

This compares full values. A substring condition for record changes the detection. A CSV lookup does not automatically implement the catalogue's prefix/contains semantics: separate exact entries or explicitly implement the modes. Case-insensitive matching is another deliberate policy.

Combine a new UA with a new destination, unusual process or repeated POST behaviour. Verify baseline retention and outages. Header order and TLS fingerprints can support a hypothesis but do not authenticate a client.

## 5. Inspect Zeek and Suricata JSON

For JSON Lines Zeek input, not TSV:

```bash
jq -r 'select(.user_agent != null) | .user_agent' http.json | sort | uniq -c | sort -nr
```

For Suricata EVE HTTP transactions:

```bash
jq -c 'select(.event_type == "http") | {timestamp,src_ip,dest_ip,flow_id,http}' eve.json
```

Alert-only logging may not contain HTTP events. Zeek uid and Suricata flow_id are different identifiers. Within a sensor use supported connection/transaction keys; across tools validate time, observation point, five-tuple and configured Community ID, considering NAT and proxies.

## 6. Illustrative Suricata rule

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL UA candidate TeslaBrowser exact"; flow:established,to_server; http.user_agent; content:"TeslaBrowser/5.5"; bsize:16; sid:9900101; rev:1;)
```

This educational rule has not been executed on a live Suricata engine here. It intends full-buffer equality for a 16-byte string. Adding nocase changes the condition. Check SID allocation, network variables, HTTP parsing, normalisation and loading on your installed version:

```bash
suricata -T -c /etc/suricata/suricata.yaml -S ua-local.rules
```

A successful syntax check does not establish accuracy or decryption. Replay positive, appended-character, normal-browser and encrypted-only controls. Lack of an alert on encrypted traffic may simply reflect missing visibility.

## 7. Wireshark and Arkime

Wireshark plaintext HTTP display filter:

```text
http.user_agent == "TeslaBrowser/5.5"
```

Arkime expression:

```text
http.user-agent == "TeslaBrowser/5.5"
```

Verify field autocomplete and collected values. Inspect timestamps, endpoints, requests/responses and retained packets. Searchable sessions do not guarantee PCAP retention. HTTP/2/3 availability depends on parsers and decrypted input.

## 8. From candidate to incident decision

Preserve event ID, raw value, collection point and time. Record exact match semantics and source. Review approved applications and destinations. Correlate DNS, URLs, login/session activity, processes and transfers. POST, bytes or HTTP 200 alone cannot prove exfiltration. Collect process path, signature, hash, ancestry and timing; a browser process name alone cannot exclude injection. Choose response based on corroborated evidence, and distinguish an action request from confirmed completion.

**Completion:** reproducible search, raw evidence, legitimate-use review, independent corroboration, limitations, response owner and follow-up validation.

## Official references

[Zeek](https://docs.zeek.org/en/current/reference/logs/http.html) · [Suricata](https://docs.suricata.io/en/suricata-8.0.8/rules/http-keywords.html) · [Arkime field source](https://github.com/arkime/arkime/blob/main/capture/parsers/http.c) · [Wireshark](https://www.wireshark.org/docs/dfref/h/http.html) · [Splunk](https://research.splunk.com/network/8c4866e4-f488-4253-8537-7dc4f954c292/)

{% include ua-series.html %}
