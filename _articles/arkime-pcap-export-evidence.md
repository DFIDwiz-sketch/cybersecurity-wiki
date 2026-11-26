---
title: "Arkime PCAP Export Evidence · Validate the File Before Reading Packets"
description: "Distinguish indexed sessions, directional raw bytes and packet captures, then test five offline export cases."
category: network
tags: [Arkime, PCAP, Wireshark, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/arkime-pcap-export-evidence/
---

**Learning path** · [Zeek, Suricata and Arkime]({{ '/wiki/network-monitoring/' | relative_url }}) → export validation → [Packet capture gaps]({{ '/wiki/capture-visibility/' | relative_url }}).

## 1. What did you download?

Arkime lets you search indexed **sessions**, which summarize observed traffic. A session can include endpoints, time range and protocol metadata. **Retained packets** are the saved bytes associated with the session. They can be stored and expired separately from its index entry. An **export** is the file a Viewer produces for the selected query or session. It has its own format, scope and provenance.

**PCAP** is a capture container with a file header followed by packet records. Each record includes a timestamp, the saved length and the reported original packet length. **PCAPNG** uses blocks and can describe multiple interfaces and link-layer types in one file. A **link-layer type** tells a reader how to interpret the first bytes of each frame, for example as Ethernet. **Snaplen** is the maximum bytes a capture source is configured to retain per packet. A short record can be valid when the saved length is smaller than the original length. A file can also end before the bytes that its record header says should be present.

| Artifact | Contains | Best use |
|---|---|---|
| Session row or CSV | Searchable metadata or an export of selected fields | Identify a candidate session, time window and capture node. |
| Source/Destination Raw view | Directional packet data representation. Arkime v7 documents a packet-text response for the raw endpoint. | Inspect the selected direction in context. A filename change cannot turn it into a capture container. |
| PCAP or PCAPNG download | Packet records with capture framing and timestamps | Open in a packet analyzer, compare scope and preserve the export. |
| HTML or JSON in a file named `.pcap` | A response body, possibly a viewer error or sign-in page | Check the response status and specific message in the approved viewer session. |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/arkime-pcap-export-evidence-en.svg' | relative_url }}" alt="Find the indexed session, verify retained bytes on its source node, choose PCAP or PCAPNG export, then check format, packet count and scope on the downloaded file." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Separate the search result, the retained bytes, the export and the analyst's validation.</figcaption>
</figure>

## 2. Follow an ordinary export

**Fictional example.** A Zeek record points to a UDP exchange at 10:14 UTC between `192.0.2.10:53000` and `198.51.100.20:9000`. In the approved Arkime Viewer, search for those endpoints over a window that allows for measured clock skew. Confirm the session's capture node, protocol and time before selecting it. Arkime documents the Sessions page's Actions menu for PCAP exports. Use its capture export and check whether the current UI applies it to selected, visible or matching sessions. Labels and controls can differ by version.

On the analysis copy, a parser reports two Ethernet frames. The first is a UDP request and the second is a reply in the reverse direction. The timestamps and tuple match the expected scope. Record the export time and hash. These observations support what this sensor and export contain. They do not establish that the sensor saw every frame on the wire or that the service accepted the application payload.

For mixed capture sources, the Arkime v7 API documents a PCAPNG requirement when an export spans multiple link types. A classic-PCAP request can therefore return a JSON error instead of capture bytes. Use the supported PCAPNG export or an approved single-link-type subset, and document which scope you acquired. Avoid collecting extra sessions just to test whether the reader works.

## 3. Diagnose the first missing piece

| Observation | What it supports | Next check |
|---|---|---|
| Indexed session exists, Viewer cannot read its packets | Search metadata remains available. Packet access is unresolved. | Confirm your role, source node, original storage location or object availability, and viewer logs. Free-space expiration can delete older local PCAP while leaving indexed sessions. |
| Small download is HTML or JSON | The file contains a response body instead of expected capture records. | Recheck the export action, response status and message. Routes can return a sign-in page, permission error or format requirement. Re-export through the approved Viewer. |
| Reader finds records with captured length below original length | Some records contain a saved prefix. This can occur with a capture snaplen or later slicing. | Preserve the exporter settings and compare the claimed lengths. Bytes absent from the original capture cannot be recovered by changing extensions or opening another reader. |
| Reader reports missing bytes within a packet record | The file does not contain all the bytes declared in that record. | Compare sizes and hashes across authorized copies. Check transfer or storage errors before retrying the same export. |
| Header is valid but packet count is zero | The file contains no recorded packet for analysis. | Verify selected session scope, time range, node, retention and viewer response. A valid header alone cannot prove the requested packet exists. |

Misleading filenames and incomplete exports can send an investigation in the wrong direction. Treat file origin and parser errors as evidence about the export path. Escalate unexpected changes to capture permissions or retention when change records and repeated results support that hypothesis. A lone parse error or absent packet does not establish intent.

## 4. Collect, detect and respond

1. **Collect.** Record case ID, authorized query or session ID, UTC range and timezone, viewer and capture node, product version, filename, export scope, status if available, byte size and SHA-256. Preserve the original read-only in the approved evidence store and inspect a working copy. Packet payload can contain private traffic. Keep it inside the approved evidence boundary. [Evidence preservation]({{ '/wiki/evidence-preservation/' | relative_url }})
2. **Detect.** Compare the file type, count, link-layer type, range and relevant packet lengths against your expectation. Track repeated failures by capture node and export type. Use a known-good export from an approved test source to separate reader issues from a storage or permission problem.
3. **Respond.** If the session exists but PCAP is unavailable, check coverage, role and storage before drawing conclusions about the network. Preserve the response details and failed artifact if relevant, then export again through the approved path. If still unavailable, document the evidence you do have and time window of the gap. Use Zeek, Suricata or endpoint telemetry for independent corroboration.

Run these local read-only examples on an authorized capture copy with Wireshark's `capinfos` and `tshark` installed. `file` tests a signature and can identify a PCAP whose last record is broken. `capinfos` inspects type, encapsulation, packet count, snaplen, timestamps and hashes. The display filter below compares per-frame saved and reported lengths. A filter with no output means no such decoded frame matched, subject to reader warnings and exit status.

~~~sh
file evidence.pcap
capinfos -t -E -c -l -a -e -H evidence.pcap
tshark -n -r evidence.pcap -Y 'frame.cap_len < frame.len' -T fields \
  -e frame.number -e frame.cap_len -e frame.len
~~~

## 5. Offline exercise · Five files with the same extension

Use Python 3 in an authorized disposable workspace. The script writes two fictional Ethernet/IPv4/UDP packets and no traffic leaves the workspace. The files use fixed synthetic times and documentation addresses. `make` requires new filenames and refuses to overwrite existing files. The `check` command validates this lab's classic PCAP 2.4 structure and hashes its bytes. It recognizes the PCAPNG signature and directs you to a suitable reader. It does not decode every packet or certify production captures.

- <a href="{{ '/assets/downloads/arkime-pcap-export-evidence/inspect_pcap.py' | relative_url }}" download>Download the PCAP exercise script</a>

~~~sh
python3 inspect_pcap.py make samples
python3 inspect_pcap.py check samples/intact.pcap samples/sliced.pcap samples/header-only.pcap
python3 inspect_pcap.py check samples/broken.pcap samples/response.pcap
~~~

| File | Expected result |
|---|---|
| `intact.pcap` | 2 records, 0 sliced. |
| `sliced.pcap` | 2 structurally valid records, both sliced at 48 bytes. |
| `header-only.pcap` | Valid classic-PCAP header, 0 records. |
| `broken.pcap` | Last packet record declares more bytes than the file retains. |
| `response.pcap` | HTML response content despite its filename. |

The first check should exit 0. The second reports both problems and exits 1. If generation fails because the files exist, use a new directory. If an external reader reports an unexpected count, compare the hash, input path and reader diagnostics. In the execution check, the script classified all five samples. The `file` utility identified the HTML and reported PCAP signatures for all four other files, including the broken one. Arkime and Wireshark steps are based on documentation and were not run against those products.

## 6. Check your understanding

- **Does a session row prove a packet copy exists?** No. Check the source node's retention and the Viewer export.
- **Can the same output be valid and sliced?** Yes. A structurally valid record can contain fewer bytes than the reported original frame.
- **Does matching SHA-256 prove export completeness?** It supports equality of the bytes compared. The investigation still needs evidence for session selection, capture coverage and time.

Complete the chapter by identifying both failing files, explaining how sliced and broken records differ, and listing the evidence needed to link a real export to a specific sensor and query.

## Official references

Reviewed **2026-11-27**. Arkime export behavior refers to the version 7 API and the publisher's Sessions documentation. Check your installed Viewer and Wireshark versions. The IETF documents describe historical classic PCAP and the PCAPNG format as Internet-Drafts at review time.

- Arkime · [Sessions and PCAP export](https://arkime.com/#sessions-page), [v7 API](https://arkime.com/apiv7), [storage settings](https://arkime.com/settings) and [retention troubleshooting](https://arkime.com/faq).
- Wireshark · [capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html), [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) and [frame filter fields](https://www.wireshark.org/docs/dfref/f/frame.html).
- IETF OPSAWG · [PCAP draft -09](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/09/) and [PCAPNG draft -06](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/06/).
