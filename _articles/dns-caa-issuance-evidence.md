---
title: "DNS CAA Issuance Evidence · From Lookup to Certificate"
description: "Trace CAA parent and alias lookups, issuer and wildcard checks, and renewal failures with eight offline cases."
category: network
tags: [DNS, CAA, PKI, Certificates, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/dns-caa-issuance-evidence/
---

**Learning goal.** Explain which DNS CAA record set applies to a requested certificate name, then distinguish an issuer restriction from a failed lookup or a certificate deployment problem.

## 1. What CAA controls

**Certification Authority Authorization (CAA)** is a DNS record type that a public TLS certificate authority (CA) consults before issuance. An **RRset** is the records of one type at one DNS owner name. The **issuer identifier** is the DNS-style name the CA documents for use in CAA values. It need not match the issuer display name in a certificate. **SAN** is the Subject Alternative Name extension, which contains the DNS names a certificate covers.

A CA normally checks each requested DNS name, including each wildcard name. This check narrows who may issue. The applicant must still prove domain control, and other issuance checks still apply. The browser's check of a deployed certificate is a separate step. Changing CAA does not revoke a certificate or replace the certificate served by a load balancer.

| Record | Role |
| --- | --- |
| `0 issue "ca-a.example"` | Authorizes the named issuer for ordinary names. It can also apply to wildcards when no `issuewild` is present. |
| `0 issuewild ";"` | Authorizes no issuer for wildcards through this entry. Another applicable `issuewild` entry may still authorize one. |
| `0 iodef "mailto:security@example"` | Advertises a reporting destination. It grants no permission, and report delivery is not guaranteed. |
| Unsupported property with flag `128` | The issuer-critical flag requires an issuer that cannot process the property to stop issuance for the name. |

An applicable `issue ";"` alone denies all issuers. Combining it with a valid applicable authorization does not cancel that authorization. When the relevant set contains no applicable issuer tags and no unhandled critical properties, CAA alone leaves issuance unrestricted. The first nonempty set still stops the parent search, even if it contains only a reporting property.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-caa-issuance-evidence-en.svg' | relative_url }}" alt="For each requested name, query CAA and follow aliases. A usable nonempty record set stops the search. An empty successful result leads to the original name's parent. A lookup error requires investigation. Then evaluate issuer tags before other issuance checks.">
  <figcaption>Keep the result of DNS discovery separate from evaluation of the records it returned.</figcaption>
</figure>

## 2. Follow a routine renewal

A team requests `api.example` and `*.apps.example` from fictional `ca-a.example`. The response for `api.example` has no CAA records and the next lookup at `example` returns `issue "ca-a.example"`. For the wildcard, start at `apps.example`, without the leading wildcard label. Suppose that set contains `issue "ca-a.example"` and `issuewild ";"`. The ordinary name is authorized by CAA, but the wildcard is blocked by the applicable wildcard policy. The team checks both names before retrying the combined order.

At each step the CA performs DNS lookup for the current name, including following CNAME or DNAME aliases where applicable. If that lookup returns no CAA after following the alias, the next parent-search step removes a label from the current query name on the **original** branch. A CAA record at the alias target itself can supply the relevant set. Do not automatically substitute a target's parent policy. Keep the query names, aliases and exact returned owner names so this distinction remains visible.

## 3. Diagnose a failure or unexpected issuance

| Observation | Next evidence to collect |
| --- | --- |
| No CAA answer with a usable negative response | Keep the header and authority section. Distinguish NOERROR with no type data from NXDOMAIN. Verify aliases and parent lookups. |
| SERVFAIL, timeout or DNSSEC validation error | Compare validating resolver and authoritative observations. Preserve the failure and DNSSEC context. A failed query is not evidence that CAA was empty. |
| Allowed at your resolver, refused by the CA | Compare the CA's issuer identifier and reported name, wildcard tags, applicable parameters, DNS change history, TTLs and network perspectives. |
| New certificate issued, clients still see the old one | Inspect the served leaf and the intended TLS endpoint; issuance and deployment have separate evidence. |

A DNS change can add an unintended issuer, block a renewal path, or cause inconsistent responses across providers. A planned migration, a stale cache or a broken delegation can also explain mismatches. Preserve the approved change, control-plane DNS audit history, request or order ID, SAN list, returned DNS sets, TTLs, resolver vantage and timestamps in UTC. A local observation made after the fact does not prove the CA saw the same set at issuance. Current public TLS Baseline Requirements require DNSSEC validation for primary-perspective CAA lookups and prohibit treating DNSSEC validation errors in that context as permission. Consult their scoped exceptions and perspective requirements; the offline exercise stops at lookup errors.

Compare the issuer and names with your authorized CA and inventory. Verify the actual served certificate and check Certificate Transparency (CT) for matching logged entries where applicable. A CT entry can support a timeline; it does not show when a server started serving the certificate. If a change is unauthorized, preserve evidence, coordinate DNS correction with the operator, and validate from the approved vantage points before retrying. Escalate suspected unauthorized issuance to the CA through your incident process. Do not copy private keys into incident evidence.

## 4. Practice with offline evidence

Download the <a href="{{ '/assets/labs/dns-caa-issuance-evidence.py' | relative_url }}" download="dns-caa-issuance-evidence.py">Python script</a> and <a href="{{ '/assets/labs/dns-caa-issuance-evidence-cases.json' | relative_url }}" download="dns-caa-issuance-evidence-cases.json">fictional lookup cases</a>. Put them in one approved workspace. The file supplies recorded steps including alias outcomes. The script uses only the first supplied nonempty set, or reports a lookup error or missing evidence. It does not resolve DNS, implement CA-specific parameters or issue a certificate.

```bash
python3 dns-caa-issuance-evidence.py dns-caa-issuance-evidence-cases.json
```

```text
parent: authorized_by_caa
wildcard: issuer_not_authorized
alias_target: issuer_not_authorized
empty_and_allowed: authorized_by_caa
critical: unsupported_critical_property
report_only: unrestricted_by_caa
lookup_error: lookup_unresolved
missing_parent: incomplete_evidence
```

Use Python 3. If the input cannot be opened, check the directory and names. For an unexpected decision, read the selected set and whether the name is a wildcard. In this simplified fixture, `complete` means all required lookups were supplied even if they were empty. The eight cases were executed offline.

For a separate live read-only comparison, use `dig @RESOLVER_IP YOUR_APPROVED_NAME CAA` on a name you control, with BIND's `dig` and an approved resolver. Record the resolver, response code, alias answers, TTL and authority section. Repeat at each parent when the response is a usable negative result. A wildcard certificate starts with the base name without `*.`. Do not use `+short` as your only evidence. A local query does not reproduce the CA's perspective. The command and CA workflow were reviewed in documentation and were not exercised against a live CA or DNS zone for this chapter.

## 5. Check your reasoning

- **The leaf has an `iodef` record and its parent has an `issue` restriction. Does the restriction apply?** The leaf's nonempty set stops the search. The reporting property does not set an issuer restriction.
- **A lookup returns SERVFAIL. Can you record “no CAA”?** Keep the failure and investigate resolver and DNSSEC evidence. There is no successful empty result.
- **CAA now allows the right CA. Does that prove users get the new certificate?** Inspect the certificate at the intended client-facing endpoint and compare it with issuance and deployment evidence.

Finish when all eight cases match and you can identify the selected set, explain which tag matters and name an independent source for deployment evidence.

## Official references

Reviewed November 23, 2026. RFC 8659 (2019) supersedes the original RFC 6844. The CA/Browser Forum public TLS Baseline Requirements reviewed here are version 2.3.1 (October 4, 2026). Historical incidents need the rules effective at the time.

- Name discovery, properties and wildcard behavior. [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html)
- Issuer checks, DNSSEC and multiple perspectives. [CA/Browser Forum TLS Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)
- Issuer identifier and vendor-specific examples, updated October 4, 2026. [Let's Encrypt CAA documentation](https://letsencrypt.org/docs/caa/)
- Query syntax and diagnostics. [BIND 9 dig manual](https://bind9.readthedocs.io/en/latest/manpages.html#dig-dns-lookup-utility)

[Previous · DNS investigation]({{ '/wiki/dns-investigation/' | relative_url }}) · [Next · Certificate renewal evidence]({{ '/wiki/certificate-renewal-evidence/' | relative_url }}) · [Related · Certificate Transparency]({{ '/wiki/certificate-transparency-evidence/' | relative_url }})
