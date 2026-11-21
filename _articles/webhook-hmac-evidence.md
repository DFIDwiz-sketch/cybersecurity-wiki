---
title: "Webhook HMAC Evidence · Authenticate, Deduplicate and Confirm the Effect"
description: "Validate the original request bytes, distinguish freshness from duplicate delivery, and investigate the operation that followed."
category: blue-team
tags: [HTTP, Webhooks, HMAC, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/webhook-hmac-evidence/
---

**Learning goal.** Explain what a valid message proves, when an old or repeated delivery may be rejected, and which record proves that the requested action completed.

## 1. What a webhook receiver checks

A **webhook** is an HTTP request sent by a publisher when something happens. The **event** is what happened. A **delivery** is one attempt to send it. A **worker** can process accepted events after the receiver replies. A 2xx response may mean durable receipt while the worker is still pending.

A **message authentication code (MAC)** is a tag calculated from a message using a shared secret. **HMAC** is a standard way to build a MAC from a cryptographic hash. HMAC-SHA256 covers the exact bytes specified by the protocol. A tag match supports integrity and possession of the shared secret. Both sides can calculate it, so the result does not independently identify which holder generated it. The body remains readable unless separately protected. See [cryptography fundamentals]({{ '/wiki/public-key-cryptography/' | relative_url }}).

| Check | Question | Evidence |
| --- | --- | --- |
| HTTPS | Did the publisher connect to its intended endpoint over encrypted transport? | Certificate validation and transport telemetry when available |
| HMAC | Do the covered bytes match a tag from a holder of the endpoint secret? | Verification result, endpoint scope and key version |
| Freshness and authorisation | Is the authenticated time acceptable when available? Is the event and resource allowed? | Time policy, clock offset and authenticated event scope |
| Idempotent processing | Has this event or business operation already taken effect? | Durable receipt, worker result and authoritative state |

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/webhook-hmac-evidence-en.svg' | relative_url }}" alt="Raw bytes are checked before an event is accepted. Rejection ends the validation path. Accepted work proceeds to durable receipt, duplicate handling and effect verification.">
<figcaption>Authentication, receipt and the worker's result are distinct checkpoints.</figcaption>
</figure>

## 2. Follow a normal delivery

A fictional publisher sends a lesson completion event, `evt-a`. The receiver validates the tag over the original request bytes before relying on the parsed event. It applies the provider's signed-time policy if supported, checks the event type and scope, and records accepted work durably. The worker later applies and records the completion. If the publisher retries after losing the acknowledgement, the receiver can recognise the event without repeating the completed operation.

JSON that differs only in whitespace or escaping can decode to the same object and still contain different bytes. Verify what the publisher signed, before middleware rewrites it. Use the vendor's library or an appropriate comparison primitive such as Python's `hmac.compare_digest` with parsed same-type inputs. Keep endpoint secrets in an approved secret store and distinguish test and production keys.

| Provider | Verification | Delivery evidence |
| --- | --- | --- |
| GitHub with a webhook secret | `X-Hub-Signature-256` authenticates the body with HMAC-SHA256. The SHA-1 header is legacy. | `X-GitHub-Delivery` tracks a delivery and stays the same on requested redelivery. The body MAC does not authenticate arbitrary headers or include a signed timestamp. |
| Stripe HTTPS webhook | Pass the raw body, `Stripe-Signature` and endpoint secret to the provider library. | Stripe documents a signed timestamp, a five-minute library default and a new timestamp and tag on retry. Track the event ID separately. |

## 3. Distinguish stale, duplicated and altered input

An authentic delivery can recur through a normal retry, a requested redelivery or misuse of previously valid input. A signed timestamp limits age where supported. It cannot distinguish two deliveries within the accepted interval and a fresh retry can describe an older event. Use the provider's delivery history and the receiver's clock before drawing conclusions.

Deduplication detects repeated input. Idempotency prevents repeated effects. Use a durable uniqueness constraint scoped to the provider contract and the relevant account, environment or endpoint. Use authenticated payload fields for business decisions. Two distinct events can request the same state change, so use a business-operation key where needed. A memory-only set loses state on restart and an independent read then write can race across workers. If the receipt and effect share a database, a single transaction can commit both. For external effects, use a durable handoff, downstream idempotency or reconciliation. One database transaction cannot guarantee exactly-once delivery to another system.

| Observation | Check before attributing cause |
| --- | --- |
| Tag fails just after deployment | Key version and endpoint, raw bytes, middleware order and provider delivery diagnostic |
| Tag passes but time fails | Signed time, receiver UTC and offset, delay and delivery history |
| Event already processed | Provider retry/redelivery history and the scoped committed effect |
| 2xx with no business change | Receipt, queue age, worker retries and authoritative application state |

## 4. Collect and respond

1. Join the sender history and receiver logs by environment, endpoint, IDs and UTC. Record which fields were authenticated and record the receiver's clock offset. Keep verification result, failure category and safe key-version identifier. Keep secrets, full tags and sensitive raw payloads out of general logs.
2. Track invalid/missing tag, time rejection, unsupported event, durable receipt, duplicate, worker retry and commit separately. Alert against a known baseline, for example sustained failures after a rollout or a growing gap between valid receipt and worker completion.
3. Check the durable operation or application audit record before requesting redelivery. If an authorised test is available, check both a known-good event and a repeated one and compare the final state. For suspected secret exposure, coordinate rotation with the integration owner, preserve the relevant receipts and reconcile accepted events against authoritative state.

## 5. Offline lab · count the effects

Download <a href="{{ '/assets/labs/webhook-hmac-lab.py' | relative_url }}" download>the Python HMAC exercise</a> and run `python3 webhook-hmac-lab.py` on an authorised system with Python 3.8+ and `sqlite3` linked to SQLite 3.24+. This self-contained fixture generates a test key and uses a fixed clock and in-memory database. Its own teaching envelope authenticates the raw body and timestamp. The accepted time is at most 300 seconds old and 30 seconds ahead. It does not parse vendor HTTP headers or contact an endpoint.

| Cases | Expected result |
| --- | --- |
| A | Valid event commits one effect. |
| B / C | Changed spacing or wrong test key fails the tag, count stays 1. |
| D / E | Valid tag with time outside the past or future bound is rejected, count stays 1. |
| F / G | A fresh delivery of the same event adds nothing, and a different unsupported event is rejected. |
| H / I | Injected failure rolls back the receipt and effect. A retry commits once, advancing the count from 1 to 2. |
| J | Missing tag is rejected, count stays 2. |

Expect `10/10 webhook controls matched.` If the SQLite module is missing, check the Python installation. If B looks equivalent to A, compare the original bytes. If F seems new, identify the event ID separately from the tag and time. H and I exercise transaction rollback and retry in the local database. The Python fixture ran in the cloud. Production SDKs, live provider delivery and concurrent processing were reviewed as design context.

## 6. Check your reasoning

1. **Does a valid tag encrypt the body?** No. It authenticates covered bytes. Protect confidentiality separately.
2. **Can a fresh delivery describe old work?** Yes. Check event identity and the previously committed outcome.
3. **A sender saw 200. What proves the effect?** The worker or business record correlated by an authenticated and scoped operation key.
4. **Why record the active key version?** It helps diagnose key mismatches during rotation without exposing the secret.

**Completion criteria.** Predict all ten outcomes and counts. Explain which control prevents duplicate effects and name an independent record that confirms the effect.

## Official references

Reviewed 2026-11-22. RFC 2104 is the February 1997 HMAC construction. Follow the documentation for your deployed provider and SDK.

- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) and [Python 3.12 hmac](https://docs.python.org/3.12/library/hmac.html).
- GitHub [validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) and [delivery best practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks).
- Stripe [webhook verification and retries](https://docs.stripe.com/webhooks).
- [SQLite UPSERT](https://www.sqlite.org/lang_upsert.html), available from SQLite 3.24.0.
