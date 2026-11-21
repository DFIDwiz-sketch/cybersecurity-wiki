---
title: "Amazon S3 Object Deletion · Version and Recovery Evidence"
description: "Distinguish a delete marker from permanent version loss, correlate S3 deletion evidence, and verify a recovery candidate."
category: cloud
tags: [AWS, Amazon S3, CloudTrail, Cloud Security, DFIR, Blue Team, Backups]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/s3-version-recovery-evidence/
---

**Learning goal.** When an S3 object appears to disappear, explain which request or lifecycle action is supported by the evidence, which versions remain, and what you still need to verify before restoring one. Start with [S3 object read evidence]({{ '/wiki/s3-object-read-evidence/' | relative_url }}) if bucket, key or CloudTrail data events are new to you.

## 1. Why a missing key has several explanations

Applications usually read an S3 **key**, such as `reports/daily.csv`, without asking for a particular **version ID**. In a general purpose bucket with versioning enabled, multiple versions of that key can coexist. The **current version** is the one S3 resolves for ordinary reads. A **noncurrent version** remains addressable by ID. A **delete marker** also has an ID and can be current, but holds no object data. When it is current, ordinary reads behave as though the key is missing.

**S3 Lifecycle** applies configured rules to eligible objects or versions. **S3 Object Lock** protects a particular data version using a retention period, a legal hold, or both. Protecting a version can preserve its data while a newer delete marker hides it from ordinary reads. Track current visibility and retained data as separate facts.

<figure>
  <img src="{{ '/assets/diagrams/s3-version-recovery-en.svg' | relative_url }}" alt="An unqualified delete adds marker m1 above data versions v2 and v1. Current HEAD returns 404. A version listing still shows both data versions, and a permitted version-specific HEAD of v2 returns 200.">
  <figcaption>The marker changes the current view. In this example, both data versions survive and v2 is a candidate for verification.</figcaption>
</figure>

## 2. Follow the version timeline

Suppose a reporting job wrote `v1` at 09:00 UTC and `v2` at 10:00. An approved cleanup at 10:05 sent a delete request without a version ID. It returned HTTP 204 and created marker `m1`. At 10:06 an application reading the current key saw 404. A responder listed the key's versions and found `m1` with `IsLatest=true`, plus `v2` and `v1` under `Versions`. A permitted HEAD for `v2` returned 200. This is a fictional normal sequence. The 404 describes a current read, while the list and HEAD show why a data version merits further recovery checks.

| Action or observation | Possible effect with versioning enabled | What to verify |
| --- | --- | --- |
| Delete request omits version ID | Adds a current delete marker | Listing shows the marker and any retained data versions |
| Successful deletion of a specific data version | Permanently removes that version from the bucket | Compare exact IDs with a previous inventory or a trusted change record |
| Successful deletion of a specific marker | If it was current, the next surviving entry determines visibility | A prior data version, an older marker, or no entry can take its place |
| Current HEAD encounters a marker | S3 returns 404 and indicates a delete marker | Inspect the marker header where the tool exposes it, then list versions |
| HEAD explicitly targets an existing marker ID | S3 returns 405 with marker information | Treat the ID as a marker. Check data versions separately |

Confirm the bucket's versioning state **at the event time**. In a bucket where versioning was never enabled, a regular delete permanently removes the object. When versioning is suspended, an unqualified delete can remove a data version whose ID is `null` and creates a delete marker. Data versions with other IDs can remain. The timeline and lab below assume versioning stayed enabled.

## 3. How data can disappear or become inaccessible

Someone misusing a role with object-delete access, or a misconfigured cleanup job, can hide current keys. A principal permitted to delete specified versions can cause permanent loss when policy and retention allow it. Lifecycle expiration can also change visibility or permanently remove eligible noncurrent versions without a customer's delete request for each key. A large batch during a scheduled cleanup window can be expected. Compare it with the job's allowed bucket, prefix and requested version scope before making that call.

With Object Lock, governance retention can be bypassed by a request explicitly requesting bypass and backed by `s3:BypassGovernanceRetention`. Compliance retention prevents deletion of the protected version during the retention period, including by the account root user. A legal hold has no expiration and stays in force until an authorized principal removes it. A version can have both controls, so confirm the mode, retain-until time and hold status for the exact data version. A successful marker creation can coexist with a denied permanent delete.

## 4. Collect evidence and decide what to restore

| Source | Collect | Interpret |
| --- | --- | --- |
| CloudTrail object data events | UTC time, account, region, session identity, bucket, key, version ID when present, request ID, and error details | Check that the write data-event selector covered the bucket and prefix during the incident. Review per-object results for `DeleteObjects` when available. |
| Bucket configuration and change history | Versioning state, lifecycle rules, Object Lock, approved changes and job history | Match rules and changes to the affected key and time. Current settings alone cannot establish past settings. |
| S3 server access logs | Request ID and operation where recorded, plus lifecycle actions such as `S3.CREATE.DELETEMARKER` and `S3.EXPIRE.OBJECT` | Requires logging coverage and delivery. Best-effort delivery means gaps are possible. |
| Version listing, prior inventory and restore checks | Exact key, `VersionId`, `IsLatest`, marker status, timestamps and application checkpoint | Listing shows what the caller can establish at collection time. Prior inventory helps establish what existed earlier. |

Filter `s3.amazonaws.com` for `DeleteObject` and `DeleteObjects` within the affected scope. Preserve raw records before grouping by session, bucket and time, and track distinct keys and version IDs where present. An S3 session identifies credentials and may need workload or sign-in evidence to identify who used them. Absence of an error field, a batch result, a missing log entry or a current 404 alone does not establish the effect on a particular data version. Preserve available request IDs and compare job runs, selector coverage, version listings and attributable changes. As of 2026-11-22, AWS lists S3 Lifecycle and S3 authentication failure events in CloudTrail as upcoming, with delivery scheduled for **2026-12-21** for trails already logging S3 data events. For historical investigations, check the sources available at the event time. After rollout, verify delivery and selector behavior in the account before relying on the new events.

For an owned, approved bucket, these AWS CLI v2 commands collect metadata. Set `BUCKET`, `KEY` and `VERSION_ID` from your case. The first command needs `s3:ListBucketVersions`. A prefix may match several keys, so retain all pages and then compare the exact `Key` in both arrays. Select a data version for the second command, which needs `s3:GetObjectVersion`. Check region, account and policy if you get 403. A 403 can also obscure a missing object when the caller lacks bucket listing permission.

```sh
aws s3api list-object-versions --bucket "$BUCKET" --prefix "$KEY" --output json
aws s3api head-object --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION_ID"
```

Preserve the relevant records and coordinate with incident and storage owners to stop any unauthorized job or restrict its exact permissions. Record the candidate version ID, checkpoint and restore approval. Read the candidate into an isolated destination under the recovery plan, taking archive storage and KMS access into account. Verify content against a trusted checksum or manifest and test that the application can read it with the expected permissions. HEAD only verifies metadata access. An ETag is not a general-purpose content checksum. If the candidate is gone or unreadable, check independently controlled backups or replicas and document the last verified recovery point. Use [Backup restore verification]({{ '/wiki/backup-restore-evidence/' | relative_url }}) for the service go or hold decision.

## 5. Authorized offline exercise

Download [s3-version-recovery.py]({{ '/assets/labs/s3-version-recovery.py' | relative_url }}){: download="s3-version-recovery.py" }. In your own workspace, use Python 3.8 or later. The standard-library program projects synthetic, newest-first histories for a single key in a versioning-enabled bucket. It uses no credentials, network, cloud calls or local input files.

```sh
python3 s3-version-recovery.py
```

| Compare these case labels | Expected evidence | Explain the difference |
| --- | --- | --- |
| `normal` and `marker-added` | Current HEAD changes 200 → 404, while `v2` and `v1` survive | Current visibility changed |
| `marker-added` and `older-version-removed` | Both show HEAD 404. Only the former lists `v1` | Current HEAD cannot show whether `v1` survived |
| `older-version-removed` and `protected-version-denied` | Their final inventories are identical | The denied request left state unchanged. Request evidence explains the difference. |
| `marker-removed`, `marker-only` and `empty` | Current HEAD is 200, 404 and 404, respectively. Exact HEAD of `m1` is 405 only in the marker-only case. | A marker can exist without a retained data version |

All seven cases should print and the program should return exit code 0. A mismatch message identifies the case and both values. If Python cannot open the file, check the download name and working directory. Use the same fixture inputs when comparing results. This model assumes authorized reads and bucket list permission. It does not compute IAM, retention decisions, lifecycle timing or bytes recovered. Python 3.12.14 ran all seven synthetic cases. AWS behavior and CLI examples were reviewed against documentation. No managed AWS environment was exercised.

## 6. Check your reasoning

1. **The current HEAD returns 404 and the list shows current marker `m1` and data version `v2`. Is recovery proven?** No. `v2` is a candidate. Verify authorized access, readable content, integrity and the application checkpoint.
2. **A removal alert aligns with a lifecycle rule, and no customer delete event is present. What can you conclude?** The rule is a plausible explanation. Compare its filters and timing with lifecycle evidence, the version inventory and logging coverage.
3. **A team removes the latest marker. Does the key always become readable?** No. The next surviving entry may be a data version or another marker, and no entry may remain. Access and readability still need checking.

**Completion check.** Explain the difference between a marker and a data version, distinguish the marker-only and empty cases that both return 404, and write a short incident note covering observed state, likely cause, what is still unknown and the next recovery check.

## Official references

Reviewed 2026-11-22. The S3 documentation covers general purpose bucket behavior at review time. The CloudTrail documentation also describes the scheduled December 2026 delivery change.

- [AWS S3 API · DeleteObject and versioning states](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html) · [Delete markers and response codes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html)
- [AWS S3 API · ListObjectVersions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html) · [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html) · [AWS CLI v2 pagination](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-object-versions.html)
- [AWS S3 · Object Lock retention and legal holds](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) · [Lifecycle expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)
- [AWS S3 · CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html) · [CloudTrail · Announcement and delivery date](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [AWS S3 · Access log format and operations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html) · [Best-effort log delivery](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
