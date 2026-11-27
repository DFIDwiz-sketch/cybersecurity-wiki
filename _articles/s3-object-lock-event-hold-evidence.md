---
title: "S3 Object Lock Event Holds · Verify a Version’s Retention"
description: "Reconstruct an S3 version's retention across an event hold, its release and the independent legal hold."
category: cloud
tags: [AWS, Amazon S3, Object Lock, CloudTrail, Blue Team, DFIR]
level: Beginner
updated: "2026-11-28"
translation_url: /ko/wiki/s3-object-lock-event-hold-evidence/
---

An audit closes and the archive workflow releases an S3 event hold. Can the object version be removed now? Read the exact version’s retention metadata, release record and legal hold. A release typically starts a further retention period.

## 1. Scope the protection to one version

**S3 Object Lock** provides write-once-read-many (WORM) protection for versions in an enabled, versioned S3 bucket. A *key* names the object. A *version ID* distinguishes one stored revision under that key. Investigate by bucket, key and version ID. Each revision can have different protection.

**Fixed retention** stores a retain-until date for the version, subject to authorized changes. **Variable retention** protects the version while its *event hold* is on and then continues retention for a configured duration after release. A separate **legal hold** has no scheduled end and remains active until an authorized removal. AWS launched variable retention in September 2026 and announced availability in the AWS GovCloud (US) Regions in October. Older guides may only describe fixed retention and legal holds.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/s3-object-lock-event-hold-evidence.svg' | relative_url }}" width="360" height="413" alt="An active event hold has a moving retain-until date. Release fixes the later of release plus duration and the existing date. Check the legal hold independently." />
  <figcaption>An event-hold release defines an end date for retention. The legal hold has a separate state.</figcaption>
</figure>

| Control | What to inspect | What the evidence supports |
| --- | --- | --- |
| Bucket default | Object Lock configuration, mode, default period or event-hold setting | The default applied to eligible new uploads at the time it was configured. Explicit per-version retention can override it. |
| Fixed retention | Version mode and `RetainUntilDate` | Time-based WORM protection up to the applicable date. |
| Variable retention | Version mode, `EventHold`, `EventHoldDuration`, and `RetainUntilDate` | While the hold is on, the returned date is a moving estimate for release now, subject to the existing date or minimum. Release fixes a date. |
| Legal hold | Version-specific legal-hold `Status` | An independent hold with no expiry. `OFF` describes this control only. |
| Current key state | Version listing and delete markers | A marker can hide a protected version from an ordinary lookup. Check the version separately. |

`GOVERNANCE` and `COMPLIANCE` are retention modes, independent of fixed versus variable timing. Governance allows exceptional changes only under specifically authorized conditions. Compliance prevents shortening active retention or deleting the protected version during it, including by the account root user. For incident triage retain the mode and legal hold. An exception applicable to governance cannot clear an independent legal hold.

## 2. Compute the timeline before interpreting a change

The fictional audit version `v-a` has a 30-day event hold in compliance mode. At **2026-11-10 00:00 UTC** a fresh read shows December 10 as the retain-until date. On November 12 a fresh read shows December 12. Both readings can be correct. The date advances while the event hold remains active. If a shorter duration would produce an earlier date than the service has already established, the date stays at that later value until the shorter window catches up.

Suppose an authorized workflow releases the event hold at **2026-11-15 00:00 UTC**, keeping the 30-day duration. With the prior dates above and no later floor, the fixed date is **December 15 00:00 UTC**. With an explicit minimum of **January 1, 2027 00:00 UTC**, that later date applies. After the recorded deadline, an independent legal hold can still preserve the version. A business ticket closing is evidence that release may be due. Correlate the successful S3 operation and a version-specific read to learn when it actually happened.

If there is S3 Replication, validate the destination separately. AWS documents that the destination computes its final date when the release replicates, using that destination’s replication time and the configured duration. Preserve the source and destination identifiers, release timestamps and observations separately.

## 3. Collect three kinds of evidence

### Current version state

Use an authorized read-only role and a supported AWS CLI with event-hold fields. Set `BUCKET`, `KEY`, and `VERSION` to the approved general purpose bucket, exact key and exact data version. Capture the UTC observation time alongside the raw output. The calls require `s3:GetBucketObjectLockConfiguration`, `s3:GetObjectRetention` and `s3:GetObjectLegalHold` respectively. Independently verify account and bucket scope before collecting.

```bash
aws s3api get-object-lock-configuration --bucket "$BUCKET"
aws s3api get-object-retention --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION"
aws s3api get-object-legal-hold --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION"
```

On a denied or incomplete response, confirm the version, AWS account or role, feature support and permissions. Keep missing evidence marked unknown. These commands were checked against AWS documentation. The offline exercise below uses no AWS environment.

### Change history

Configure CloudTrail S3 object data events for the bucket or relevant object ARN scope before the observation period. AWS records the API call `PutObjectRetention` as the data event `PutObjectLockRetention`. For a recorded change, inspect `additionalEventData.objectRetentionInfo` when present for the resulting mode, date, hold status and duration. Record event time, principal, request or event ID, outcome, and version when available. A failed operation or a record without the version needs corroboration. `PutBucketObjectLockConfiguration` is the documented bucket-level management event name. CloudTrail Event History provides recent management events. It excludes S3 object data events, which require their own logging and retrieval path.

### Batch visibility

Enable Object Lock fields in S3 Inventory and include all versions if the investigation needs noncurrent ones. Inventory can lag by up to 48 hours and its moving retain-until dates represent the report generation time. AWS documents `s3:ObjectRetention:Put` notifications for explicit retention calls. A bucket default applied on upload, or retention set in creation requests, can lack that notification. Use fresh version metadata to verify state and CloudTrail or the creation record to explain its origin.

## 4. Detect drift and respond without destroying evidence

- Compare successful releases with approved business-event records for the exact version. Investigate an unexpected `ON` to `OFF` transition, a duration outside the approved bounds, or a default change near the creation time of affected versions. Check role sessions and batch jobs before assigning intent. Scope alerting to resources covered by selectors and validate that collection captured the expected event name.
- Separate stale data from an actual configuration change. Compare source type and UTC observation time, then fetch the current version metadata. Preserve the original observations, the source event and the fresh response. A computed date drifting forward during an active event hold is expected.
- Protect recoverability as its own question. A version can be protected and still hidden by a delete marker, in a storage class requiring restoration, or inaccessible if its encryption key is unavailable. For evidence handling, record the version and authorization and use an approved copy or integrity check. A past retain-until date alone cannot authorize deletion.

## 5. Offline lab · Review ten fictional observations

Use Python 3 in a directory you own or have approval to use. Download <a href="{{ '/assets/labs/s3-object-lock-event-hold-evidence/object-lock-cases.csv' | relative_url }}" download="object-lock-cases.csv">object-lock-cases.csv</a>, save the code below as `review_object_lock.py` beside it, and run `python3 review_object_lock.py`. The CSV is a normalized teaching fixture with one independent case per row. `prior_until` is a previously established bound supplied by the fixture and `minimum_until` is an explicit floor. The arithmetic model uses UTC and whole days. For real diagnostics compare service values at their observation or release times and account for precision. The program reads a local file and performs no AWS calls.

```python
import csv
from datetime import datetime, timedelta
from pathlib import Path
import sys


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def review(row):
    observed = utc(row["observed_at"])
    reported = utc(row["reported_until"])
    released = utc(row["released_at"])
    hold = row["event_hold"]
    legal = row["legal_hold"]
    if row["mode"] not in {"GOVERNANCE", "COMPLIANCE"}:
        raise ValueError("Fixture must specify a retention mode")
    if hold not in {"ON", "OFF"} or legal not in {"ON", "OFF", "UNKNOWN"}:
        raise ValueError("Unrecognized hold status")
    if not observed or (released and (released > observed or hold == "ON")):
        raise ValueError("Inconsistent observation and release times")

    if hold == "ON" or released:
        day_count = int(row["duration_days"])
        if day_count < 1:
            raise ValueError("Expected a positive duration in days")
        computed = (released or observed) + timedelta(days=day_count)
        floors = [utc(row["minimum_until"]), utc(row["prior_until"])]
        effective = max([computed] + [value for value in floors if value])
    else:
        effective = reported

    if reported is None or legal == "UNKNOWN":
        status = "needs-evidence"
    elif effective != reported:
        status = "date-disagrees"
    elif legal == "ON":
        status = "legal-hold-active"
    elif hold == "ON":
        status = "event-hold-active"
    elif effective > observed:
        status = "retention-active"
    else:
        status = "no-lock-in-model"
    return effective, status


def main(path):
    discrepancies = 0
    with path.open(encoding="utf-8", newline="") as fixture:
        for row in csv.DictReader(fixture):
            until, status = review(row)
            correct = (until, status) == (utc(row["expected_until"]), row["expected_status"])
            discrepancies += int(not correct)
            mark = "OK" if correct else "MISMATCH"
            print(f"{mark} {row['case_id']}: {until} {status}")
    return int(discrepancies > 0)


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("object-lock-cases.csv")
    raise SystemExit(main(path))
```

| Cases | Expected outcome |
| --- | --- |
| `active-first`, `active-later`, `shorter-duration` | Two moving dates and one date kept at an earlier established bound. The event hold stays active in all three. |
| `released`, `released-with-floor`, `fixed-retention` | Time-based protection is active. The calculated dates are December 15, January 1, and the supplied December 1 respectively. |
| `expired-legal-hold`, `expired-no-hold` | An independent legal hold still protects the first case. The second has no remaining lock in the model. |
| `missing-legal-hold`, `stale-observation` | Collect additional evidence for the first. Investigate the date discrepancy for the second. |

Expect ten `OK` results. Use the directory containing the CSV or pass its path. In a copy, change the `released-with-floor` expected date to December 15, 2026, using the same UTC format. Running `python3 review_object_lock.py altered.csv` should report a mismatch and exit with status 1. The exercise tests the date model and evidence labels. It leaves IAM, KMS, bucket state, collection and AWS service behavior to the cited documentation and authorized environment verification.

## 6. Check your understanding

1. **Why can today’s date differ from yesterday’s Inventory value?** The event hold can still be on, so the retain-until date is computed for each observation time. Compare the same version.
2. **Does an event release end protection immediately?** It fixes a future retention date in the example. An independent legal hold can continue beyond that date.
3. **What does a change in the bucket default prove about an older object?** It proves a configuration change at bucket level. Retrieve that older version’s metadata and history to determine its protection.

Complete the chapter when you can reconstruct the release date calculation, distinguish an unknown hold from `OFF`, and identify the records needed to corroborate one version’s state.

## Official references

Reviewed **2026-11-28**. Scope covers October and September 2026 AWS releases, supported S3 general purpose buckets and the current AWS manuals.

- [AWS S3 · Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS S3 · Inventory, replication and retention monitoring](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [AWS S3 · CloudTrail event names and collection](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [AWS Storage Blog · Variable retention with event holds](https://aws.amazon.com/blogs/storage/flexibly-control-amazon-s3-object-lock-retention-based-on-real-business-events/)
- [AWS CLI · get-object-retention](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-retention.html)
- [AWS CLI · get-object-legal-hold](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-legal-hold.html)
- [AWS CLI · get-object-lock-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-lock-configuration.html)
- [AWS · September 2026 launch](https://aws.amazon.com/about-aws/whats-new/2026/09/amazon-s3-object-lock-variable-retention/)
- [AWS · October 2026 GovCloud release](https://aws.amazon.com/about-aws/whats-new/2026/10/s3-object-lock-variable-retention-event-holds-aws-govcloud/)

[Previous · S3 version recovery]({{ '/wiki/s3-version-recovery-evidence/' | relative_url }}) · [Next · Backup and restore evidence]({{ '/wiki/backup-restore-evidence/' | relative_url }}) · [CloudTrail log integrity]({{ '/wiki/cloudtrail-log-integrity/' | relative_url }})
