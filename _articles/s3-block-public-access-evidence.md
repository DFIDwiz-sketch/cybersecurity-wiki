---
title: "Amazon S3 Block Public Access · From Settings to Read Evidence"
description: "Read effective S3 public-access controls, distinguish ACL and policy behavior, and verify evidence from fictional access records."
category: cloud
tags: [AWS, Amazon S3, Block Public Access, CloudTrail, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/s3-block-public-access-evidence/
---

A scanner flags a bucket policy as public. The bucket owner says the account blocks public access. An S3 access log shows a successful request that used a query-string signature. All three observations can be true. This chapter follows a general purpose bucket and separates what was configured, what S3 would restrict, and what was actually returned.

## 1. Learn the settings and their scope

An **ACL** is a grant attached to a bucket or object. A **bucket policy** is a resource-based policy attached to the bucket. A policy on an **access point** can control requests made through that access point. **Block Public Access** (BPA) adds restrictions to those authorization paths. It grants no permissions. A setting that does not block a request leaves other checks in place, including identity and resource policies where applicable.

| Setting | What it changes | Existing permissions |
| --- | --- | --- |
| `BlockPublicAcls` | Rejects attempts to set public ACLs, including applicable uploads carrying a public ACL | An existing public ACL is not neutralized by this setting alone |
| `IgnorePublicAcls` | Excludes public ACL grants from permission evaluation | ACLs are not deleted. Other settings can still reject an ACL write |
| `BlockPublicPolicy` | Rejects applicable updates that would install a policy S3 classifies as public | A stored public policy is not neutralized by this setting alone |
| `RestrictPublicBuckets` | Restricts access when the applicable bucket or access point has a public policy | For a direct bucket, access is limited to authorized principals in the owner account and AWS service principals, subject to other checks. A named cross-account grant can also be blocked |

S3 evaluates the most restrictive combination of applicable settings. On a **direct bucket route**, compare the bucket with the **effective account** settings. If the route uses an access point, include its configuration and the relevant owner accounts. An AWS Organizations S3 policy can override the member account’s local configuration as a group of four settings. Use the effective account result, not an extra per-flag union with a superseded local setting. Scope and time matter. Account settings apply globally, and AWS notes changes can take time to reach all Regions.

**Object Ownership** supplies another control. With `Bucket owner enforced`, ACLs are disabled for authorization and policy determines access. AWS changed the defaults for new buckets across creation methods in 2023 to enable BPA and disable ACLs. Existing buckets were unaffected by that rollout. Check actual settings at the relevant time for both old and new buckets.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/s3-block-public-access-evidence-en.svg' | relative_url }}" alt="Bucket and effective account settings feed the applicable restrictions. Investigate configuration changes, authorization decisions and object response evidence as separate steps." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Follow settings to a specific request. Evidence of a setting and evidence of returned bytes answer different questions.</figcaption>
</figure>

## 2. Follow a normal private read

In this fictional example, the account has all four settings enabled and the bucket uses `Bucket owner enforced`. A workload in the owner account makes a signed `GetObject` for `reports/summary.csv`. Assume its policies permit the request and no applicable deny, endpoint policy, or key policy blocks it. The workload can receive the object while unauthenticated access remains restricted.

A colleague receives a limited presigned URL as part of an approved workflow. An S3 server access log for that request can show `Authentication Type=QueryString`. The URL carries authentication from the signing principal and is a bearer credential within its validity. The recipient need not have an AWS login to use it. Treat leakage as a separate access risk and redact the signature and query string in shared evidence. It does not establish a public bucket or an unauthenticated S3 read.

## 3. Find the restriction that explains the incident

Suppose a fictional bucket already has a policy classified as public. The policy includes a statement for a fixed partner account. With only `BlockPublicPolicy` enabled, the existing policy remains in place. When `RestrictPublicBuckets` applies, that separate partner grant can also stop working because the **policy as a whole** is classified as public. Check the applied restriction and affected routes before changing a security control. Preserve the policy and the failing request evidence, and reconcile the trust boundary with the approved design.

S3 uses its own public-policy rules. A broad principal with qualifying fixed conditions can be treated differently from an unrestricted statement. Use S3’s policy status and inspect the scope. A bucket policy status alone cannot show the effect of object ACLs, access-point policy or alternate delivery paths. IAM Access Analyzer for S3 reports potential access outside its trust zone, including named external accounts. Validate the analyzer’s scope, timeliness and access-point coverage. A finding is configuration evidence.

An unauthorized setting change can remove a restriction that previously hid a broad grant. A migration or emergency fix might leave similar audit records. Conversely, an attacker’s read attempt may be denied. Establish the actor, approval and effect separately. A CDN might serve content to a viewer through a private, authenticated S3 origin. Do not infer the bucket’s anonymous access from the viewer’s response.

## 4. Collect, detect and respond

| Source | Evidence to retain |
| --- | --- |
| Effective configuration | Bucket owner, Region, account and bucket BPA, Object Ownership, policies, relevant ACLs and route. Check Organizations policy and access points when applicable. Separate absent configuration from access denied or an unavailable API |
| CloudTrail management events | Successful and failed `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock` and ACL or ownership changes. Collect account and organization change evidence where enabled and authorized |
| S3 request evidence | S3 data events, if selected for the affected objects, and server access logs if configured. Preserve operation, object key or version, time, request ID, requester and authentication type, status and bytes sent. Data events are outside default CloudTrail Event history, and server log delivery is best effort |

For a direct general purpose bucket, the following are read-only AWS CLI v2 examples. Use a vetted profile in the authorized account. Set `BUCKET` and `OWNER` to the approved bucket and its 12-digit owner account ID, and `REGION` to the bucket Region. The permissions are `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus` and `s3:GetBucketOwnershipControls` respectively. The account command reads the effective account-level result.

```bash
aws s3control get-public-access-block --account-id "$OWNER" --region "$REGION"
aws s3api get-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
aws s3api get-bucket-policy-status --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
aws s3api get-bucket-ownership-controls --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
```

For detection, look for succeeded configuration changes outside normal change windows, then compare external-access findings or authenticated and unauthenticated traffic. Match by time, bucket, endpoint and request ID when available. In the S3 server access log format, an authentication type of `-` can indicate an unauthenticated request. An explicit `REST.GET.OBJECT` with `200` or `206` and positive bytes sent supports a body response for that specific request. `206` is partial content. A 403 or a successful HEAD supplies different evidence. Sender-side bytes do not establish receipt of every byte or the reader’s identity.

Preserve the before/after policy and logging coverage. If suspected exposure is active, apply the approved least-privilege containment, check the intended private integration and authorized validation from the relevant route, and track possible earlier reads separately. Do not reopen a public grant to confirm it. Review any published content through its delivery path as well as the bucket.

## 5. Authorized offline exercise

Download <a href="{{ '/assets/labs/s3-block-public-access-evidence.py' | relative_url }}" download>the Python checker</a> and <a href="{{ '/assets/labs/s3-block-public-access-cases.json' | relative_url }}" download>the fictional cases</a> into one directory. Use Python 3 in an environment you own or are authorized to use. The checker reads local files and never calls AWS. Its fixtures supply complete scope settings and, when needed, a public-policy classification established separately. The checker models selected restrictions, not IAM policy evaluation.

```bash
python3 s3-block-public-access-evidence.py
```

| What to compare | Expected result |
| --- | --- |
| Public ACL or policy write and an existing grant | Write rejection and authorization-time treatment have different controls |
| Bucket flags off with an effective account restriction on | The restriction still applies |
| Disabled ACLs and a named partner under a public policy | Ownership disables the ACL path. A policy-wide restriction can block the partner |
| Unauthenticated, presigned, denied and metadata-only observations | Keep the authentication mechanism and body evidence separate |

Expect `12/12 evidence cases matched.` For a negative control, set case C’s effective-account `BlockPublicPolicy` value to `false` without changing its expected result. The checker should flag the difference and return exit code 1. If the untouched file fails, confirm both files are from the same edition and look at the failed case ID. The lab treats only its defined routes and normalized records. No AWS account, live S3 access or CLI authorization was exercised.

## 6. Check your understanding

1. **Can a false bucket flag establish effective public access?** Check the effective account, route, policy, ownership and other authorization before drawing that conclusion.
2. **Is a successful presigned read anonymous in S3 logs?** It is a query-signed request. Keep that separate from an unauthenticated request.
3. **May a named partner be denied when a separate policy statement is public?** Yes. If `RestrictPublicBuckets` applies to the public policy, a fixed external-account statement does not cancel that restriction.

**Completion criterion.** Reproduce the twelve controls and the negative case. Explain the difference between a write-time restriction, a request-time restriction, and evidence of actual bytes returned. Continue with [S3 object read evidence]({{ '/wiki/s3-object-read-evidence/' | relative_url }}) for object-level correlation.

## Official references

Reviewed 2026-11-26. The 2023 default change is historical context. Product behavior and AWS CLI v2 commands were checked against the current documentation at review.

- [S3 Block Public Access and public-policy classification](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) and [Amazon S3 policies in AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html)
- [Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html) and [AWS notice for the April 2023 defaults](https://aws.amazon.com/about-aws/whats-new/2022/12/amazon-s3-automatically-enable-block-public-access-disable-access-control-lists-buckets-april-2023/)
- [Effective account configuration in AWS CLI v2](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-public-access-block.html), [bucket policy status](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html) and [IAM Access Analyzer for S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html)
- [S3 CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html), [server access logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html) and [S3 log fields](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html)

## Investigate the AWS Organizations policy path

[AWS SCP evaluation evidence]({{ '/wiki/aws-scp-evaluation-evidence/' | relative_url }}) follows the caller's account through the organization and explains how to confirm an SCP denial.
