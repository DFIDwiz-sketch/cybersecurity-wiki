---
title: "Amazon S3 Presigned URLs · Trace Issuance, Use, and Expiry"
description: "Connect application issuance records, CloudTrail S3 data events, and server access logs to investigate a presigned object read."
category: cloud
tags: [AWS, Amazon S3, Presigned URL, CloudTrail, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/s3-presigned-url-evidence/
---

A customer says they downloaded a private report. A CloudTrail record names your application’s IAM role session. How can both be true? This chapter follows a presigned GET for a general purpose S3 bucket and shows which record answers each part of the question. The worked example and downloadable records are fictional.

## 1. What the link grants

An application can use its AWS credentials to sign a request for a specific object and operation, such as reading a report with `GetObject`. A **presigned URL** carries that signature and other authentication parameters in its query string. With Signature Version 4 (SigV4), the signature binds request details such as the method and object path. The **signer** is the AWS principal or role session whose credentials the application used. The **holder** is whoever presents the URL to S3. The holder can be a browser, a service, or a person acting through either.

This arrangement lets an application authorize a download while keeping the bucket private and keeping AWS credentials with the signer. Treat the full URL as a **bearer credential**. A holder can use it while the request meets S3’s signature, expiry, and authorization checks. S3 presigned URLs can be used more than once in that period. An application’s decision to issue one link to one customer provides the intended recipient, while S3 evaluates the signed request it actually receives.

<figure>
  <img src="{{ '/assets/diagrams/s3-presigned-url-evidence.svg' | relative_url }}" width="560" height="362" alt="The app authorizes a recipient and records issuance. S3 checks a holder’s request. CloudTrail and S3 access logs can be paired by request ID. Application issuance is correlated separately by signer, object, operation, and time.">
  <figcaption>Join the two S3 observations by request ID. Trace the app’s issuance separately using the signing session, object, operation, and timing.</figcaption>
</figure>

## 2. From issuance to response

1. The app checks that the requester can receive the report, then signs the object GET using its current role session. An SDK can sign locally in the app, so the arrival of a new URL does not create an S3 issuance event. An STS role-assumption event can help establish when the signing session started.
2. The holder sends the signed request to S3. S3 checks the signature and expiration when the request begins, then evaluates permissions and applicable policy conditions. A signature that is still within its nominal lifetime can fail authorization.
3. With collection enabled and in scope, CloudTrail can record the object request and the signing session. S3 server access logging can supply a separate HTTP status and response byte count. The application must record issuance itself if the team needs that link in the investigation.

| Limit | Interpretation | Evidence to look for |
| --- | --- | --- |
| URL lifetime | `X-Amz-Expires` is a duration in seconds from the signing time. | Sanitized app signing time and configured duration. |
| Signing credentials | Temporary credentials can expire before the URL’s nominal expiry. Credential revocation, deletion, or deactivation can also cut short use. | Signing-session lifetime or credential lifecycle records. |
| Request policy | A bucket policy can deny a SigV4 request that exceeds a signature-age threshold. `s3:signatureAge` is measured in milliseconds. | The policy in force at request time and whether its conditions covered that operation and object. |

**Fictional normal path.** At 10:00 UTC an app signs a private report GET with a 300-second lifetime. The link’s nominal expiry is 10:05 UTC, and the role session expires at 10:03 UTC. At 10:02 UTC the matching access log shows HTTP `200` and `8192` bytes sent. A request beginning after 10:03 UTC with that session’s URL would no longer be authorized on those credentials, even though the nominal URL timer has time left. S3 can continue streaming a download that began before expiry. A reconnect or fresh GET after expiry is a new request. A later `403` alone leaves the exact reason open, including a policy deny or an expired session.

## 3. Collect, detect, and respond

A link exposed in a support ticket or retained in a log can be used by another holder while valid. This can leave the same signer in CloudTrail as a normal download. Monitor for new or unusual object keys, bursts of successful signed reads, repeated reads after an expected delivery window, and mismatches with the app’s issuance history. Compare these patterns with expected retries, range requests, and application releases before escalating.

| Source | Collect and compare | What it supports |
| --- | --- | --- |
| Application audit | Issuance ID, UTC time, intended recipient reference, signing-session ARN, target account, bucket, key, operation, and known URL and credential expiry. | Who the app intended to authorize and which issuance records could explain the request. |
| CloudTrail S3 data event | Enable read data events for the relevant bucket and prefixes before the incident. Look for `eventSource=s3.amazonaws.com`, `eventName=GetObject`, `additionalEventData.AuthenticationMethod=QueryString`, and presence of `requestParameters.X-Amz-Expires`. Retain `requestID`, `eventTime`, `userIdentity.arn`, and any error code. | A likely SigV4 presigned GET and its signing session. Map to the underlying role with `userIdentity.sessionContext.sessionIssuer.arn` when available. |
| S3 server access log | Enable bucket server access logging beforehand. Pair its `Request ID` with CloudTrail `requestID` and corroborate the bucket, key, operation, account context, and time. Check `Authentication Type`, HTTP status, and `Bytes Sent`. | The HTTP outcome and logged response bytes for that request. Access log delivery is best effort and may be delayed. |

CloudTrail `eventID` identifies the CloudTrail event. S3’s request ID is the cross-log join field. `QueryString` alone can represent other query-authenticated requests. For an independent check in a protected server access log, look for `Authentication Type=QueryString` and the presence of the expiry parameter name in `Request-URI`. Project only the fields you need and keep complete URLs, signatures, and security tokens out of shared cases and alerts.

Match candidate issuance records by signing session, target account, bucket, key, operation, and the relevant time window. If two records overlap on those fields, list both and mark the attribution unresolved. Source address and User-Agent can support a timeline. A shared proxy, forwarding, or a shared device can break the link between those fields and a human identity.

For a suspected leak, preserve the sanitized evidence and identify the affected object scope and remaining lifetime. Coordinate with the signer and bucket owners to restrict further reads, account for legitimate downloads, and verify the effect of any policy change. Scope a deny to the affected objects or principals where practical. Review role permissions and use short issuance windows suited to the download. Consider signature age and source-network conditions where the client flow supports them. After containment, review matched successful GETs and separate observed bytes from unresolved requests.

## 4. Offline evidence lab

Use the following files in a directory you control with Python 3.9 or later. The script reads fictional JSON, uses no AWS credentials, and sends no requests. The input models selected CloudTrail fields and **normalized** app and access records. It is a worksheet for this chapter, so adapt collection and normalization separately for production.

- [Download the evidence review script]({{ '/assets/labs/s3-presigned-url-evidence/review.py' | relative_url }})
- [Download the fictional evidence and expected outcomes]({{ '/assets/labs/s3-presigned-url-evidence/cases.json' | relative_url }})

```sh
python3 review.py cases.json
```

| Check | Expected observation |
| --- | --- |
| Successful GET and one issuance | One time-valid issuance candidate, HTTP 200, 8192 object bytes logged. |
| Denied GET after session expiry | No time-valid issuance candidate, HTTP 403, and no object payload inferred. The time comparison leaves the denial cause open. |
| Overlapping issuances and partial response | Two issuance candidates, HTTP 206, 1024 object bytes logged. |
| Missing or wrong-scope access row | Response bytes unknown, even when CloudTrail reports no error. |
| Query-only marker, header auth, and metadata read | Query-only remains uncertain. Header auth and metadata are outside the lab’s presigned GET classification. |

All eight checks should pass. As a negative control, copy the JSON, change the first case’s access record `request_id`, and run against that copy. The expected match should fail and the script should exit with status 1. If the unmodified inputs fail, check that you have the matching downloads, valid JSON, and UTC timestamps with a time zone. Python and the fictional fixture were run in a cloud execution environment. AWS log and policy behavior was reviewed against official documentation.

## 5. Interpret the limits

A confirmed presigned GET can occur against a private bucket. HTTP `206` tells you the response was partial. `Bytes Sent` measures bytes reported by the server and excludes HTTP protocol overhead. For a denied request it may describe an error response, so do not count those bytes as object content. Even a successful `200` with a byte count leaves storage, onward sharing, and the holder’s identity unestablished. Absence of a record calls for review of selectors, retention, and delivery before drawing a conclusion.

<details>
<summary>Check your understanding and completion criteria</summary>

1. **A URL was signed at 10:00 UTC for 300 seconds and the signer’s session expires at 10:03 UTC. Can a new GET be authorized with this URL at 10:04 UTC?** No. The signing credentials have expired.
2. **CloudTrail shows the release service’s role session and two app issuance records fit. Who downloaded the file?** The evidence identifies the signing session and two candidate issuances. The actual holder needs independent client or application evidence.
3. **A matching access row reports `206` and `1024` bytes. What can you write in the case?** S3 logged a partial response and sent 1024 response bytes for the matched GET. The full object’s receipt is unestablished.

You have completed the chapter when you can explain the two expiry clocks, match the S3 records by request ID, and give separate conclusions for the signing session, issuance candidates, and observed object bytes.

</details>

## Official references

Reviewed 2026-11-27. Scope is AWS S3 SigV4 presigned GETs and the documented logging formats for general purpose buckets as of that review.

- AWS S3 User Guide. [Presigned URL behavior, expiry, and policy conditions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html).
- AWS Prescriptive Guidance. [Identify presigned requests in CloudTrail and S3 logs](https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/identifying-requests.html) and [logging considerations for presigned interactions](https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/logging-interactions.html).
- AWS S3 User Guide. [CloudTrail logging for S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html), [server access logging and delivery](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html), and [access log fields](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html).

## Related reading

- [S3 object reads and response bytes]({{ '/wiki/s3-object-read-evidence/' | relative_url }})
- [S3 Block Public Access and private access evidence]({{ '/wiki/s3-block-public-access-evidence/' | relative_url }})
- [AWS IAM roles and session evidence]({{ '/wiki/aws-iam-role-evidence/' | relative_url }})
