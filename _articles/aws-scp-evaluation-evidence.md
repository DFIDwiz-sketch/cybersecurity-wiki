---
title: "AWS Service Control Policies · Trace an Access Denial"
description: "Trace the caller account through root, OU and account policies, and distinguish an explicit SCP denial from a missing allow."
category: cloud
tags: [AWS, IAM, AWS Organizations, CloudTrail, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/aws-scp-evaluation-evidence/
---

A deployment role has an IAM policy that allows an API operation. The same operation works in one AWS account but fails in another. Before adding a permission to the role, find the account the **calling session** belongs to and reconstruct its AWS Organizations policy path at the time of the request.

## 1. What an SCP controls

AWS Organizations arranges accounts under an organization **root** and optional nested **organizational units** (OUs). The root here is a container and is distinct from an account's root user. A **service control policy** (SCP) puts an upper bound on permissions available to in-scope principals in member accounts. It supplies no authorization grant by itself. The root user of a member account is generally in scope, subject to documented exceptions. The management account and permissions attached to service-linked roles are outside this guardrail. An ordinary workload role assumed by a service should not be presumed to be a service-linked role.

| Layer | What it answers | What to collect |
| --- | --- | --- |
| Role and session | Which principal sent the request, and which identity or session restrictions apply? | Caller account, assumed role and session, relevant policies and permissions boundary |
| SCP | Does the caller's organization path permit this action in this request context? | Root and direct OU path, directly attached policies at each level, matched conditions |
| Resource-side controls | Can this resource be accessed under its policies and service restrictions? | Resource policy and, where supported, resource control policy (RCP) and service-specific controls |
| Service result | What happened to this particular call? | Response status, error context, request ID and available audit records |

An SCP is principally about **the caller's member-account path**. If a principal from an external account calls a resource, the resource owner's SCP does not govern that external principal. The caller's own controls and applicable resource-side controls still matter. An RCP can constrain access to supported resources in a member account, including requests from external principals. For an STS session, distinguish the original caller that assumed a role from the role session making the subsequent request. Evaluate each call with its own principal and context.

## 2. Follow the policy path

For an in-scope request with SCPs enabled, AWS looks from the root through every OU on the direct path to the account. At **each level**, at least one directly attached SCP must have a matching `Allow`. Policies at the same level can supply alternative allows. A matching explicit `Deny` anywhere on the path overrides matching allows. A condition that does not match contributes neither an allow nor a deny for that statement. The managed `FullAWSAccess` SCP can satisfy the allow check at its attachment level, while leaving separate denies effective. A sibling OU is outside the path.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/aws-scp-evaluation-evidence-en.svg' | relative_url }}" alt="For a member-account role, follow the Organizations root, every parent OU and the account. Every level needs a matching allow, and any matching explicit deny stops the request at the SCP layer. Passing that layer still leaves other authorization checks." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Walk the calling account's organization path before evaluating other authorization controls.</figcaption>
</figure>

## 3. Work through a normal call and two failures

In a fictional organization, role session `InventoryJob` in a member account calls `ec2:DescribeInstances` in `eu-west-1`. Root and account have matching allows. At the Production OU one attached policy allows this action and another covers unrelated services. No matching SCP deny is present. If the identity grant and remaining controls permit the operation, the service can return the inventory.

At 10:05 UTC an approved rollout adds a matching explicit deny at the root for the request's region. Production still has an allow, yet AWS can refuse the call. For a separate scenario, assume the root deny was never attached and the account was moved to an OU whose policies contain no matching allow. The call can still fail, this time because the path lost an allow. No policy text on that child account had to change. For either case, correlate the attempted request with the organization state and the successful configuration-change event.

A mistaken administrative change or an unauthorized policy edit may open or restrict a large branch of the organization. A deployment delay, OU move or use of a different caller session can also account for different outcomes. Treat the message as evidence about the specific request. Where AWS includes SCP context, distinguish an explicit deny from a missing allow. Some calls provide only a generic denial. An enhanced message can describe one contributing denial, so removing that cause may expose another. The failure alone does not establish actor intent or a compromise.

## 4. Collect, detect and respond

1. **Identify one request.** Save UTC time, actual caller account and role session, API action, target resource where applicable, Region, error text and request ID. Match the audit record using those fields. Availability and fields vary by service and event type. CloudTrail Event history covers recent management events per account and Region for 90 days. Use a preconfigured trail or event data store for relevant older records or selected data events. Record the coverage before interpreting a missing event.
2. **Collect the path and policy content.** With AWS CLI and an authorized profile, set `ACCOUNT_OR_OU_ID`, `ROOT_OU_OR_ACCOUNT_ID` and `POLICY_ID` to the relevant identifiers before each read-only call. Use management or a delegated administrator account with permissions for these APIs. Start with the caller's account and repeat the parent lookup for each OU until the root. For every level, list the direct attachments and read each SCP. Keep pagination enabled. `DescribeEffectivePolicy` is for management policies and does not return a combined SCP.

~~~bash
aws organizations list-parents --child-id "$ACCOUNT_OR_OU_ID"
aws organizations list-policies-for-target \
  --target-id "$ROOT_OU_OR_ACCOUNT_ID" --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id "$POLICY_ID"
~~~

3. **Reconstruct the incident-time state.** These commands read current state. For change history, inspect CloudTrail management records for `organizations.amazonaws.com` in `us-east-1` in the commercial AWS partition. Look for successful `AttachPolicy`, `DetachPolicy`, `UpdatePolicy` and `MoveAccount` relevant to the path. Compare target IDs, caller, parameters and the approved change. Use retained snapshots or reviewed policy versions for historical content. A management record can document a configuration change without containing a complete point-in-time evaluation.
4. **Test the diagnosis narrowly.** Review actual action, resource and condition context. Check missing allows and explicit denies separately, and record which layers still need evidence. Use an approved harmless request in a representative test account before changing production. Monitor unexpected policy changes or a jump in similar denials by account path and service. Keep the original policy snapshots and validate the exact same caller action after an approved correction.

## 5. Authorized offline exercise

Download the <a href="{{ '/assets/labs/aws-scp-evaluation-evidence.py' | relative_url }}" download>Python checker</a> and <a href="{{ '/assets/labs/aws-scp-evaluation-evidence.json' | relative_url }}" download>fictional cases</a> into one directory. Run with Python 3 in your own or approved environment. In this fixture each statement's `matches` value has already been assigned for one synthetic request. The checker models only SCP path evidence. It does not parse AWS IAM policy syntax, load credentials, or contact AWS.

~~~bash
python3 aws-scp-evaluation-evidence.py
~~~

| Cases | Expected observations |
| --- | --- |
| A, E, F | All levels covered, a second policy at the same level provides the allow, and an unmatched deny has no effect |
| B, G, H | A missing allow at the OU, account, or root respectively |
| C, D, I | Explicit deny at the root, an outer OU, or the account even when other allows match |
| J, K, L | Management and service-linked exceptions, and insufficient path evidence |

Expect `12/12 cases matched.` For a negative control, copy the JSON and set the root `Allow` statement's `matches` in case A to `false` without updating its expected result. Pass the copy as the optional filename. Case A should report `missing-allow` at root and the checker should exit 1. If the supplied files fail, check the filename and ensure the JSON booleans are unquoted. The Python exercise was run against fictional data. The AWS CLI examples and service behavior were reviewed in documentation without using a live AWS organization.

## 6. Check your reasoning

1. **The account has a matching allow but the root has a matching deny. Which matters?** The explicit deny applies across its in-scope descendants. A closer allow does not override it.
2. **Three policies are attached to an OU and only one allows the request. Do the other two need to allow it too?** One matching allow covers that level, provided no matching deny applies. Every other level on the path must still have its own matching allow.
3. **The role policy permits the action, but the account moved last week. What evidence is missing?** Reconstruct the incident-time OU path and its policy attachments. Current state can differ from the state when the request was made.
4. **All SCP checks pass. Can the service still deny the call?** Yes. Confirm the grant, session constraints and any applicable resource-side or service-specific controls.

**Completion criterion.** Reproduce all cases and the negative control. For one unexplained denial, name the caller's account, reconstruct its path, and specify what policy and request evidence could confirm the hypothesis. Continue with [AWS role and session evidence]({{ '/wiki/aws-iam-role-evidence/' | relative_url }}) and [S3 Block Public Access evidence]({{ '/wiki/s3-block-public-access-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. This chapter follows the current AWS Organizations authorization model. AWS expanded SCP language support on 2025-09-19, including conditions with `Allow` and additional action and resource matching. Older descriptions of supported elements can differ from the current syntax.

- [AWS Organizations · SCP scope](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html) and [authorization policy types](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_authorization_policies.html)
- [AWS · September 2025 SCP language expansion](https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies/) and [IAM AccessDenied troubleshooting](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
- [AWS Organizations · ListParents](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListParents.html), [ListPoliciesForTarget](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPoliciesForTarget.html), [DescribePolicy](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribePolicy.html) and [DescribeEffectivePolicy scope](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeEffectivePolicy.html)
- [AWS Organizations CloudTrail integration](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_cloudtrail-integration.html) and [CloudTrail Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
