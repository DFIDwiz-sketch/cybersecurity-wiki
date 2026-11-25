---
title: "AWS Security Group Evidence · From Rule Change to Traffic"
description: "Correlate CloudTrail changes, ENI rules, flow records and application evidence through eight synthetic cases."
category: cloud
tags: [AWS, Security Groups, CloudTrail, VPC Flow Logs, Network Security, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-25"
translation_url: /ko/wiki/aws-security-group-evidence/
---

At 10:14 UTC, CloudTrail records a security group rule change. At 10:17, a dashboard reports a connection to a similar address. A useful investigation answers four questions in order: Did AWS accept the change? Was the rule attached to the resource at that time? Was traffic observed there? What did the application do?

## 1. What a security group controls

A **VPC** is a logically isolated AWS network. A **subnet** is a range of addresses in that network. An **ENI** (elastic network interface) is the network interface that connects a resource to the VPC. A **security group** is a set of network allow rules associated with resources, commonly through their ENIs. A rule specifies **direction** (inbound or outbound), protocol, applicable ports or ICMP type/code, and a source for inbound or a destination for outbound. A CIDR expresses an address range. An IPv4 rule for `0.0.0.0/0` permits matching traffic from any IPv4 address at this layer. IPv6 has separate rules, such as `::/0`. A reference to another group can match the private addresses of associated interfaces under supported conditions. It does not import that group's rules. Check AWS's restrictions when traffic traverses a middlebox or crosses VPC boundaries.

Groups contain allow rules only. When multiple groups are attached to the same ENI, their rules are combined. An allow in one group can still apply after removing an equivalent allow in another. Groups are **stateful**. For tracked connections, replies are allowed based on connection state. AWS documents cases where existing tracked flows persist after a rule change and cases where untracked flows can be interrupted immediately. Treat new and established connections as separate checks.

| Control | What it evaluates | What to inspect |
| --- | --- | --- |
| Security group | ENI-associated allow rules and connection state | All attached groups, direction and rule ID |
| Network ACL | Ordered allow and deny rules at a subnet boundary, without connection state | Inbound and outbound rules, including reply ports |
| Route table | Destination prefixes and forwarding targets | Forward and return routes, gateways and address translation |
| Application | Its own listener, authentication and authorization | Listener state and request, login or action logs |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/aws-security-group-evidence-en.svg' | relative_url }}" alt="Compare the rule change in CloudTrail with ENI history, flow observations and application audit records.">
  <figcaption>Each step answers a separate question. Preserve any gaps before drawing a conclusion.</figcaption>
</figure>

## 2. Walk through a normal change

Suppose the owner approves remote access for one private operations subnet, `10.20.8.0/24`, to TCP port 8443. These are fictional records.

1. At 10:14 UTC, a deployment role adds an inbound rule to `sg-app`. The CloudTrail management event identifies the recorded principal, API, group and parameters. Check the error fields and the operation's response. A failed request can appear in CloudTrail.
2. At 10:15, a configuration snapshot associates `sg-app` with `eni-app`. Check when the snapshot was taken and whether changes between 10:14 and 10:15 are accounted for. The team's September inventory would be weak evidence for today's attachment.
3. From 10:16 to 10:17, a flow record on `eni-app` shows ingress from `10.20.8.24:51540` to `10.20.2.18:8443`, TCP, `ACCEPT` and `OK`. This supports network traffic at this observation point. Review direction, address translations and the return path when matching another observation.
4. An application audit record at 10:16:48 links the service, source and request to a successful health check. The audit record supplies the application outcome. The flow record supplies traffic metadata and cannot identify a request's path or the rule that matched it.

An approved change can have no matching traffic. A broad rule can also be a real configuration issue while the resource lacks a viable route from the internet. Unexpected traffic can come from an approved scanner, health check or shared NAT address. Conversely, an unapproved change may come from a compromised automation role or a configuration error. A role name, caller IP or successful API response alone cannot distinguish these explanations.

## 3. Collect, detect and respond

**Collect change evidence.** Query EC2 management events in the affected account and Region. CloudTrail Event history covers 90 days and is regional. Longer or centralized coverage depends on the trail or event data store you configured. Preserve original event and ingest times, `eventID`, `eventName`, `userIdentity`, `requestParameters`, response and error fields. Look for `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, their egress equivalents, and `ModifySecurityGroupRules`. Also capture changes to group membership on the ENI. If a managed service owns it, use the service configuration and audit history to understand attachment changes. Correlate a role session with its issuance and approved change or pipeline run. A shared role may need additional attribution.

**Build the historical rule set.** Compare rule and attachment snapshots from the incident window, using AWS Config history if those resource types were recorded, or trusted deployment and inventory records. Track account, Region, VPC, ENI, group ID, rule ID and collection time. For new connections, evaluate all groups at the relevant network point, including approved exceptions and IPv6. Evaluate routing, the ACL and the listener separately. Record any interval for which attachment or rule history is incomplete.

**Check the observations.** Confirm Flow Logs covered the relevant ENI and time. Verify the traffic-type filter (accepted, rejected or both) and that the custom fields you rely on were collected. Join by ENI, 5-tuple, direction and overlapping UTC times. Include original packet addresses if available and needed around intermediaries. `SKIPDATA` indicates missing records. A row marked `REJECT` does not name the specific control that rejected it. Reachability Analyzer evaluates supported paths from configuration. Its result does not establish that a packet was sent or that a listener answered.

**Respond in proportion to the evidence.** A practical alert starts with a successful policy-sensitive expansion, such as IPv4 or IPv6 any-source access to a restricted service port. Enrich it with all attached ENIs, previously approved scope and a change record. Check whether another rule already allowed the same traffic. Keep an unattached risky group in the configuration queue and record deployment exposure separately. For an attached unexpected rule, preserve evidence, notify the owner, and use approved rollback or containment. Reevaluate all groups and test new and existing connections separately within authorized scope. If application logs independently support misuse, scope actions and affected identities from those logs.

### Read-only commands for an authorized account

Use AWS CLI v2 in an authorized account with permission for the two EC2 Describe APIs. Replace the example Region and IDs with your authorized inventory. Keep output with the observation timestamp and AWS account. These commands show current configuration.

~~~bash
aws ec2 describe-network-interfaces --region us-east-1 \
  --filters Name=group-id,Values=sg-0123456789abcdef0 --output json
aws ec2 describe-security-group-rules --region us-east-1 \
  --filters Name=group-id,Values=sg-0123456789abcdef0 --output json
~~~

If no ENI is listed, verify credentials, Region and managed-resource visibility. Retrieve the rules of every other group attached to an in-scope ENI. A failed collection or an empty response still needs time and scope context.

## 4. Offline lab · Eight evidence decisions

<a href="{{ '/assets/labs/aws-security-group-review.py' | relative_url }}" download="aws-security-group-review.py">Download the Python check script</a> · <a href="{{ '/assets/labs/aws-security-group-cases.json' | relative_url }}" download="aws-security-group-cases.json">Download the synthetic JSON</a>

Save both files in the same directory and run the command there with Python 3. The fixture is synthetic and deliberately normalized. It assumes direct inbound TCP flows and treats each independent signal as known, absent or unknown. It does not parse real AWS logs or simulate the network. The script performs no AWS calls.

~~~bash
python3 aws-security-group-review.py aws-security-group-cases.json
~~~

| Case | Observation | Defensible conclusion |
| --- | --- | --- |
| 01 | Approved change, attached group, matching flow and app record | Authorized change and corroborated request |
| 02 | Failed API call | Failed attempt in this event |
| 03 | Successful change, complete inventory shows no attachment | No attachment in checked scope |
| 04 | Attached group, no matching flow and incomplete coverage | Traffic unresolved |
| 05 | Target ENI records `ACCEPT`, no app evidence | Traffic observed, app outcome unresolved |
| 06 | `ACCEPT` is on a different ENI | Target traffic unresolved |
| 07 | Revoked rule, another attached group still allows new traffic | Alternate allow |
| 08 | Revoked rule, a tracked connection still observed | Established flow; new reachability unresolved |

Expect eight PASS lines. If Python cannot open the fixture, confirm the filenames and working directory. If a case fails, compare its scenario with the table before changing any expected value. Try changing the target ENI in case 05 and predict the result. Change the expected value only after making and explaining your prediction. For a team exercise, have one participant review the change and another independently review network/application evidence before comparing conclusions.

## 5. Knowledge check and completion

1. **Does a successful any-source rule change establish public reachability?** No. Check the incident-time attachment, address family, routing, ACL and listener, then validate the authorized path separately.
2. **Does a matching `ACCEPT` prove a user signed in?** No. Find an application authentication decision and match it to the flow using time, service, address and available request or session identifiers.
3. **Why might a connection persist after revocation?** Another group's rule can still allow new traffic. A previously tracked connection can continue after a change. Distinguish the two with attachment and rule evidence and a fresh authorized connection check.
4. **Can no record be reported as no access?** Only describe the specific checked evidence. Verify collection scope, filter, delay and skipped data. Application or endpoint logs may answer a question the network records cannot.

Complete the chapter when you can explain all eight cases and write one short incident note that names the account, Region, ENI and time range, cites the signals that support your conclusion, and states which question still needs evidence.

## Official references and related reading

Reviewed **2026-11-25**. AWS product documentation describes service and CLI v2 behavior at review time. The lab uses fictional evidence. The CLI and Reachability Analyzer examples were reviewed against documentation.

- Amazon VPC rule composition, group references and limitations. [Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- Amazon EC2 tracked and untracked flows. [Security group connection tracking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)
- Regional 90-day management event scope. [CloudTrail Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- Network aggregation fields and configuration analysis. [Flow Log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html) · [Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)
- Subnet ACLs and recorded configuration history. [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) · [AWS Config resource history](https://docs.aws.amazon.com/config/latest/developerguide/view-manage-resource-console.html)
- AWS CLI v2 references. [Describe network interfaces](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-interfaces.html) · [Describe security group rules](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-group-rules.html)

Previous · [AWS IAM Roles and CloudTrail Investigation]({{ '/wiki/aws-iam-role-evidence/' | relative_url }})  
Next · [AWS VPC Flow Logs]({{ '/wiki/vpc-flow-log-evidence/' | relative_url }})
