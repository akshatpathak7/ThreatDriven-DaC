# Threat-Driven Cloud Detection Report

## Executive Summary

The pipeline generated 12 alert(s), including 10 critical and 2 high severity finding(s). The highest-risk activity was 'Root Account Console Login' affecting arn:aws:iam::111122223333:root from 203.0.113.66. 4 alert(s) matched offline threat-intelligence indicators. Security teams should validate the affected identities (arn:aws:iam::111122223333:root, backup-admin, contractor, finance-user, network-admin), review CloudTrail and IAM changes, rotate exposed credentials where needed, and confirm whether the activity was authorized.

## Alert Overview

- Total alerts: 12
- Critical: 10
- High: 2
- Medium: 0
- Low: 0
- Threat intelligence matches: 4

## High and Critical Alerts

| Time | Severity | Rule | User | Source IP | Region | Risk |
| --- | --- | --- | --- | --- | --- | ---: |
| 2026-06-11T01:00:00Z | critical | Root Account Console Login | arn:aws:iam::111122223333:root | 203.0.113.66 | us-east-1 | 100 |
| 2026-06-11T01:00:00Z | critical | Console Login Without MFA | arn:aws:iam::111122223333:root | 203.0.113.66 | us-east-1 | 100 |
| 2026-06-11T01:00:00Z | critical | API Call From Known Malicious IP | arn:aws:iam::111122223333:root | 203.0.113.66 | us-east-1 | 100 |
| 2026-06-11T01:05:00Z | critical | Console Login Without MFA | finance-user | 198.51.100.77 | us-east-1 | 80 |
| 2026-06-11T01:12:00Z | high | IAM User Created | security-admin | 198.51.100.78 | us-east-1 | 73 |
| 2026-06-11T01:16:00Z | critical | AdministratorAccess Policy Attached to User | security-admin | 198.51.100.78 | us-east-1 | 100 |
| 2026-06-11T01:20:00Z | critical | New Access Key Created | security-admin | 198.51.100.78 | us-east-1 | 90 |
| 2026-06-11T01:30:00Z | critical | S3 Bucket Policy Allows Public Access | storage-operator | 198.51.100.80 | us-east-1 | 88 |
| 2026-06-11T01:40:00Z | critical | CloudTrail Logging Stopped or Deleted | ops-admin | 198.51.100.81 | us-east-1 | 100 |
| 2026-06-11T01:45:00Z | critical | Security Group Opened to the World | network-admin | 198.51.100.82 | us-west-2 | 94 |
| 2026-06-11T01:50:00Z | critical | API Call From Known Malicious IP | contractor | 192.0.2.44 | us-east-1 | 97 |
| 2026-06-11T02:05:00Z | high | Activity From Unusual AWS Region | backup-admin | 198.51.100.90 | ap-southeast-3 | 76 |

## Threat Intelligence Matches

| Indicator | Type | Threat Type | Confidence | Source |
| --- | --- | --- | ---: | --- |
| 203.0.113.66 | ip | credential_access_infrastructure | 92 | MockTI |
| 203.0.113.66 | ip | credential_access_infrastructure | 92 | MockTI |
| 203.0.113.66 | ip | credential_access_infrastructure | 92 | MockTI |
| 192.0.2.44 | ip | suspicious_cloud_api_activity | 84 | MockTI |

## MITRE ATT&CK Coverage

| Tactic | Techniques | Alert Count |
| --- | --- | ---: |
| Collection | T1530 Data from Cloud Storage | 1 |
| Command and Control | T1102 Web Service | 2 |
| Credential Access | T1552.005 Cloud Instance Metadata API, T1556 Modify Authentication Process | 3 |
| Defense Evasion | T1535 Unused/Unsupported Cloud Regions, T1562.008 Disable or Modify Cloud Logs | 2 |
| Discovery | T1526 Cloud Service Dashboard | 1 |
| Exfiltration | T1537 Transfer Data to Cloud Account | 1 |
| Initial Access | T1078.004 Cloud Accounts, T1133 External Remote Services | 6 |
| Persistence | T1098 Account Manipulation, T1136.003 Cloud Account | 3 |
| Privilege Escalation | T1098.003 Additional Cloud Roles | 1 |

## Affected Scope

- Accounts: 111122223333
- Users/roles: arn:aws:iam::111122223333:root, backup-admin, contractor, finance-user, network-admin, ops-admin, security-admin, storage-operator

## Recommended Next Steps

- Validate whether each IAM, S3, CloudTrail, and security group change was authorized.
- Review source IP reputation and geolocation for suspicious login and API activity.
- Re-enable CloudTrail logging immediately if it was stopped or deleted.
- Remove public S3 bucket exposure unless explicitly approved.
- Rotate access keys created during suspicious sessions and enforce MFA.

## False Positive Considerations

- Administrative automation can create IAM users, keys, and policies during approved deployments.
- Security groups may be opened temporarily during troubleshooting or migration windows.
- Unusual regions can be legitimate when new business units expand cloud usage.
- Threat-intelligence indicators are sample offline data and should be validated before escalation.
