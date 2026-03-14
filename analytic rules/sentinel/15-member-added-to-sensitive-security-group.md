**Author:** Goodness Caleb Ibeh

# Member Added to Sensitive Security Group

This detection monitors for users being added to sensitive on-premises Active Directory security groups such as Domain Admins, Enterprise Admins, and Schema Admins. These groups provide the highest levels of privilege in an AD environment. Unauthorized additions typically indicate an attacker has compromised a privileged account and is escalating their access to gain full domain control.

**Importance:** A SOC analyst should investigate immediately because membership in groups like Domain Admins or Enterprise Admins grants near-total control over the Active Directory environment.

**MITRE:** T1078.002 — Valid Accounts: Domain Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | MemberName |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for group membership changes
| where TimeGenerated > ago(24h)
// Event IDs: 4728 (Global), 4732 (Local), 4756 (Universal) group member add
| where EventID in (4728, 4732, 4756)
// Key filter: only flag additions to known sensitive/privileged groups
| where TargetUserName has_any (
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "DnsAdmins", "Exchange Organization Management"
  )
| project TimeGenerated, Computer, SubjectAccount, MemberName, MemberSid,
          TargetUserName, Activity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 15c6d7e8-f9a0-4b1c-2d3e-4f5a6b7c8d9b
name: "Member Added to Sensitive Security Group"
description: |
  This detection monitors for users being added to sensitive on-premises Active Directory security groups such as Domain Admins, Enterprise Admins, and Schema Admins. These groups provide the highest levels of privilege in an AD environment.
  A SOC analyst should investigate immediately because membership in groups like Domain Admins or Enterprise Admins grants near-total control over the Active Directory environment.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078.002
query: |
  SecurityEvent
  // 24-hour lookback for group membership changes
  | where TimeGenerated > ago(24h)
  // Event IDs: 4728 (Global), 4732 (Local), 4756 (Universal) group member add
  | where EventID in (4728, 4732, 4756)
  // Key filter: only flag additions to known sensitive/privileged groups
  | where TargetUserName has_any (
      "Domain Admins", "Enterprise Admins", "Schema Admins",
      "Administrators", "Account Operators", "Backup Operators",
      "Server Operators", "DnsAdmins", "Exchange Organization Management"
    )
  | project TimeGenerated, Computer, SubjectAccount, MemberName, MemberSid,
            TargetUserName, Activity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: MemberName
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
version: 1.0.0
kind: Scheduled
```
