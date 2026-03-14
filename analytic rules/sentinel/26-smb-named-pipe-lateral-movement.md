**Author:** Goodness Caleb Ibeh

# SMB/Named Pipe Lateral Movement

This detection identifies access to administrative SMB shares (ADMIN$, C$, IPC$) from non-machine accounts, which is a common lateral movement technique. Attackers use these administrative shares to copy tools and malware to remote systems, execute commands, and access sensitive files. While administrative shares are used legitimately, access from standard user accounts or unusual source IPs warrants investigation.

**Importance:** A SOC analyst should investigate because administrative share access is the backbone of many lateral movement techniques including PsExec, remote service installation, and manual file staging.

**MITRE:** T1021.002 — Remote Services: SMB/Windows Admin Shares

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | SubjectAccount |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for SMB share access events
| where TimeGenerated > ago(24h)
// Event ID 5145 = A network share object was checked for access
| where EventID == 5145
// Key filter: only administrative shares used for lateral movement
| where ShareName in (@"\*\ADMIN$", @"\*\C$", @"\*\IPC$")
// Exclude machine accounts (end with $) which access these legitimately
| where SubjectUserName !endswith "$"
// Aggregate access count to identify high-volume/automated activity
| summarize
    AccessCount = count(),
    Shares = make_set(ShareName),
    Targets = make_set(RelativeTargetName, 20)
  by SubjectAccount, Computer, IpAddress
// Threshold: flag high-volume share access
| where AccessCount > 10
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 26b7c8d9-e0f1-4a2b-3c4d-5e6f7a8b9ca6
name: "SMB/Named Pipe Lateral Movement"
description: |
  This detection identifies access to administrative SMB shares (ADMIN$, C$, IPC$) from non-machine accounts, which is a common lateral movement technique. Attackers use these administrative shares to copy tools and malware to remote systems, execute commands, and access sensitive files.
  A SOC analyst should investigate because administrative share access is the backbone of many lateral movement techniques including PsExec, remote service installation, and manual file staging.
severity: Medium
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
  - LateralMovement
relevantTechniques:
  - T1021.002
query: |
  SecurityEvent
  // 24-hour lookback for SMB share access events
  | where TimeGenerated > ago(24h)
  // Event ID 5145 = A network share object was checked for access
  | where EventID == 5145
  // Key filter: only administrative shares used for lateral movement
  | where ShareName in (@"\*\ADMIN$", @"\*\C$", @"\*\IPC$")
  // Exclude machine accounts (end with $) which access these legitimately
  | where SubjectUserName !endswith "$"
  // Aggregate access count to identify high-volume/automated activity
  | summarize
      AccessCount = count(),
      Shares = make_set(ShareName),
      Targets = make_set(RelativeTargetName, 20)
    by SubjectAccount, Computer, IpAddress
  // Threshold: flag high-volume share access
  | where AccessCount > 10
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: SubjectAccount
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
version: 1.0.0
kind: Scheduled
```
