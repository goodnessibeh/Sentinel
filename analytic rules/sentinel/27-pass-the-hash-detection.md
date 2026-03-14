**Author:** Goodness Caleb Ibeh

# Pass-the-Hash Detection

This detection identifies potential Pass-the-Hash attacks by finding NTLM network logons from a single account and IP address to multiple distinct hosts. In a Pass-the-Hash attack, the adversary uses a stolen NTLM hash (rather than a plaintext password) to authenticate to remote systems. The use of NTLM authentication combined with network logon type across multiple hosts is a strong indicator of this technique.

**Importance:** A SOC analyst should treat this as high priority because Pass-the-Hash enables an attacker to move laterally across the domain using stolen credential hashes without knowing the actual password.

**MITRE:** T1550.002 — Use Alternate Authentication Material: Pass the Hash

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | TargetUserName |
| Host | FullName | Computer |

```kql
SecurityEvent
// 24-hour lookback for NTLM logon events
| where TimeGenerated > ago(24h)
// Event ID 4624 = An account was successfully logged on
| where EventID == 4624
// Key filter: Network logon (Type 3) + NTLM = PtH pattern
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
// Exclude machine accounts and local/loopback addresses
| where TargetUserName !endswith "$"
| where IpAddress != "-" and IpAddress != "127.0.0.1"
// Aggregate: count distinct target hosts per account and source IP
| summarize
    LogonCount = count(),
    DistinctHosts = dcount(Computer),
    HostList = make_set(Computer, 20)
  by TargetUserName, TargetDomainName, IpAddress
// Threshold: NTLM logons to 3+ distinct hosts from same source is suspicious
| where DistinctHosts >= 3
| project TargetUserName, TargetDomainName, IpAddress, DistinctHosts, HostList, LogonCount
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 27c8d9e0-f1a2-4b3c-4d5e-6f7a8b9c0db7
name: "Pass-the-Hash Detection"
description: |
  This detection identifies potential Pass-the-Hash attacks by finding NTLM network logons from a single account and IP address to multiple distinct hosts. In a Pass-the-Hash attack, the adversary uses a stolen NTLM hash to authenticate to remote systems.
  A SOC analyst should treat this as high priority because Pass-the-Hash enables an attacker to move laterally across the domain using stolen credential hashes without knowing the actual password.
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
  - LateralMovement
relevantTechniques:
  - T1550.002
query: |
  SecurityEvent
  // 24-hour lookback for NTLM logon events
  | where TimeGenerated > ago(24h)
  // Event ID 4624 = An account was successfully logged on
  | where EventID == 4624
  // Key filter: Network logon (Type 3) + NTLM = PtH pattern
  | where LogonType == 3  // Network logon
  | where AuthenticationPackageName == "NTLM"
  // Exclude machine accounts and local/loopback addresses
  | where TargetUserName !endswith "$"
  | where IpAddress != "-" and IpAddress != "127.0.0.1"
  // Aggregate: count distinct target hosts per account and source IP
  | summarize
      LogonCount = count(),
      DistinctHosts = dcount(Computer),
      HostList = make_set(Computer, 20)
    by TargetUserName, TargetDomainName, IpAddress
  // Threshold: NTLM logons to 3+ distinct hosts from same source is suspicious
  | where DistinctHosts >= 3
  | project TargetUserName, TargetDomainName, IpAddress, DistinctHosts, HostList, LogonCount
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: TargetUserName
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
version: 1.0.0
kind: Scheduled
```
