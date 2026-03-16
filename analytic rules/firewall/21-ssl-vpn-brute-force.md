**Author:** Goodness Caleb Ibeh

# SSL VPN Brute Force — Multiple Failed Logins

Detects multiple failed SSL VPN login attempts from a single source IP within a short time window. Brute force attacks against VPN portals are extremely common and represent one of the top initial access vectors for ransomware operators. A high number of failures — especially against multiple user accounts — indicates an active credential stuffing or password spraying attack.

**Importance:** VPN brute force attacks are a leading initial access vector for ransomware, and detecting them early allows blocking the attacker IP before valid credentials are found.

**MITRE:** T1110 — Brute Force
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 39426 (SSL VPN Login Fail) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39426/39426
let lookback = 1h;
let threshold = 5;
CommonSecurityLog
// Filter to the last 1 hour for near-real-time brute force detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: only look at failed SSL VPN login attempts
| where DeviceAction == "ssl-login-fail"
// Aggregate failure counts per source IP to identify brute force patterns
| summarize
    FailureCount = count(),
    DistinctUsers = dcount(DestinationUserName),
    Users = make_set(DestinationUserName, 10),
    Reasons = make_set(Message, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by SourceIP
// Threshold filter: only alert when failures exceed the brute force threshold
| where FailureCount >= threshold
| extend
    AlertTitle = "SSL VPN Brute Force — Multiple Failed Logins",
    AlertDescription = "Multiple failed SSL VPN login attempts detected from a single source IP, indicating a potential credential stuffing or password spraying attack.",
    AlertSeverity = "Medium"
| project SourceIP, FailureCount, DistinctUsers, Users, Reasons, FirstAttempt, LastAttempt, AlertTitle, AlertDescription, AlertSeverity
| order by FailureCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: c5e1b8c2-4f6a-4a9d-d7e3-1f2a5b8c0d9e
name: "SSL VPN Brute Force — Multiple Failed Logins"
description: |
  Detects multiple failed SSL VPN login attempts from a single source IP within a short time window. VPN brute force attacks are a leading initial access vector for ransomware, and detecting them early allows blocking the attacker IP before valid credentials are found. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
query: |
  let lookback = 1h;
  let threshold = 5;
  CommonSecurityLog
  // Filter to the last 1 hour for near-real-time brute force detection
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for VPN-related log entries
  | where Activity has "vpn"
  // Key filter: only look at failed SSL VPN login attempts
  | where DeviceAction == "ssl-login-fail"
  // Aggregate failure counts per source IP to identify brute force patterns
  | summarize
      FailureCount = count(),
      DistinctUsers = dcount(DestinationUserName),
      Users = make_set(DestinationUserName, 10),
      Reasons = make_set(Message, 5),
      FirstAttempt = min(TimeGenerated),
      LastAttempt = max(TimeGenerated)
    by SourceIP
  // Threshold filter: only alert when failures exceed the brute force threshold
  | where FailureCount >= threshold
  | extend
      AlertTitle = "SSL VPN Brute Force — Multiple Failed Logins",
      AlertDescription = "Multiple failed SSL VPN login attempts detected from a single source IP, indicating a potential credential stuffing or password spraying attack.",
      AlertSeverity = "Medium"
  | project SourceIP, FailureCount, DistinctUsers, Users, Reasons, FirstAttempt, LastAttempt, AlertTitle, AlertDescription, AlertSeverity
  | order by FailureCount desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  FailureCount: FailureCount
  DistinctUsers: DistinctUsers
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **SSL VPN Login Fail (Log ID 39426):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39426/39426
- **VPN Logs Overview:** https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/834425/understanding-vpn-related-logs
