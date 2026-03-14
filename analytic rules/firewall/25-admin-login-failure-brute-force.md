**Author:** Goodness Caleb Ibeh

# Admin Login Failure — Brute Force

Detects multiple failed administrative login attempts to FortiGate management interfaces from a single source IP. Firewall admin access is one of the highest-value targets for attackers — gaining admin access to the firewall allows complete network control, policy manipulation, and the ability to disable all security features. Brute force attacks against admin interfaces are a critical threat that can lead to total network compromise.

**Importance:** Firewall admin brute force attacks target the single most critical security control in your network, and successful compromise would give an attacker complete control over all network security policies.

**MITRE:** T1110 — Brute Force
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 0100032002 (Admin Login Fail) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32002/32002
let lookback = 30m;
let threshold = 5;
CommonSecurityLog
// Filter to a short 30-minute window for rapid brute force detection
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for system-level log entries (admin events)
| where Activity has "system"
// Key filter: FortiGate event ID for admin login failure
| where DeviceEventClassID in ("32002", "0100032002")
// Aggregate login failures per source IP and target device
| summarize
    FailureCount = count(),
    Users = make_set(DestinationUserName, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by SourceIP, DeviceName
// Threshold filter: only alert when failure count indicates brute force
| where FailureCount >= threshold
| project SourceIP, DeviceName, FailureCount, Users, FirstAttempt, LastAttempt
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a9c5f2a6-8d0e-4e3b-b1c7-5d6e9f0a3b2c
name: "Admin Login Failure — Brute Force"
description: |
  Detects multiple failed administrative login attempts to FortiGate management interfaces from a single source IP. Firewall admin brute force attacks target the single most critical security control in your network, and successful compromise would give an attacker complete control over all network security policies. Designed for Fortinet FortiGate firewalls.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 30m
queryPeriod: 30m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
query: |
  let lookback = 30m;
  let threshold = 5;
  CommonSecurityLog
  // Filter to a short 30-minute window for rapid brute force detection
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for system-level log entries (admin events)
  | where Activity has "system"
  // Key filter: FortiGate event ID for admin login failure
  | where DeviceEventClassID in ("32002", "0100032002")
  // Aggregate login failures per source IP and target device
  | summarize
      FailureCount = count(),
      Users = make_set(DestinationUserName, 5),
      FirstAttempt = min(TimeGenerated),
      LastAttempt = max(TimeGenerated)
    by SourceIP, DeviceName
  // Threshold filter: only alert when failure count indicates brute force
  | where FailureCount >= threshold
  | project SourceIP, DeviceName, FailureCount, Users, FirstAttempt, LastAttempt
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceName: DeviceName
  FailureCount: FailureCount
version: 1.0.0
kind: Scheduled
```

## References

- **Admin Login Fail (Log ID 0100032002):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/32002/32002
- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
