**Author:** Goodness Caleb Ibeh

# Session Table Saturation — Excessive Concurrent Sessions

Detects a single source IP creating an abnormally large number of concurrent sessions, which can exhaust the FortiGate's session table and cause denial of service for all network users. Session table saturation is a resource exhaustion attack that can be more effective than bandwidth-based DoS because it targets the firewall's finite connection tracking capacity. This can also indicate a compromised host running botnet or cryptomining software that opens thousands of connections.

**Importance:** Session table exhaustion can cause the firewall to drop legitimate traffic for all users, and a single compromised host generating thousands of sessions can create a network-wide outage.

**MITRE:** T1499 — Endpoint Denial of Service
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: FortiOS DoS Protection — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/639498/dos-protection
let lookback = 1h;
// Session threshold — adjust based on your firewall's session table capacity
let sessionThreshold = 5000;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Key filter: only count accepted/started sessions (active connections)
| where DeviceAction in ("accept", "start")
// Aggregate active sessions per source IP in 5-minute bins
| summarize
    ActiveSessions = count(),
    DistinctDests = dcount(DestinationIP),
    DistinctPorts = dcount(DestinationPort)
  by SourceIP, bin(TimeGenerated, 5m)
// Threshold filter: only flag sources exceeding the session threshold
| where ActiveSessions > sessionThreshold
| extend
    AlertTitle = "Session Table Saturation — Excessive Concurrent Sessions",
    AlertDescription = "Single source IP creating an abnormally large number of concurrent sessions, which can exhaust the firewall session table and cause denial of service.",
    AlertSeverity = "Medium"
| project TimeGenerated, SourceIP, ActiveSessions, DistinctDests, DistinctPorts, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b2c8a5b9-1d3e-4b6f-c4e0-8f9a2b5c7d6e
name: "Session Table Saturation — Excessive Concurrent Sessions"
description: |
  Detects a single source IP creating an abnormally large number of concurrent sessions, which can exhaust the FortiGate's session table and cause denial of service for all network users. Session table exhaustion can cause the firewall to drop legitimate traffic for all users, and a single compromised host generating thousands of sessions can create a network-wide outage. Designed for Fortinet FortiGate firewalls.
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
  - Impact
relevantTechniques:
  - T1499
query: |
  let lookback = 1h;
  // Session threshold — adjust based on your firewall's session table capacity
  let sessionThreshold = 5000;
  CommonSecurityLog
  // Filter to the last 1 hour of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Key filter: only count accepted/started sessions (active connections)
  | where DeviceAction in ("accept", "start")
  // Aggregate active sessions per source IP in 5-minute bins
  | summarize
      ActiveSessions = count(),
      DistinctDests = dcount(DestinationIP),
      DistinctPorts = dcount(DestinationPort)
    by SourceIP, bin(TimeGenerated, 5m)
  // Threshold filter: only flag sources exceeding the session threshold
  | where ActiveSessions > sessionThreshold
  | extend
      AlertTitle = "Session Table Saturation — Excessive Concurrent Sessions",
      AlertDescription = "Single source IP creating an abnormally large number of concurrent sessions, which can exhaust the firewall session table and cause denial of service.",
      AlertSeverity = "Medium"
  | project TimeGenerated, SourceIP, ActiveSessions, DistinctDests, DistinctPorts, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  ActiveSessions: ActiveSessions
  DistinctDests: DistinctDests
  DistinctPorts: DistinctPorts
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **DoS Protection:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/639498/dos-protection
- **Anomaly Log IDs 18432-18434:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/18432/18432
