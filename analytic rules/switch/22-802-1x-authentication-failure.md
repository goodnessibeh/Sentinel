**Author:** Goodness Caleb Ibeh

# 802.1X Authentication Failure

Detects failed 802.1X (Network Access Control) authentication attempts on switch ports. 802.1X provides port-based access control where devices must authenticate before gaining network access. Failures indicate that a device was unable to present valid credentials, which may be a misconfigured endpoint, an expired certificate, or an unauthorized device attempting to connect to the network.

**Importance:** SOC analysts should monitor 802.1X failures because repeated failures on the same port may indicate an attacker attempting to bypass network access control with stolen or brute-forced credentials.

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — nl.ClientStateChange — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for 802.1X authentication events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match netLogin client state change events
| where SyslogMessage has_any ("nl.ClientStateChange", "netLogin.ClientStateChange")
// Further filter to only failure/rejection states
| where SyslogMessage has_any ("Reject", "reject", "Fail", "fail", "Denied", "denied")
// Extract the client MAC address, port, and VLAN context
| extend MACAddress = extract(@"Station\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
| extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
| extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
| project TimeGenerated, HostName, MACAddress, Port, VLANName, SyslogMessage
// Aggregate failures per MAC per hour to detect persistent attempts
| summarize
    FailCount = count(),
    Ports = make_set(Port, 10)
  by HostName, MACAddress, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "802.1X Authentication Failure",
    AlertDescription = "Failed 802.1X authentication attempts detected on switch ports, indicating unauthorized device connection attempts or misconfigured endpoints.",
    AlertSeverity = "Medium"
| order by FailCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: da9ad8e3-efd8-4080-8d3d-48e7addf77dd
name: "802.1X Authentication Failure"
description: |
  Detects failed 802.1X (Network Access Control) authentication attempts on switch ports. 802.1X provides port-based access control where devices must authenticate before gaining network access. Failures indicate that a device was unable to present valid credentials, which may be a misconfigured endpoint, an expired certificate, or an unauthorized device attempting to connect to the network.
  SOC analysts should monitor 802.1X failures because repeated failures on the same port may indicate an attacker attempting to bypass network access control with stolen or brute-forced credentials.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
query: |
  // Lookback: 24 hours for 802.1X authentication events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match netLogin client state change events
  | where SyslogMessage has_any ("nl.ClientStateChange", "netLogin.ClientStateChange")
  // Further filter to only failure/rejection states
  | where SyslogMessage has_any ("Reject", "reject", "Fail", "fail", "Denied", "denied")
  // Extract the client MAC address, port, and VLAN context
  | extend MACAddress = extract(@"Station\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  | extend Port = extract(@"port\s+(\S+)", 1, SyslogMessage)
  | extend VLANName = extract(@'VLAN\s+"([^"]+)"', 1, SyslogMessage)
  | project TimeGenerated, HostName, MACAddress, Port, VLANName, SyslogMessage
  // Aggregate failures per MAC per hour to detect persistent attempts
  | summarize
      FailCount = count(),
      Ports = make_set(Port, 10)
    by HostName, MACAddress, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "802.1X Authentication Failure",
      AlertDescription = "Failed 802.1X authentication attempts detected on switch ports, indicating unauthorized device connection attempts or misconfigured endpoints.",
      AlertSeverity = "Medium"
  | order by FailCount desc

alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  MACAddress: MACAddress
  FailCount: FailCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Network Login (802.1X) Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
