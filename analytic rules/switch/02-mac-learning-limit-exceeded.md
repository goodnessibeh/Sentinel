**Author:** Goodness Caleb Ibeh

# MAC Learning Limit Exceeded

Detects when a switch port exceeds its configured MAC address learning limit, which restricts how many unique MAC addresses can be learned on a single port. Exceeding this limit often indicates a MAC flooding attack where an adversary sends frames with many spoofed source MAC addresses to overflow the switch's CAM table. It can also indicate a misconfigured hub or unauthorized switch connected downstream.

**Importance:** SOC analysts should investigate as MAC flooding is a classic technique to force switches into hub mode, enabling traffic sniffing across the entire VLAN.

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — FDB.LrnLimit — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours of syslog data
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match FDB learning limit exceeded messages
| where SyslogMessage has "FDB.LrnLimit"
// Parse port information from the message
| parse SyslogMessage with * "Port " Port " " Rest
// Extract offending MAC address
| extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
// Aggregate violations per host/port per hour to identify patterns
| summarize
    ViolationCount = count(),
    MACList = make_set(MACAddress, 20)
  by HostName, Port, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "MAC Learning Limit Exceeded",
    AlertDescription = "A switch port exceeded its configured MAC address learning limit, potentially indicating a MAC flooding attack.",
    AlertSeverity = "Medium"
| order by ViolationCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: ca270bad-bc19-4763-b9ad-f430d0d4703f
name: "MAC Learning Limit Exceeded"
description: |
  Detects when a switch port exceeds its configured MAC address learning limit, which restricts how many unique MAC addresses can be learned on a single port. Exceeding this limit often indicates a MAC flooding attack where an adversary sends frames with many spoofed source MAC addresses to overflow the switch's CAM table. It can also indicate a misconfigured hub or unauthorized switch connected downstream.
  SOC analysts should investigate as MAC flooding is a classic technique to force switches into hub mode, enabling traffic sniffing across the entire VLAN.
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
  - T1557
query: |
  // Lookback: 24 hours of syslog data
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match FDB learning limit exceeded messages
  | where SyslogMessage has "FDB.LrnLimit"
  // Parse port information from the message
  | parse SyslogMessage with * "Port " Port " " Rest
  // Extract offending MAC address
  | extend MACAddress = extract(@"MAC\s+([0-9a-fA-F:.-]+)", 1, SyslogMessage)
  // Aggregate violations per host/port per hour to identify patterns
  | summarize
      ViolationCount = count(),
      MACList = make_set(MACAddress, 20)
    by HostName, Port, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "MAC Learning Limit Exceeded",
      AlertDescription = "A switch port exceeded its configured MAC address learning limit, potentially indicating a MAC flooding attack.",
      AlertSeverity = "Medium"
  | order by ViolationCount desc

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
  Port: Port
  ViolationCount: ViolationCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — MAC Learning Limit Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — FDB EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
