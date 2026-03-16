**Author:** Goodness Caleb Ibeh

# EAPS Ring State Change

Detects state changes in the Ethernet Automatic Protection Switching (EAPS) ring topology. EAPS provides sub-second failover for ring-based network designs common in campus and metro Ethernet deployments. A state change from Complete to Failed indicates a ring break, while rapid state transitions may indicate instability in the ring that could lead to traffic blackholing or loops.

**Importance:** SOC analysts should monitor EAPS state changes because ring failures affect redundancy and can lead to traffic loss or loops if the protection mechanism does not converge correctly.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — EAPS.State — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for EAPS ring state events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match EAPS state and topology change events
| where SyslogMessage has_any ("EAPS.State", "EAPS.Topology")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| extend
    AlertTitle = "EAPS Ring State Change",
    AlertDescription = "EAPS ring state change detected, indicating a potential ring break or instability that could lead to traffic loss or loops.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 12499a95-d402-4d1f-82b8-666dfa2b1e40
name: "EAPS Ring State Change"
description: |
  Detects state changes in the Ethernet Automatic Protection Switching (EAPS) ring topology. EAPS provides sub-second failover for ring-based network designs common in campus and metro Ethernet deployments. A state change from Complete to Failed indicates a ring break, while rapid state transitions may indicate instability in the ring that could lead to traffic blackholing or loops.
  SOC analysts should monitor EAPS state changes because ring failures affect redundancy and can lead to traffic loss or loops if the protection mechanism does not converge correctly.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
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
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 24 hours for EAPS ring state events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match EAPS state and topology change events
  | where SyslogMessage has_any ("EAPS.State", "EAPS.Topology")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | extend
      AlertTitle = "EAPS Ring State Change",
      AlertDescription = "EAPS ring state change detected, indicating a potential ring break or instability that could lead to traffic loss or loops.",
      AlertSeverity = "High"
  | project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc

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
  Component: Component
  Severity: Severity
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — EAPS Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
