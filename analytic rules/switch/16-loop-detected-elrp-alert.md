**Author:** Goodness Caleb Ibeh

# Loop Detected — ELRP Alert

Detects when the Extreme Loop Recovery Protocol (ELRP) identifies a Layer 2 loop in the network. Loops cause broadcast storms that can overwhelm switch CPUs and saturate bandwidth, effectively bringing down the entire VLAN or network segment. ELRP sends test packets and alerts when they return to the originating switch, confirming a loop condition.

**Importance:** SOC analysts must respond to loop detections urgently because an unresolved loop can cascade into a complete network outage within seconds.

**MITRE:** T1498 — Network Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — ELRP.Detect — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for loop detection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match ELRP loop detection and action events
| where SyslogMessage has_any ("ELRP.Detect", "ELRP.Action")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| extend
    AlertTitle = "Loop Detected — ELRP Alert",
    AlertDescription = "ELRP identified a Layer 2 loop in the network, which can cause broadcast storms and network outages.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b71981e3-a9b9-4db2-a060-cc4f5c1ceefe
name: "Loop Detected — ELRP Alert"
description: |
  Detects when the Extreme Loop Recovery Protocol (ELRP) identifies a Layer 2 loop in the network. Loops cause broadcast storms that can overwhelm switch CPUs and saturate bandwidth, effectively bringing down the entire VLAN or network segment. ELRP sends test packets and alerts when they return to the originating switch, confirming a loop condition.
  SOC analysts must respond to loop detections urgently because an unresolved loop can cascade into a complete network outage within seconds.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Critical
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
  // Lookback: 24 hours for loop detection events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match ELRP loop detection and action events
  | where SyslogMessage has_any ("ELRP.Detect", "ELRP.Action")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | extend
      AlertTitle = "Loop Detected — ELRP Alert",
      AlertDescription = "ELRP identified a Layer 2 loop in the network, which can cause broadcast storms and network outages.",
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

- [Extreme Networks — ELRP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
