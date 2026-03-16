**Author:** Goodness Caleb Ibeh

# DoS Protection Alert Triggered

Detects when the switch's built-in DoS protection feature triggers an alert or takes action against suspected denial-of-service traffic. The switch can detect various DoS attack patterns including SYN floods, ICMP floods, and other volumetric attacks directed at the switch's control plane. When triggered, the switch may rate-limit or block the offending traffic to protect itself.

**Importance:** SOC analysts should investigate DoS protection alerts because they confirm that attack traffic has reached sufficient volume to trigger hardware-level protection, indicating an active denial-of-service attack.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — dosprotect.Alert / dosprotect.Action — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for DoS protection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match DoS protection alert and action events
| where SyslogMessage has_any ("dosprotect.Alert", "dosprotect.Action")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| extend
    AlertTitle = "DoS Protection Alert Triggered",
    AlertDescription = "The switch DoS protection feature triggered against suspected denial-of-service traffic, indicating an active attack.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, Severity, Component, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: cb9dc218-83db-41f3-b9fa-a15d20d705b3
name: "DoS Protection Alert Triggered"
description: |
  Detects when the switch's built-in DoS protection feature triggers an alert or takes action against suspected denial-of-service traffic. The switch can detect various DoS attack patterns including SYN floods, ICMP floods, and other volumetric attacks directed at the switch's control plane. When triggered, the switch may rate-limit or block the offending traffic to protect itself.
  SOC analysts should investigate DoS protection alerts because they confirm that attack traffic has reached sufficient volume to trigger hardware-level protection, indicating an active denial-of-service attack.
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
  // Lookback: 24 hours for DoS protection events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match DoS protection alert and action events
  | where SyslogMessage has_any ("dosprotect.Alert", "dosprotect.Action")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | extend
      AlertTitle = "DoS Protection Alert Triggered",
      AlertDescription = "The switch DoS protection feature triggered against suspected denial-of-service traffic, indicating an active attack.",
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

- [Extreme Networks — DoS Protection Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
