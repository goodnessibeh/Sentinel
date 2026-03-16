**Author:** Goodness Caleb Ibeh

# PoE Power Fault or Denial

Detects Power over Ethernet (PoE) faults, power denials, and overload conditions on switch ports. PoE issues can affect IP phones, wireless access points, cameras, and other powered devices. A power denial indicates the switch cannot allocate sufficient power to a port, a power fault indicates a wiring or device issue, and an overload means the total PoE budget is exceeded. These events can be caused by hardware failures or deliberate PoE exhaustion attacks.

**Importance:** SOC analysts should monitor PoE events because power denial to critical devices like security cameras or access points can be used to create blind spots in physical security.

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — PoE.PwrDeny / PoE.PwrFault / PoE.Overload — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for PoE power events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match PoE power denial, fault, and overload events
| where SyslogMessage has_any ("PoE.PwrDeny", "PoE.PwrFault", "PoE.Overload")
// Extract the affected port
| extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| extend
    AlertTitle = "PoE Power Fault or Denial",
    AlertDescription = "PoE fault, power denial, or overload condition detected on a switch port, potentially affecting powered devices.",
    AlertSeverity = "Medium"
| project TimeGenerated, HostName, Severity, Component, Port, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a52030ec-d255-498a-85cd-d1ebb0e86ed9
name: "PoE Power Fault or Denial"
description: |
  Detects Power over Ethernet (PoE) faults, power denials, and overload conditions on switch ports. PoE issues can affect IP phones, wireless access points, cameras, and other powered devices. A power denial indicates the switch cannot allocate sufficient power to a port, a power fault indicates a wiring or device issue, and an overload means the total PoE budget is exceeded. These events can be caused by hardware failures or deliberate PoE exhaustion attacks.
  SOC analysts should monitor PoE events because power denial to critical devices like security cameras or access points can be used to create blind spots in physical security.
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
  - Impact
relevantTechniques:
  - T1499
query: |
  // Lookback: 24 hours for PoE power events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match PoE power denial, fault, and overload events
  | where SyslogMessage has_any ("PoE.PwrDeny", "PoE.PwrFault", "PoE.Overload")
  // Extract the affected port
  | extend Port = extract(@"[Pp]ort\s+(\S+)", 1, SyslogMessage)
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | extend
      AlertTitle = "PoE Power Fault or Denial",
      AlertDescription = "PoE fault, power denial, or overload condition detected on a switch port, potentially affecting powered devices.",
      AlertSeverity = "Medium"
  | project TimeGenerated, HostName, Severity, Component, Port, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
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
  Port: Port
  Component: Component
  Severity: Severity
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — PoE Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Severity Levels (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-D3F3B734-61C5-4F78-A6C6-198B56174DE2.shtml)
- [Extreme Networks — Syslog Severity Mapping (Knowledge Base)](https://extreme-networks.my.site.com/ExtrArticleDetail?n=000005865)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
