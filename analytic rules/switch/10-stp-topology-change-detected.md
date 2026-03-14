**Author:** Goodness Caleb Ibeh

# STP Topology Change Detected

Detects Spanning Tree Protocol topology change notifications (TCNs) on the switch. STP topology changes cause the switch to flush its MAC address table and temporarily flood traffic, which degrades network performance. While some TCNs are expected during maintenance, unexpected changes may indicate physical link failures, misconfigurations, or deliberate STP manipulation.

**Importance:** SOC analysts should correlate STP topology changes with other events because they can be a side effect of physical intrusion, unauthorized device connections, or deliberate network attacks.

**MITRE:** T1498 — Network Denial of Service

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — STP.State.Topology — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for STP topology change events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all STP topology change related EMS messages
| where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.SendClntTopoChgMsg")
// Parse severity and component from structured EMS format
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Extract the STP domain name for context
| extend StpDomain = extract(@"\[([^\]]+)\]", 1, SyslogMessage)
| project TimeGenerated, HostName, Severity, Component, StpDomain, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a33e0288-54fa-4d8c-b85d-8bc7098718af
name: "STP Topology Change Detected"
description: |
  Detects Spanning Tree Protocol topology change notifications (TCNs) on the switch. STP topology changes cause the switch to flush its MAC address table and temporarily flood traffic, which degrades network performance. While some TCNs are expected during maintenance, unexpected changes may indicate physical link failures, misconfigurations, or deliberate STP manipulation.
  SOC analysts should correlate STP topology changes with other events because they can be a side effect of physical intrusion, unauthorized device connections, or deliberate network attacks.
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
  - T1498
query: |
  // Lookback: 24 hours for STP topology change events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match all STP topology change related EMS messages
  | where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.SendClntTopoChgMsg")
  // Parse severity and component from structured EMS format
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Extract the STP domain name for context
  | extend StpDomain = extract(@"\[([^\]]+)\]", 1, SyslogMessage)
  | project TimeGenerated, HostName, Severity, Component, StpDomain, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Component: Component
  StpDomain: StpDomain
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — STP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — STP TCN Events (Knowledge Base)](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000081945)
- [Extreme Networks — STP EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
