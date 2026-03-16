**Author:** Goodness Caleb Ibeh

# Critical/Error System Events

Detects all Critical and Error severity events from the switch, providing a catch-all for system issues that may not be covered by more specific detections. These events represent the highest severity conditions reported by the switch operating system and can include hardware failures, memory exhaustion, firmware errors, and other conditions that threaten switch stability or security.

**Importance:** SOC analysts should review critical and error events as a catch-all to ensure no significant system issues are missed by the more targeted detection rules.

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — Severity Crit/Erro — https://documentation.extremenetworks.com/exos_31.5/GUID-D3F3B734-61C5-4F78-A6C6-198B56174DE2.shtml
// Lookback: 24 hours for critical and error system events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match messages with Critical or Error severity prefixes
| where SyslogMessage has_any ("<Crit:", "<Erro:")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate events per host/severity per hour to identify patterns and volume
| summarize
    EventCount = count(),
    Components = make_set(Component, 10),
    SampleMessages = make_set(SyslogMessage, 5)
  by HostName, Severity, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "Critical/Error System Events",
    AlertDescription = "Critical or Error severity system events detected from the switch, indicating potential hardware failures or conditions threatening switch stability.",
    AlertSeverity = "High"
| order by EventCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 70113ae0-3078-433a-a717-3fb3cbe406aa
name: "Critical/Error System Events"
description: |
  Detects all Critical and Error severity events from the switch, providing a catch-all for system issues that may not be covered by more specific detections. These events represent the highest severity conditions reported by the switch operating system and can include hardware failures, memory exhaustion, firmware errors, and other conditions that threaten switch stability or security.
  SOC analysts should review critical and error events as a catch-all to ensure no significant system issues are missed by the more targeted detection rules.
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
  - T1499
query: |
  // Lookback: 24 hours for critical and error system events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match messages with Critical or Error severity prefixes
  | where SyslogMessage has_any ("<Crit:", "<Erro:")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Aggregate events per host/severity per hour to identify patterns and volume
  | summarize
      EventCount = count(),
      Components = make_set(Component, 10),
      SampleMessages = make_set(SyslogMessage, 5)
    by HostName, Severity, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "Critical/Error System Events",
      AlertDescription = "Critical or Error severity system events detected from the switch, indicating potential hardware failures or conditions threatening switch stability.",
      AlertSeverity = "High"
  | order by EventCount desc

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
  EventCount: EventCount
  Severity: Severity
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — EMS Severity Levels (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-D3F3B734-61C5-4F78-A6C6-198B56174DE2.shtml)
- [Extreme Networks — Syslog Severity Mapping (Knowledge Base)](https://extreme-networks.my.site.com/ExtrArticleDetail?n=000005865)
- [Extreme Networks — Process Manager (EPM) (ExtremeXOS 22.5)](https://documentation.extremenetworks.com/exos_22.5/GUID-0353BCE6-5198-40D6-8E2A-31C8115FD13F.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
