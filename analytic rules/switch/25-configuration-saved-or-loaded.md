**Author:** Goodness Caleb Ibeh

# Configuration Saved or Loaded

Detects when a switch configuration is saved to persistent storage or when a new configuration file is loaded. Configuration saves typically follow administrative changes, while configuration loads may indicate a device restore, firmware upgrade, or an attacker loading a modified configuration to establish persistence or alter security settings.

**Importance:** SOC analysts should correlate configuration save/load events with authorized change windows to detect unauthorized configuration modifications.

**MITRE:** T1565 — Data Manipulation

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — cm.SaveCfg / cm.UseCfg — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for configuration save/load events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match configuration save, use, and file operation events
| where SyslogMessage has_any ("cm.SaveCfg", "cm.UseCfg", "cm.fileOps")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
| project TimeGenerated, HostName, Severity, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 964dc88a-4b19-4f7a-b96e-8147d820cf52
name: "Configuration Saved or Loaded"
description: |
  Detects when a switch configuration is saved to persistent storage or when a new configuration file is loaded. Configuration saves typically follow administrative changes, while configuration loads may indicate a device restore, firmware upgrade, or an attacker loading a modified configuration to establish persistence or alter security settings.
  SOC analysts should correlate configuration save/load events with authorized change windows to detect unauthorized configuration modifications.
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
  - T1565
query: |
  // Lookback: 24 hours for configuration save/load events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match configuration save, use, and file operation events
  | where SyslogMessage has_any ("cm.SaveCfg", "cm.UseCfg", "cm.fileOps")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  | project TimeGenerated, HostName, Severity, Component, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Component: Component
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Configuration Management (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Event Configuration (ExtremeXOS 30.7)](https://documentation.extremenetworks.com/exos_30.7/GUID-AE091E7C-851A-462B-BFAE-D0FA9E6F98BD.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
