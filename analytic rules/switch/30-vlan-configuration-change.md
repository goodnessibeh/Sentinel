**Author:** Goodness Caleb Ibeh

# VLAN Configuration Change

Detects when VLANs are created, deleted, or modified on the switch, including port membership changes. VLAN manipulation is a key technique in VLAN hopping attacks and network segmentation bypass. An attacker who modifies VLAN configuration can move ports between VLANs to gain access to restricted network segments, or remove VLAN isolation entirely.

**Importance:** SOC analysts should monitor VLAN changes because unauthorized modifications can break network segmentation and expose sensitive network zones to unauthorized access.

**MITRE:** T1599 — Network Boundary Bridging

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd (vlan) — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for VLAN configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match VLAN-related configuration commands
| where SyslogMessage has_any (
    "create vlan", "delete vlan", "configure vlan",
    "add vlan", "add ports", "delete ports",
    "vlan tag", "vlan untag",
    "configure vlan-translation",
    "enable vlan", "disable vlan"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "delete", "DELETED",
    SyslogMessage has "create", "CREATED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| extend
    AlertTitle = "VLAN Configuration Change",
    AlertDescription = "VLANs were created, deleted, or modified on the switch, which may break network segmentation or enable VLAN hopping attacks.",
    AlertSeverity = "Medium"
| project TimeGenerated, HostName, Action, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 06566e32-3faf-4ced-a712-97ca4a5fd48e
name: "VLAN Configuration Change"
description: |
  Detects when VLANs are created, deleted, or modified on the switch, including port membership changes. VLAN manipulation is a key technique in VLAN hopping attacks and network segmentation bypass. An attacker who modifies VLAN configuration can move ports between VLANs to gain access to restricted network segments, or remove VLAN isolation entirely.
  SOC analysts should monitor VLAN changes because unauthorized modifications can break network segmentation and expose sensitive network zones to unauthorized access.
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
  - DefenseEvasion
relevantTechniques:
  - T1599
query: |
  // Lookback: 24 hours for VLAN configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // First filter: match CLI command log events
  | where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
  // Key filter: match VLAN-related configuration commands
  | where SyslogMessage has_any (
      "create vlan", "delete vlan", "configure vlan",
      "add vlan", "add ports", "delete ports",
      "vlan tag", "vlan untag",
      "configure vlan-translation",
      "enable vlan", "disable vlan"
    )
  // Classify the action type for quick triage
  | extend Action = case(
      SyslogMessage has "delete", "DELETED",
      SyslogMessage has "create", "CREATED",
      SyslogMessage has "configure", "MODIFIED",
      "CHANGED"
    )
  | extend
      AlertTitle = "VLAN Configuration Change",
      AlertDescription = "VLANs were created, deleted, or modified on the switch, which may break network segmentation or enable VLAN hopping attacks.",
      AlertSeverity = "Medium"
  | project TimeGenerated, HostName, Action, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
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
  Action: Action
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Configuration Management (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
