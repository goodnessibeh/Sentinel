**Author:** Goodness Caleb Ibeh

# STP Configuration Change

Detects when STP configuration is modified, including changes to bridge priority, BPDU guard settings, root guard, or enabling/disabling STP entirely. STP configuration changes are high-risk because they directly affect the Layer 2 forwarding topology. An attacker may lower the bridge priority to become the root bridge, disable BPDU guard to allow their injected BPDUs, or disable STP entirely to create loops.

**Importance:** SOC analysts should investigate STP configuration changes immediately because they can be precursors to STP manipulation attacks or may indicate an attacker weakening Layer 2 security controls.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd (stpd) — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for STP configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match STP-related configuration commands
| where SyslogMessage has_any (
    "stpd", "spanning-tree", "stp",
    "configure stpd", "enable stpd", "disable stpd",
    "bpdu-guard", "bpdu-restrict", "bpdu-filter",
    "loop-protect", "edge-safeguard",
    "priority", "root-guard",
    "create stpd", "delete stpd"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "disable", "DISABLED",
    SyslogMessage has "enable", "ENABLED",
    SyslogMessage has "configure", "MODIFIED",
    SyslogMessage has "delete", "DELETED",
    SyslogMessage has "create", "CREATED",
    "CHANGED"
  )
| extend
    AlertTitle = "STP Configuration Change",
    AlertDescription = "STP configuration was modified on the switch, which may weaken Layer 2 security controls or enable STP manipulation attacks.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, Action, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b9815417-4061-4a3b-ad49-05afa3d1f808
name: "STP Configuration Change"
description: |
  Detects when STP configuration is modified, including changes to bridge priority, BPDU guard settings, root guard, or enabling/disabling STP entirely. STP configuration changes are high-risk because they directly affect the Layer 2 forwarding topology. An attacker may lower the bridge priority to become the root bridge, disable BPDU guard to allow their injected BPDUs, or disable STP entirely to create loops.
  SOC analysts should investigate STP configuration changes immediately because they can be precursors to STP manipulation attacks or may indicate an attacker weakening Layer 2 security controls.
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
  - DefenseEvasion
relevantTechniques:
  - T1562.001
query: |
  // Lookback: 24 hours for STP configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // First filter: match CLI command log events
  | where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
  // Key filter: match STP-related configuration commands
  | where SyslogMessage has_any (
      "stpd", "spanning-tree", "stp",
      "configure stpd", "enable stpd", "disable stpd",
      "bpdu-guard", "bpdu-restrict", "bpdu-filter",
      "loop-protect", "edge-safeguard",
      "priority", "root-guard",
      "create stpd", "delete stpd"
    )
  // Classify the action type for quick triage
  | extend Action = case(
      SyslogMessage has "disable", "DISABLED",
      SyslogMessage has "enable", "ENABLED",
      SyslogMessage has "configure", "MODIFIED",
      SyslogMessage has "delete", "DELETED",
      SyslogMessage has "create", "CREATED",
      "CHANGED"
    )
  | extend
      AlertTitle = "STP Configuration Change",
      AlertDescription = "STP configuration was modified on the switch, which may weaken Layer 2 security controls or enable STP manipulation attacks.",
      AlertSeverity = "High"
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

- [Extreme Networks — STP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
