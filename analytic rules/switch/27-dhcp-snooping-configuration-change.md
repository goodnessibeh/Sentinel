**Author:** Goodness Caleb Ibeh

# DHCP Snooping Configuration Change

Detects when DHCP snooping is enabled, disabled, or modified on the switch. DHCP snooping is a critical network security feature that prevents rogue DHCP servers. Disabling or weakening it exposes the entire VLAN to DHCP spoofing attacks. An attacker with switch access may disable DHCP snooping as a prerequisite to deploying a rogue DHCP server.

**Importance:** SOC analysts must investigate DHCP snooping configuration changes immediately because disabling this feature removes a fundamental Layer 2 security control and enables DHCP-based attacks.

**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd (ip-security) — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for DHCP snooping configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// First filter: match CLI command log events (where config changes are recorded)
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
// Key filter: match DHCP snooping and IP security related commands
| where SyslogMessage has_any (
    "ip-security dhcp-snooping",
    "dhcp-snooping",
    "trusted-server",
    "trusted-port",
    "ip-security",
    "configure ip-security",
    "enable ip-security",
    "disable ip-security",
    "configure trusted-server",
    "configure trusted-port"
  )
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has "disable", "DISABLED",
    SyslogMessage has "enable", "ENABLED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 6edbdc89-d3ba-458f-aab7-44e1994e42dc
name: "DHCP Snooping Configuration Change"
description: |
  Detects when DHCP snooping is enabled, disabled, or modified on the switch. DHCP snooping is a critical network security feature that prevents rogue DHCP servers. Disabling or weakening it exposes the entire VLAN to DHCP spoofing attacks. An attacker with switch access may disable DHCP snooping as a prerequisite to deploying a rogue DHCP server.
  SOC analysts must investigate DHCP snooping configuration changes immediately because disabling this feature removes a fundamental Layer 2 security control and enables DHCP-based attacks.
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
  - DefenseEvasion
relevantTechniques:
  - T1562.001
query: |
  // Lookback: 24 hours for DHCP snooping configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // First filter: match CLI command log events (where config changes are recorded)
  | where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
  // Key filter: match DHCP snooping and IP security related commands
  | where SyslogMessage has_any (
      "ip-security dhcp-snooping",
      "dhcp-snooping",
      "trusted-server",
      "trusted-port",
      "ip-security",
      "configure ip-security",
      "enable ip-security",
      "disable ip-security",
      "configure trusted-server",
      "configure trusted-port"
    )
  // Classify the action type for quick triage
  | extend Action = case(
      SyslogMessage has "disable", "DISABLED",
      SyslogMessage has "enable", "ENABLED",
      SyslogMessage has "configure", "MODIFIED",
      "CHANGED"
    )
  | project TimeGenerated, HostName, Action, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  Action: Action
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — DHCP Snooping Configuration (ExtremeXOS 31.6)](https://documentation.extremenetworks.com/exos_31.6/GUID-71D58AF6-81A3-4DF1-B34E-05D91BEBE2D8.shtml)
- [Extreme Networks — IP Security Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
