**Author:** Goodness Caleb Ibeh

# Port Mirroring Configuration Change

Detects when port mirroring is configured, enabled, or disabled on the switch. Port mirroring duplicates traffic from one or more ports to a monitoring port, and while it is a legitimate tool for network troubleshooting, unauthorized port mirroring is a primary technique for traffic interception and data exfiltration. An attacker with switch access can mirror sensitive traffic to a port connected to their capture device.

**Importance:** SOC analysts must investigate port mirroring changes as unauthorized mirroring is a direct indicator of traffic interception and potential data exfiltration.

**MITRE:** T1040 — Network Sniffing

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd (mirror) / HAL.Mirror — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for port mirroring configuration changes
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match CLI commands related to port mirroring or HAL mirror events
| where (SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
    and SyslogMessage has_any (
        "mirror", "port-mirror", "mirroring",
        "configure mirror", "enable mirror", "disable mirror",
        "create mirror", "delete mirror",
        "monitor port", "analyzer port"
    ))
    or SyslogMessage has "HAL.Mirror"
// Classify the action type for quick triage
| extend Action = case(
    SyslogMessage has_any ("disable", "delete"), "DISABLED/DELETED",
    SyslogMessage has_any ("enable", "create"), "ENABLED/CREATED",
    SyslogMessage has "configure", "MODIFIED",
    "CHANGED"
  )
| project TimeGenerated, HostName, Action, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 060f6dc1-4ce8-47a4-b960-71418846c3b3
name: "Port Mirroring Configuration Change"
description: |
  Detects when port mirroring is configured, enabled, or disabled on the switch. Port mirroring duplicates traffic from one or more ports to a monitoring port, and while it is a legitimate tool for network troubleshooting, unauthorized port mirroring is a primary technique for traffic interception and data exfiltration. An attacker with switch access can mirror sensitive traffic to a port connected to their capture device.
  SOC analysts must investigate port mirroring changes as unauthorized mirroring is a direct indicator of traffic interception and potential data exfiltration.
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
  - CredentialAccess
relevantTechniques:
  - T1040
query: |
  // Lookback: 24 hours for port mirroring configuration changes
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match CLI commands related to port mirroring or HAL mirror events
  | where (SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd", "cm.CLILog")
      and SyslogMessage has_any (
          "mirror", "port-mirror", "mirroring",
          "configure mirror", "enable mirror", "disable mirror",
          "create mirror", "delete mirror",
          "monitor port", "analyzer port"
      ))
      or SyslogMessage has "HAL.Mirror"
  // Classify the action type for quick triage
  | extend Action = case(
      SyslogMessage has_any ("disable", "delete"), "DISABLED/DELETED",
      SyslogMessage has_any ("enable", "create"), "ENABLED/CREATED",
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

- [Extreme Networks — Mirror Port Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
