**Author:** Goodness Caleb Ibeh

# CLI Command Audit — Remote Commands

Audits CLI commands executed on the switch, distinguishing between remote (SSH/Telnet) and local (console) sessions. Remote command execution is the primary method attackers use after gaining switch access. Monitoring all commands provides forensic evidence and enables detection of destructive or suspicious commands such as disabling security features, creating backdoor accounts, or modifying ACLs.

**Importance:** SOC analysts should review CLI command audits to detect post-compromise activity such as security feature disablement, backdoor creation, or configuration tampering.

**MITRE:** T1059 — Command and Scripting Interpreter

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — CLI.logRemoteCmd / CLI.logLocalCmd — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for CLI command audit events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match remote and local CLI command log events
| where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Classify as remote vs local for risk assessment (remote is higher risk)
| extend CommandType = iff(SyslogMessage has "Remote", "Remote", "Local")
| project TimeGenerated, HostName, CommandType, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 6911fcae-b495-4375-b566-67ee6f556074
name: "CLI Command Audit — Remote Commands"
description: |
  Audits CLI commands executed on the switch, distinguishing between remote (SSH/Telnet) and local (console) sessions. Remote command execution is the primary method attackers use after gaining switch access. Monitoring all commands provides forensic evidence and enables detection of destructive or suspicious commands such as disabling security features, creating backdoor accounts, or modifying ACLs.
  SOC analysts should review CLI command audits to detect post-compromise activity such as security feature disablement, backdoor creation, or configuration tampering.
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
  - Execution
relevantTechniques:
  - T1059
query: |
  // Lookback: 24 hours for CLI command audit events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match remote and local CLI command log events
  | where SyslogMessage has_any ("CLI.logRemoteCmd", "CLI.logLocalCmd")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Classify as remote vs local for risk assessment (remote is higher risk)
  | extend CommandType = iff(SyslogMessage has "Remote", "Remote", "Local")
  | project TimeGenerated, HostName, CommandType, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  CommandType: CommandType
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — CLI Logging Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — Log Filter Commands (ExtremeXOS 31.7)](https://documentation.extremenetworks.com/exos_commands_31.7/GUID-6C70A09B-FE41-4692-912F-7512C10926D2.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
