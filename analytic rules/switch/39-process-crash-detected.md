**Author:** Goodness Caleb Ibeh

# Process Crash Detected

Detects when a software process crashes or is unexpectedly stopped on the switch. Process crashes can affect switch functionality ranging from losing specific protocol support to a complete management plane failure. Crashes may be caused by software bugs, resource exhaustion, or deliberate exploitation of vulnerabilities in switch software. Repeated crashes of the same process may indicate an active exploit attempt.

**Importance:** SOC analysts should investigate process crashes because they may indicate exploitation of a switch vulnerability or denial-of-service attack against the switch's control plane.

**MITRE:** T1499 — Endpoint Denial of Service

**Severity:** Critical

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — epm.ProcCrash / epm.ProcStop — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for process crash events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match process crash and unexpected stop events
| where SyslogMessage has_any ("epm.ProcCrash", "epm.ProcStop")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Extract the name of the crashed process for triage
| extend ProcessName = extract(@"Process\s+(\S+)", 1, Rest)
| project TimeGenerated, HostName, Severity, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 58b25e25-7bd9-46ac-bc26-1b6eb78a20e8
name: "Process Crash Detected"
description: |
  Detects when a software process crashes or is unexpectedly stopped on the switch. Process crashes can affect switch functionality ranging from losing specific protocol support to a complete management plane failure. Crashes may be caused by software bugs, resource exhaustion, or deliberate exploitation of vulnerabilities in switch software. Repeated crashes of the same process may indicate an active exploit attempt.
  SOC analysts should investigate process crashes because they may indicate exploitation of a switch vulnerability or denial-of-service attack against the switch's control plane.
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
  - Impact
relevantTechniques:
  - T1499
query: |
  // Lookback: 24 hours for process crash events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match process crash and unexpected stop events
  | where SyslogMessage has_any ("epm.ProcCrash", "epm.ProcStop")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Extract the name of the crashed process for triage
  | extend ProcessName = extract(@"Process\s+(\S+)", 1, Rest)
  | project TimeGenerated, HostName, Severity, ProcessName, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  ProcessName: ProcessName
  Severity: Severity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Process Manager (EPM) (ExtremeXOS 22.5)](https://documentation.extremenetworks.com/exos_22.5/GUID-0353BCE6-5198-40D6-8E2A-31C8115FD13F.shtml)
- [Extreme Networks — EMS Severity Levels (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-D3F3B734-61C5-4F78-A6C6-198B56174DE2.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
