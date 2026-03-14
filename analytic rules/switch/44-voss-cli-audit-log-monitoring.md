**Author:** Goodness Caleb Ibeh

# VOSS CLI Audit Log Monitoring

Monitors all CLI commands executed on VOSS (Virtual Services Platform Operating System) switches via the CLILOG facility. VOSS uses a different logging format than ExtremeXOS, so this detection uses a broader filter. Every command entered by an administrator is logged, providing a complete audit trail for forensic analysis and compliance. This is the VOSS equivalent of detection #26 for ExtremeXOS.

**Importance:** SOC analysts should review VOSS CLI audit logs to detect unauthorized configuration changes, backdoor creation, or security feature disablement on VOSS-based switches.

**MITRE:** T1059 — Command and Scripting Interpreter

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: Extreme Networks VOSS — CLILOG — https://documentation.extremenetworks.com/VOSS/VSP8600/SW/80x/ConfigLogTech_8.0_VSP86.pdf
// Lookback: 24 hours for VOSS CLI audit events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Key filter: match VOSS CLI log entries (note: no Facility filter — VOSS may use different facilities)
| where SyslogMessage has "CLILOG"
| project TimeGenerated, HostName, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 2100b212-2017-4e26-8acc-1869044091eb
name: "VOSS CLI Audit Log Monitoring"
description: |
  Monitors all CLI commands executed on VOSS (Virtual Services Platform Operating System) switches via the CLILOG facility. VOSS uses a different logging format than ExtremeXOS, so this detection uses a broader filter. Every command entered by an administrator is logged, providing a complete audit trail for forensic analysis and compliance. This is the VOSS equivalent of detection #26 for ExtremeXOS.
  SOC analysts should review VOSS CLI audit logs to detect unauthorized configuration changes, backdoor creation, or security feature disablement on VOSS-based switches.
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
  // Lookback: 24 hours for VOSS CLI audit events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Key filter: match VOSS CLI log entries (note: no Facility filter — VOSS may use different facilities)
  | where SyslogMessage has "CLILOG"
  | project TimeGenerated, HostName, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — VOSS Logging Configuration (VSP 8600)](https://documentation.extremenetworks.com/VOSS/VSP8600/SW/80x/ConfigLogTech_8.0_VSP86.pdf)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
