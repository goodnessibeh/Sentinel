**Author:** Goodness Caleb Ibeh

# Mass Port Down Event — Potential Cable/Switch Failure

Detects when multiple ports on the same switch go down simultaneously or within a very short time window. A mass port-down event typically indicates a hardware failure (failed line card, power supply issue), a severed cable trunk, or a catastrophic switch failure. It can also indicate a physical attack where an attacker disconnects infrastructure cabling.

**Importance:** SOC analysts should treat mass port-down events as high priority because they indicate either critical infrastructure failure or potential physical sabotage affecting network availability.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — HAL.Port.LinkDown — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 5-minute window for detecting mass port failures
let lookback = 5m;
// Threshold: 5 or more ports going down simultaneously is a mass event
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match port link-down messages only
| where SyslogMessage has_any ("portLinkStateDown", "HAL.Port.LinkDown")
// Extract the port identifier for each down event
| extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
// Aggregate down events per switch in 2-minute bins to detect simultaneous failures
| summarize
    DownCount = count(),
    AffectedPorts = make_set(Port, 50)
  by HostName, bin(TimeGenerated, 2m)
// Detection logic: alert when port-down count reaches threshold
| where DownCount >= threshold
| project TimeGenerated, HostName, DownCount, AffectedPorts
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 527c4597-bf1a-40bb-8873-bc37f4a2472a
name: "Mass Port Down Event — Potential Cable/Switch Failure"
description: |
  Detects when multiple ports on the same switch go down simultaneously or within a very short time window. A mass port-down event typically indicates a hardware failure (failed line card, power supply issue), a severed cable trunk, or a catastrophic switch failure. It can also indicate a physical attack where an attacker disconnects infrastructure cabling.
  SOC analysts should treat mass port-down events as high priority because they indicate either critical infrastructure failure or potential physical sabotage affecting network availability.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 5m
queryPeriod: 5m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 5-minute window for detecting mass port failures
  let lookback = 5m;
  // Threshold: 5 or more ports going down simultaneously is a mass event
  let threshold = 5;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match port link-down messages only
  | where SyslogMessage has_any ("portLinkStateDown", "HAL.Port.LinkDown")
  // Extract the port identifier for each down event
  | extend Port = extract(@"Port\s+(\S+)", 1, SyslogMessage)
  // Aggregate down events per switch in 2-minute bins to detect simultaneous failures
  | summarize
      DownCount = count(),
      AffectedPorts = make_set(Port, 50)
    by HostName, bin(TimeGenerated, 2m)
  // Detection logic: alert when port-down count reaches threshold
  | where DownCount >= threshold
  | project TimeGenerated, HostName, DownCount, AffectedPorts

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  DownCount: DownCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — Link-Flap Detection (ExtremeXOS 30.2)](https://documentation.extremenetworks.com/exos_30.2.2/GUID-657A01D2-799F-4CF7-94FE-29996520AFBA.shtml)
- [Extreme Networks — HAL Port EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
