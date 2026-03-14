**Author:** Goodness Caleb Ibeh

# Excessive STP Topology Changes — Network Instability

Detects when an unusually high number of STP topology changes occur on a single switch within a short time window. Excessive topology changes cause repeated MAC table flushes and traffic flooding, leading to severe network degradation. This pattern may indicate a deliberate STP DoS attack, a flapping link, or a misconfigured device sending rapid BPDUs.

**Importance:** SOC analysts should escalate excessive STP topology changes because they indicate either an active Layer 2 attack or a hardware/configuration issue causing significant network instability.

**MITRE:** T1498 — Network Denial of Service

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — STP.State.Topology / STP.State.RootChg — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 30-minute window for detecting excessive topology changes
let lookback = 30m;
// Threshold: more than 5 topology changes in 10 minutes is abnormal
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all STP topology and root change events
| where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.State.RootChg")
// Aggregate topology change events per switch in 10-minute bins
| summarize
    TCNCount = count(),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 10m)
// Detection logic: alert only when count exceeds threshold
| where TCNCount > threshold
| project TimeGenerated, HostName, TCNCount, Messages
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: fdfce5bd-f5e9-44d3-a027-0894dee8e0bf
name: "Excessive STP Topology Changes — Network Instability"
description: |
  Detects when an unusually high number of STP topology changes occur on a single switch within a short time window. Excessive topology changes cause repeated MAC table flushes and traffic flooding, leading to severe network degradation. This pattern may indicate a deliberate STP DoS attack, a flapping link, or a misconfigured device sending rapid BPDUs.
  SOC analysts should escalate excessive STP topology changes because they indicate either an active Layer 2 attack or a hardware/configuration issue causing significant network instability.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 30m
queryPeriod: 30m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1498
query: |
  // Lookback: 30-minute window for detecting excessive topology changes
  let lookback = 30m;
  // Threshold: more than 5 topology changes in 10 minutes is abnormal
  let threshold = 5;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match all STP topology and root change events
  | where SyslogMessage has_any ("STP.State.Topology", "STP.InTopChg", "STP.State.RootChg")
  // Aggregate topology change events per switch in 10-minute bins
  | summarize
      TCNCount = count(),
      Messages = make_set(SyslogMessage, 10)
    by HostName, bin(TimeGenerated, 10m)
  // Detection logic: alert only when count exceeds threshold
  | where TCNCount > threshold
  | project TimeGenerated, HostName, TCNCount, Messages

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  TCNCount: TCNCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — STP Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — STP TCN Events (Knowledge Base)](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000081945)
- [Extreme Networks — STP EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
