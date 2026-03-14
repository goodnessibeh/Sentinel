**Author:** Goodness Caleb Ibeh

# Port Security Violation Surge

Detects a surge of multiple port security violations occurring on a single switch within a short time window. When many MAC lock, learning limit, and MAC tracking violations fire simultaneously, it typically indicates a coordinated attack such as MAC flooding or a large-scale unauthorized device deployment rather than isolated incidents.

**Importance:** SOC analysts should treat a surge of port security violations as a high-priority event because it suggests an active, ongoing attack against the network switching infrastructure.

**MITRE:** T1557 — Adversary-in-the-Middle

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |

```kql
// Reference: ExtremeXOS EMS — FDB.MacLocking / FDB.LrnLimit / FDB.MACTracking — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 15-minute window for detecting violation surges
let lookback = 15m;
// Threshold: more than 10 violations in 5 minutes triggers alert
let threshold = 10;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match all port security violation types
| where SyslogMessage has_any ("FDB.MacLocking", "FDB.LrnLimit", "FDB.MACTracking")
// Parse component from the EMS message for categorization
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Aggregate all violations per switch in 5-minute bins to detect surges
| summarize
    ViolationCount = count(),
    Components = make_set(Component, 5),
    Messages = make_set(SyslogMessage, 10)
  by HostName, bin(TimeGenerated, 5m)
// Detection logic: only alert when violations exceed threshold
| where ViolationCount > threshold
| project TimeGenerated, HostName, ViolationCount, Components, Messages
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 64f98c78-0071-4df7-b4f6-0ac26bb76c0f
name: "Port Security Violation Surge"
description: |
  Detects a surge of multiple port security violations occurring on a single switch within a short time window. When many MAC lock, learning limit, and MAC tracking violations fire simultaneously, it typically indicates a coordinated attack such as MAC flooding or a large-scale unauthorized device deployment rather than isolated incidents.
  SOC analysts should treat a surge of port security violations as a high-priority event because it suggests an active, ongoing attack against the network switching infrastructure.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
queryFrequency: 15m
queryPeriod: 15m
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CredentialAccess
relevantTechniques:
  - T1557
query: |
  // Lookback: 15-minute window for detecting violation surges
  let lookback = 15m;
  // Threshold: more than 10 violations in 5 minutes triggers alert
  let threshold = 10;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match all port security violation types
  | where SyslogMessage has_any ("FDB.MacLocking", "FDB.LrnLimit", "FDB.MACTracking")
  // Parse component from the EMS message for categorization
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Aggregate all violations per switch in 5-minute bins to detect surges
  | summarize
      ViolationCount = count(),
      Components = make_set(Component, 5),
      Messages = make_set(SyslogMessage, 10)
    by HostName, bin(TimeGenerated, 5m)
  // Detection logic: only alert when violations exceed threshold
  | where ViolationCount > threshold
  | project TimeGenerated, HostName, ViolationCount, Components, Messages

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
customDetails:
  ViolationCount: ViolationCount
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — MAC Locking Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-19173DB1-1312-4576-BB1E-CA8A224AE14F.shtml)
- [Extreme Networks — MAC Learning Limit (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — FDB EMS Messages (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.2)](https://documentation.extremenetworks.com/ems_catalog_31.2/GUID-6C7DD8DA-F85E-4313-BFC5-742485964DCC.shtml)
