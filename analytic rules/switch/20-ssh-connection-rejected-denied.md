**Author:** Goodness Caleb Ibeh

# SSH Connection Rejected/Denied

Detects rejected or denied SSH connection attempts to the switch management interface. SSH rejections occur when connections are denied due to access control lists, maximum session limits, or authentication failures at the SSH protocol level (before AAA). Tracking these events helps identify reconnaissance activity and unauthorized access attempts targeting network infrastructure.

**Importance:** SOC analysts should monitor SSH rejections as they may reveal scanning activity or an attacker probing the network for accessible management interfaces.

**MITRE:** T1110 — Brute Force

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |

```kql
// Reference: ExtremeXOS EMS — exsshd.RejctConnAccessDeny / exsshd.AuthFail — https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml
// Lookback: 24 hours for SSH rejection events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match SSH rejection and authentication failure messages
| where SyslogMessage has_any ("exsshd.RejctConnAccessDeny", "exsshd.AuthFail")
// Extract the source IP of the rejected connection
| extend SourceIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Aggregate rejections per source IP per hour to detect persistent attackers
| summarize
    RejectCount = count(),
    Switches = make_set(HostName, 10)
  by SourceIP, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "SSH Connection Rejected/Denied",
    AlertDescription = "SSH connection attempts to the switch management interface were rejected or denied, indicating potential reconnaissance or unauthorized access attempts.",
    AlertSeverity = "Medium"
| order by RejectCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 762b3217-32ae-45c5-a929-41cd0a64f61b
name: "SSH Connection Rejected/Denied"
description: |
  Detects rejected or denied SSH connection attempts to the switch management interface. SSH rejections occur when connections are denied due to access control lists, maximum session limits, or authentication failures at the SSH protocol level (before AAA). Tracking these events helps identify reconnaissance activity and unauthorized access attempts targeting network infrastructure.
  SOC analysts should monitor SSH rejections as they may reveal scanning activity or an attacker probing the network for accessible management interfaces.
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
  - CredentialAccess
relevantTechniques:
  - T1110
query: |
  // Lookback: 24 hours for SSH rejection events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match SSH rejection and authentication failure messages
  | where SyslogMessage has_any ("exsshd.RejctConnAccessDeny", "exsshd.AuthFail")
  // Extract the source IP of the rejected connection
  | extend SourceIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  // Aggregate rejections per source IP per hour to detect persistent attackers
  | summarize
      RejectCount = count(),
      Switches = make_set(HostName, 10)
    by SourceIP, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "SSH Connection Rejected/Denied",
      AlertDescription = "SSH connection attempts to the switch management interface were rejected or denied, indicating potential reconnaissance or unauthorized access attempts.",
      AlertSeverity = "Medium"
  | order by RejectCount desc

alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  SourceIP: SourceIP
  RejectCount: RejectCount
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — SSH / exsshd Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
