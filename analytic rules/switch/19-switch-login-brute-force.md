**Author:** Goodness Caleb Ibeh

# Switch Login Brute Force

Detects multiple failed authentication attempts against the switch management interface from a single source IP address within a short time window. Brute force attacks against network infrastructure are particularly dangerous because compromising a switch grants the attacker the ability to reconfigure VLANs, mirror traffic, disable security features, and pivot deeper into the network.

**Importance:** SOC analysts should prioritize switch brute force alerts because network device compromise provides attackers with privileged access to intercept and manipulate all traffic traversing the switch.

**MITRE:** T1110 — Brute Force

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | SourceIP |
| Account | Name | Users |

```kql
// Reference: ExtremeXOS EMS — AAA.authFail — https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml
// Lookback: 30-minute window for detecting brute force patterns
let lookback = 30m;
// Threshold: 5 or more failures from the same source is brute force
let threshold = 5;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match authentication failure events
| where SyslogMessage has "AAA.authFail"
// Extract user, authentication method, and source IP from the message
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
| extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Aggregate failures per source IP per target switch to detect brute force patterns
| summarize
    FailCount = count(),
    Users = make_set(User, 10),
    Methods = make_set(Method, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
  by HostName, SourceIP
// Detection logic: alert when failure count reaches brute force threshold
| where FailCount >= threshold
| project HostName, SourceIP, FailCount, Users, Methods, FirstAttempt, LastAttempt
| order by FailCount desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 2cca9a1d-0db5-4894-8644-705b959f0062
name: "Switch Login Brute Force"
description: |
  Detects multiple failed authentication attempts against the switch management interface from a single source IP address within a short time window. Brute force attacks against network infrastructure are particularly dangerous because compromising a switch grants the attacker the ability to reconfigure VLANs, mirror traffic, disable security features, and pivot deeper into the network.
  SOC analysts should prioritize switch brute force alerts because network device compromise provides attackers with privileged access to intercept and manipulate all traffic traversing the switch.
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
  - CredentialAccess
relevantTechniques:
  - T1110
query: |
  // Lookback: 30-minute window for detecting brute force patterns
  let lookback = 30m;
  // Threshold: 5 or more failures from the same source is brute force
  let threshold = 5;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match authentication failure events
  | where SyslogMessage has "AAA.authFail"
  // Extract user, authentication method, and source IP from the message
  | extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
  | extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
  | extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  // Aggregate failures per source IP per target switch to detect brute force patterns
  | summarize
      FailCount = count(),
      Users = make_set(User, 10),
      Methods = make_set(Method, 5),
      FirstAttempt = min(TimeGenerated),
      LastAttempt = max(TimeGenerated)
    by HostName, SourceIP
  // Detection logic: alert when failure count reaches brute force threshold
  | where FailCount >= threshold
  | project HostName, SourceIP, FailCount, Users, Methods, FirstAttempt, LastAttempt
  | order by FailCount desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Users
customDetails:
  SourceIP: SourceIP
  FailCount: FailCount
  Users: Users
  Methods: Methods
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — RADIUS/TACACS+ Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
