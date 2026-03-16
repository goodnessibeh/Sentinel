**Author:** Goodness Caleb Ibeh

# RADIUS/TACACS+ Authentication Events

Monitors authentication events that are directed to external RADIUS or TACACS+ servers for centralized authentication. Tracking which authentication servers are handling requests and which users are authenticating helps establish baselines and detect anomalies such as failover to a backup server, authentication to an unexpected server, or a sudden spike in authentication requests that may indicate credential stuffing.

**Importance:** SOC analysts should track RADIUS/TACACS+ events to ensure authentication is flowing to expected servers and to detect anomalies in authentication patterns.

**MITRE:** T1078 — Valid Accounts

**Severity:** Low

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | Name | Users |

```kql
// Reference: ExtremeXOS EMS — AAA.usingRadius / AAA.usingTacacs — https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml
// Lookback: 24 hours for external authentication events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match RADIUS and TACACS+ authentication events
| where SyslogMessage has_any ("AAA.usingRadius", "AAA.usingTacacs")
// Extract the authentication server and user from the message
| extend AuthServer = extract(@"server\s+(\S+)", 1, SyslogMessage)
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
// Aggregate authentication attempts per server per hour for trend analysis
| summarize
    AuthAttempts = count(),
    Users = make_set(User, 20),
    Switches = make_set(HostName, 20)
  by AuthServer, bin(TimeGenerated, 1h)
| extend
    AlertTitle = "RADIUS/TACACS+ Authentication Events",
    AlertDescription = "Authentication events directed to external RADIUS or TACACS+ servers detected, useful for baseline monitoring and anomaly detection.",
    AlertSeverity = "Low"
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 55530de9-2a42-41d2-8ea6-accf350130ce
name: "RADIUS/TACACS+ Authentication Events"
description: |
  Monitors authentication events that are directed to external RADIUS or TACACS+ servers for centralized authentication. Tracking which authentication servers are handling requests and which users are authenticating helps establish baselines and detect anomalies such as failover to a backup server, authentication to an unexpected server, or a sudden spike in authentication requests that may indicate credential stuffing.
  SOC analysts should track RADIUS/TACACS+ events to ensure authentication is flowing to expected servers and to detect anomalies in authentication patterns.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Low
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
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  // Lookback: 24 hours for external authentication events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match RADIUS and TACACS+ authentication events
  | where SyslogMessage has_any ("AAA.usingRadius", "AAA.usingTacacs")
  // Extract the authentication server and user from the message
  | extend AuthServer = extract(@"server\s+(\S+)", 1, SyslogMessage)
  | extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
  // Aggregate authentication attempts per server per hour for trend analysis
  | summarize
      AuthAttempts = count(),
      Users = make_set(User, 20),
      Switches = make_set(HostName, 20)
    by AuthServer, bin(TimeGenerated, 1h)
  | extend
      AlertTitle = "RADIUS/TACACS+ Authentication Events",
      AlertDescription = "Authentication events directed to external RADIUS or TACACS+ servers detected, useful for baseline monitoring and anomaly detection.",
      AlertSeverity = "Low"

alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Users
customDetails:
  AuthServer: AuthServer
  AuthAttempts: AuthAttempts
  Users: Users
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — RADIUS/TACACS+ Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
