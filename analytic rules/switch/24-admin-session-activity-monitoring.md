**Author:** Goodness Caleb Ibeh

# Admin Session Activity Monitoring

Monitors administrative session lifecycle events including logins, logouts, connections, and disconnections to the switch management interface. This provides an audit trail of who accessed the switch and when, enabling detection of unusual access patterns such as sessions at odd hours, unusually long sessions, or sessions from unexpected users.

**Importance:** SOC analysts should review admin session activity to maintain an accurate audit trail and detect unauthorized or suspicious administrative access patterns.

**MITRE:** T1078 — Valid Accounts

**Severity:** Informational

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| Account | Name | User |

```kql
// Reference: ExtremeXOS EMS — AAA.authPass / AAA.logout / CLI.connect — https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml
// Lookback: 24 hours for admin session events
let lookback = 24h;
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match session lifecycle events (connect, disconnect, auth, logout)
| where SyslogMessage has_any ("CLI.connect", "CLI.disconnect", "AAA.authPass", "AAA.logout")
// Parse severity and component from the EMS message
| parse SyslogMessage with * "<" Severity ":" Component ">" Rest
// Classify the event type based on component for easier analysis
| extend EventType = case(
    Component has "connect" or Component has "authPass", "SessionStart",
    Component has "disconnect" or Component has "logout", "SessionEnd",
    "Other"
  )
// Extract the username associated with the session
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| project TimeGenerated, HostName, User, EventType, Component, SyslogMessage
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 9a1d5fd3-45ca-49e1-9def-2876bfab3b0b
name: "Admin Session Activity Monitoring"
description: |
  Monitors administrative session lifecycle events including logins, logouts, connections, and disconnections to the switch management interface. This provides an audit trail of who accessed the switch and when, enabling detection of unusual access patterns such as sessions at odd hours, unusually long sessions, or sessions from unexpected users.
  SOC analysts should review admin session activity to maintain an accurate audit trail and detect unauthorized or suspicious administrative access patterns.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: Informational
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
  // Lookback: 24 hours for admin session events
  let lookback = 24h;
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match session lifecycle events (connect, disconnect, auth, logout)
  | where SyslogMessage has_any ("CLI.connect", "CLI.disconnect", "AAA.authPass", "AAA.logout")
  // Parse severity and component from the EMS message
  | parse SyslogMessage with * "<" Severity ":" Component ">" Rest
  // Classify the event type based on component for easier analysis
  | extend EventType = case(
      Component has "connect" or Component has "authPass", "SessionStart",
      Component has "disconnect" or Component has "logout", "SessionEnd",
      "Other"
    )
  // Extract the username associated with the session
  | extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
  | project TimeGenerated, HostName, User, EventType, Component, SyslogMessage
  | order by TimeGenerated desc

entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: User
customDetails:
  User: User
  EventType: EventType
  Component: Component
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — SSH / exsshd Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
