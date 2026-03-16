**Author:** Goodness Caleb Ibeh

# Successful Login from Unexpected Source

Detects successful authentication to the switch management interface from IP addresses outside the defined management network subnets. Legitimate switch administration should only originate from designated management networks. A successful login from an unexpected source may indicate credential theft, a compromised jump host, or an attacker who has gained valid credentials through phishing or other means.

**Importance:** SOC analysts should investigate unexpected source logins urgently because they indicate an attacker with valid credentials accessing network infrastructure from an unauthorized location.

**MITRE:** T1078 — Valid Accounts

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | HostName |
| IP | Address | SourceIP |
| Account | Name | User |

```kql
// Reference: ExtremeXOS EMS — AAA.authPass — https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml
// Lookback: 24 hours for successful authentication events
let lookback = 24h;
// Define allowed management subnets — customize for your environment
let AllowedMgmtSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
Syslog
| where TimeGenerated > ago(lookback)
// Filter to Extreme Networks switch logs
| where Facility == "local7"
// Key filter: match successful authentication events
| where SyslogMessage has "AAA.authPass"
// Extract user, authentication method, and source IP
| extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
| extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
| extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
// Only evaluate events with a parseable source IP
| where isnotempty(SourceIP)
// Detection logic: flag logins from IPs NOT in approved management subnets
| where not(ipv4_is_in_any_range(SourceIP, AllowedMgmtSubnets))
| extend
    AlertTitle = "Successful Login from Unexpected Source",
    AlertDescription = "Successful authentication to the switch management interface detected from an IP address outside the defined management subnets.",
    AlertSeverity = "High"
| project TimeGenerated, HostName, User, Method, SourceIP, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity
```

**Tuning:** Replace `AllowedMgmtSubnets` with your management network CIDRs.

---

## Sentinel Analytics Rule — YAML

```yaml
id: 9e739750-729a-4bc2-a5dd-ff7130231e2b
name: "Successful Login from Unexpected Source"
description: |
  Detects successful authentication to the switch management interface from IP addresses outside the defined management network subnets. Legitimate switch administration should only originate from designated management networks. A successful login from an unexpected source may indicate credential theft, a compromised jump host, or an attacker who has gained valid credentials through phishing or other means.
  SOC analysts should investigate unexpected source logins urgently because they indicate an attacker with valid credentials accessing network infrastructure from an unauthorized location.
  Designed for Extreme Networks switches (ExtremeXOS/Switch Engine, VOSS).
severity: High
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
  // Lookback: 24 hours for successful authentication events
  let lookback = 24h;
  // Define allowed management subnets — customize for your environment
  let AllowedMgmtSubnets = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
  Syslog
  | where TimeGenerated > ago(lookback)
  // Filter to Extreme Networks switch logs
  | where Facility == "local7"
  // Key filter: match successful authentication events
  | where SyslogMessage has "AAA.authPass"
  // Extract user, authentication method, and source IP
  | extend User = extract(@"user\s+(\S+)", 1, SyslogMessage)
  | extend Method = extract(@"through\s+(\S+)", 1, SyslogMessage)
  | extend SourceIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
  // Only evaluate events with a parseable source IP
  | where isnotempty(SourceIP)
  // Detection logic: flag logins from IPs NOT in approved management subnets
  | where not(ipv4_is_in_any_range(SourceIP, AllowedMgmtSubnets))
  | extend
      AlertTitle = "Successful Login from Unexpected Source",
      AlertDescription = "Successful authentication to the switch management interface detected from an IP address outside the defined management subnets.",
      AlertSeverity = "High"
  | project TimeGenerated, HostName, User, Method, SourceIP, SyslogMessage, AlertTitle, AlertDescription, AlertSeverity

alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
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
        columnName: User
customDetails:
  User: User
  Method: Method
  SourceIP: SourceIP
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- [Extreme Networks — AAA EMS Messages (ExtremeXOS 22.6)](https://documentation.extremenetworks.com/ems_catalog_22.6/GUID-976FE8D6-A65A-43F0-A148-3902B31C4429.shtml)
- [Extreme Networks — RADIUS/TACACS+ Configuration (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/exos_31.5/GUID-5BD3EAB5-7D64-4615-B197-CE45947C13F1.shtml)
- [Extreme Networks — EMS Message Catalog (ExtremeXOS 31.5)](https://documentation.extremenetworks.com/ems_catalog_31.5/GUID-C3B7D716-598A-4ECF-8015-5374C89B01CE.shtml)
