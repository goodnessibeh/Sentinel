**Author:** Goodness Caleb Ibeh

# Routing Configuration Change Detected

Detects changes to routing configurations including static routes, dynamic routing protocols (BGP, OSPF, RIP, IS-IS), policy routes, route maps, prefix lists, and SD-WAN settings. Routing changes can redirect traffic through attacker-controlled paths, create traffic black holes for denial of service, or enable man-in-the-middle attacks by diverting traffic through interception points. Routing manipulation is a sophisticated attack technique used by advanced threat actors.

**Importance:** Routing manipulation can silently redirect all network traffic through attacker-controlled infrastructure for interception, making it one of the most dangerous configuration changes an attacker can make.

**MITRE:** T1557 — Adversary-in-the-Middle
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Host | HostName | DeviceName |
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS SD-WAN — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/716691/sd-wan
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Key filter: match routing-related system events or dedicated router log entries
| where (Activity has "system" and Message has_any (
    "static-route", "route", "router bgp", "router ospf",
    "router rip", "router isis", "router multicast",
    "policy-route", "route-map", "prefix-list",
    "sd-wan", "sdwan"
  ))
  or Activity has "router"
| extend
    AlertTitle = "Routing Configuration Change Detected",
    AlertDescription = "Routing configuration change detected, which can silently redirect all network traffic through attacker-controlled infrastructure for interception.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
          Message, Activity, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e9a5d2e6-8c0f-4e3b-f1b7-5c6d9e0f4a3b
name: "Routing Configuration Change Detected"
description: |
  Detects changes to routing configurations including static routes, dynamic routing protocols (BGP, OSPF, RIP, IS-IS), policy routes, route maps, prefix lists, and SD-WAN settings. Routing manipulation can silently redirect all network traffic through attacker-controlled infrastructure for interception. Designed for Fortinet FortiGate firewalls.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - LateralMovement
relevantTechniques:
  - T1557
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Key filter: match routing-related system events or dedicated router log entries
  | where (Activity has "system" and Message has_any (
      "static-route", "route", "router bgp", "router ospf",
      "router rip", "router isis", "router multicast",
      "policy-route", "route-map", "prefix-list",
      "sd-wan", "sdwan"
    ))
    or Activity has "router"
  | extend
      AlertTitle = "Routing Configuration Change Detected",
      AlertDescription = "Routing configuration change detected, which can silently redirect all network traffic through attacker-controlled infrastructure for interception.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, DestinationUserName, SourceIP,
            Message, Activity, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  DeviceName: DeviceName
  DeviceAction: DeviceAction
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **Event Log Trigger:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/950487/fortios-event-log-trigger
- **SD-WAN:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/716691/sd-wan
