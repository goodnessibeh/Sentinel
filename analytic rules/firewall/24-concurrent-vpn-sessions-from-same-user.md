**Author:** Goodness Caleb Ibeh

# Concurrent VPN Sessions from Same User

Detects a single user account connected to the SSL VPN from multiple distinct source IP addresses simultaneously. Under normal circumstances, a user connects from one location at a time. Multiple concurrent sessions from different IPs suggest that the user's credentials have been compromised and are being used by an attacker at the same time as the legitimate user, or the credentials have been shared or sold.

**Importance:** Concurrent VPN sessions from different IPs for the same user is a high-confidence indicator of credential compromise, as legitimate users rarely connect from multiple locations simultaneously.

**MITRE:** T1078 — Valid Accounts
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| Account | Name | DestinationUserName |
| IP | Address | SourceIP |

```kql
// Reference: FortiOS Log ID 39947 (SSL VPN Tunnel Up) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up
let lookback = 1h;
CommonSecurityLog
// Filter to the last 1 hour of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for VPN-related log entries
| where Activity has "vpn"
// Key filter: only look at successful VPN tunnel establishments
| where DeviceAction == "tunnel-up"
// Extract tunnel type to focus on SSL VPN connections
| extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
| where TunnelType has "ssl"
// Aggregate sessions per user — count distinct source IPs and countries
| summarize
    SessionCount = count(),
    DistinctIPs = dcount(SourceIP),
    IPList = make_set(SourceIP, 10),
    Countries = make_set(extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions), 5)
  by DestinationUserName
// Detection logic: flag users with sessions from more than one distinct IP
| where DistinctIPs > 1
| project DestinationUserName, SessionCount, DistinctIPs, IPList, Countries
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f8b4e1f5-7c9d-4d2a-a0b6-4c5d8e1f3a2b
name: "Concurrent VPN Sessions from Same User"
description: |
  Detects a single user account connected to the SSL VPN from multiple distinct source IP addresses simultaneously. Concurrent VPN sessions from different IPs for the same user is a high-confidence indicator of credential compromise, as legitimate users rarely connect from multiple locations simultaneously. Designed for Fortinet FortiGate firewalls.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  let lookback = 1h;
  CommonSecurityLog
  // Filter to the last 1 hour of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for VPN-related log entries
  | where Activity has "vpn"
  // Key filter: only look at successful VPN tunnel establishments
  | where DeviceAction == "tunnel-up"
  // Extract tunnel type to focus on SSL VPN connections
  | extend TunnelType = extract("FTNTFGTtunneltype=([^;\\s]+)", 1, AdditionalExtensions)
  | where TunnelType has "ssl"
  // Aggregate sessions per user — count distinct source IPs and countries
  | summarize
      SessionCount = count(),
      DistinctIPs = dcount(SourceIP),
      IPList = make_set(SourceIP, 10),
      Countries = make_set(extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions), 5)
    by DestinationUserName
  // Detection logic: flag users with sessions from more than one distinct IP
  | where DistinctIPs > 1
  | project DestinationUserName, SessionCount, DistinctIPs, IPList, Countries
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
customDetails:
  SessionCount: SessionCount
  DistinctIPs: DistinctIPs
version: 1.0.0
kind: Scheduled
```

## References

- **SSL VPN Tunnel Up (Log ID 39947):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up
- **VPN Logs Overview:** https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/834425/understanding-vpn-related-logs
