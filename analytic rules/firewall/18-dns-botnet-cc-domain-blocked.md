**Author:** Goodness Caleb Ibeh

# DNS Botnet C&C Domain Blocked

Detects DNS queries that the FortiGate DNS filter identified as botnet command-and-control domains. When a host queries a known C2 domain, it strongly indicates that the host is infected with malware and attempting to reach its C2 server for instructions, payload delivery, or data exfiltration. Even though the DNS query was blocked, the infected host still needs to be investigated and remediated.

**Importance:** DNS queries to known botnet C2 domains are a near-certain indicator of active malware infection on the querying host, requiring immediate endpoint isolation and forensic investigation.

**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Host | HostName | QueriedDomain |

```kql
// Reference: FortiOS Log ID 1501054600 (DNS Filter) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/54600/54600
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DNS-related log entries
| where Activity has "dns"
// Key filter: identify botnet and C&C related DNS blocks
| where Message has "botnet" or Message has "C&C"
// Extract the queried domain and associated botnet IP for context
| extend QueriedDomain = DestinationHostName
| extend BotnetIP = extract("FTNTFGTbotnetip=([^;\\s]+)", 1, AdditionalExtensions)
| extend
    AlertTitle = "DNS Botnet C&C Domain Blocked",
    AlertDescription = "DNS query to a known botnet command-and-control domain was blocked, indicating the querying host is likely infected with malware.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, QueriedDomain, BotnetIP,
          DeviceAction, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: f2b8d5c9-1e3a-4f6d-a4b0-8c9d2e5f7a6b
name: "DNS Botnet C&C Domain Blocked"
description: |
  Detects DNS queries that the FortiGate DNS filter identified as botnet command-and-control domains. DNS queries to known botnet C2 domains are a near-certain indicator of active malware infection on the querying host, requiring immediate endpoint isolation and forensic investigation. Designed for Fortinet FortiGate firewalls.
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
  - CommandAndControl
relevantTechniques:
  - T1071.004
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for DNS-related log entries
  | where Activity has "dns"
  // Key filter: identify botnet and C&C related DNS blocks
  | where Message has "botnet" or Message has "C&C"
  // Extract the queried domain and associated botnet IP for context
  | extend QueriedDomain = DestinationHostName
  | extend BotnetIP = extract("FTNTFGTbotnetip=([^;\\s]+)", 1, AdditionalExtensions)
  | extend
      AlertTitle = "DNS Botnet C&C Domain Blocked",
      AlertDescription = "DNS query to a known botnet command-and-control domain was blocked, indicating the querying host is likely infected with malware.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, QueriedDomain, BotnetIP,
            DeviceAction, Message, AlertTitle, AlertDescription, AlertSeverity
  | order by TimeGenerated desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: QueriedDomain
customDetails:
  DeviceAction: DeviceAction
  BotnetIP: BotnetIP
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=dns):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 1501054600:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/54600/54600
