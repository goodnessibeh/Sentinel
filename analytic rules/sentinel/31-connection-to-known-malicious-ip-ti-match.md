**Author:** Goodness Caleb Ibeh

# Connection to Known Malicious IP (TI Match)

This detection correlates outbound network connections against known malicious IP addresses from threat intelligence feeds. When a device connects to an IP that has been flagged as malicious by threat intelligence providers, it strongly suggests compromise — either by malware communicating with its C2 infrastructure or by a user inadvertently visiting a malicious host. The query enriches matches with TI metadata to provide context for the analyst.

**Importance:** A SOC analyst should prioritize this alert because a confirmed connection to a threat-intelligence-flagged IP address is direct evidence of communication with known attacker infrastructure.

**MITRE:** T1071 — Application Layer Protocol

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| IP | Address | RemoteIP |

```kql
// Step 1: Build a list of active malicious IPs from threat intelligence
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where Active == true and ExpirationDateTime > now()
| where isnotempty(NetworkIP)
| distinct NetworkIP;
// Step 2: Find device connections to any of those malicious IPs
DeviceNetworkEvents
// 24-hour lookback for outbound connections
| where TimeGenerated > ago(24h)
// Key filter: match against threat intelligence IP list
| where RemoteIP in (TI_IPs)
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
// Enrich with threat intelligence metadata for analyst context
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | project NetworkIP, ThreatType, Description, Confidence, Tags
  ) on $left.RemoteIP == $right.NetworkIP
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 31a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b11
name: "Connection to Known Malicious IP (TI Match)"
description: |
  This detection correlates outbound network connections against known malicious IP addresses from threat intelligence feeds. When a device connects to an IP that has been flagged as malicious by threat intelligence providers, it strongly suggests compromise.
  A SOC analyst should prioritize this alert because a confirmed connection to a threat-intelligence-flagged IP address is direct evidence of communication with known attacker infrastructure.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
  - connectorId: ThreatIntelligence
    dataTypes:
      - ThreatIntelligenceIndicator
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071
query: |
  // Step 1: Build a list of active malicious IPs from threat intelligence
  let TI_IPs = ThreatIntelligenceIndicator
  | where TimeGenerated > ago(30d)
  | where Active == true and ExpirationDateTime > now()
  | where isnotempty(NetworkIP)
  | distinct NetworkIP;
  // Step 2: Find device connections to any of those malicious IPs
  DeviceNetworkEvents
  // 24-hour lookback for outbound connections
  | where TimeGenerated > ago(24h)
  // Key filter: match against threat intelligence IP list
  | where RemoteIP in (TI_IPs)
  | project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, RemoteUrl,
            InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
  // Enrich with threat intelligence metadata for analyst context
  | join kind=leftouter (
      ThreatIntelligenceIndicator
      | where isnotempty(NetworkIP)
      | project NetworkIP, ThreatType, Description, Confidence, Tags
    ) on $left.RemoteIP == $right.NetworkIP
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
version: 1.0.0
kind: Scheduled
```
