**Author:** Goodness Caleb Ibeh

# Critical/High IPS Signature Matches

Detects IPS signature matches rated as critical or high severity by the FortiGate IPS engine. These signatures correspond to known exploitation techniques, vulnerability exploits, and attack payloads actively used in the wild. A critical or high IPS hit means the firewall identified traffic that matches a known attack pattern, regardless of whether it was blocked or allowed.

**Importance:** Critical and high IPS signatures represent active exploitation attempts against your network and must be triaged to confirm the attack was blocked and the target host is not compromised.

**MITRE:** Multiple (depends on signature)
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
// Reference: FortiOS Log ID 0419016384 (UTM IPS) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for IPS-related log entries
| where Activity has "utm:ips" or Activity has "ips"
// Extract IPS-specific fields from the additional extensions
| extend ThreatLevel = extract("FTNTFGTcrlevel=([^;\\s]+)", 1, AdditionalExtensions)
| extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
| extend AttackId = extract("FTNTFGTattackid=([^;\\s]+)", 1, AdditionalExtensions)
| extend ThreatScore = toint(extract("FTNTFGTcrscore=([^;\\s]+)", 1, AdditionalExtensions))
// Only surface critical and high severity detections
| where ThreatLevel in ("critical", "high")
| extend
    AlertTitle = "Critical/High IPS Signature Matches",
    AlertDescription = "IPS signature matches rated critical or high severity detected, representing active exploitation attempts against the network.",
    AlertSeverity = "High"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          AttackName, AttackId, ThreatLevel, ThreatScore,
          DeviceAction, ApplicationProtocol, Message, AlertTitle, AlertDescription, AlertSeverity
| order by ThreatScore desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: a1c7e4d8-0f2b-4a5e-b3c9-7d8e1f4a6b5c
name: "Critical/High IPS Signature Matches"
description: |
  Detects IPS signature matches rated as critical or high severity by the FortiGate IPS engine. Critical and high IPS signatures represent active exploitation attempts against your network and must be triaged to confirm the attack was blocked and the target host is not compromised. Designed for Fortinet FortiGate firewalls.
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
  - InitialAccess
  - Execution
relevantTechniques:
  - T1190
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for IPS-related log entries
  | where Activity has "utm:ips" or Activity has "ips"
  // Extract IPS-specific fields from the additional extensions
  | extend ThreatLevel = extract("FTNTFGTcrlevel=([^;\\s]+)", 1, AdditionalExtensions)
  | extend AttackName = extract("FTNTFGTattack=([^;]+)", 1, AdditionalExtensions)
  | extend AttackId = extract("FTNTFGTattackid=([^;\\s]+)", 1, AdditionalExtensions)
  | extend ThreatScore = toint(extract("FTNTFGTcrscore=([^;\\s]+)", 1, AdditionalExtensions))
  // Only surface critical and high severity detections
  | where ThreatLevel in ("critical", "high")
  | extend
      AlertTitle = "Critical/High IPS Signature Matches",
      AlertDescription = "IPS signature matches rated critical or high severity detected, representing active exploitation attempts against the network.",
      AlertSeverity = "High"
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            AttackName, AttackId, ThreatLevel, ThreatScore,
            DeviceAction, ApplicationProtocol, Message, AlertTitle, AlertDescription, AlertSeverity
  | order by ThreatScore desc
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
customDetails:
  DeviceAction: DeviceAction
  AttackName: AttackName
  ThreatLevel: ThreatLevel
  ThreatScore: ThreatScore
  AttackId: AttackId
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=ips):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0419016384 (UTM IPS):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/16384/16384-log-id-utm-ips
