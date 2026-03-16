**Author:** Goodness Caleb Ibeh

# Outbound Traffic to Known Malicious Countries

Detects outbound connections from internal hosts to countries that are commonly associated with state-sponsored threat actors or sanctioned regimes. Legitimate business traffic to these regions is rare in most organizations, so any allowed connection warrants investigation. This can indicate compromised hosts communicating with command-and-control infrastructure or data being exfiltrated to adversary-controlled servers.

**Importance:** Connections to sanctioned or high-risk countries may indicate active C2 communication or sanctions violations that require immediate triage and potential blocking.

**MITRE:** T1071 — Application Layer Protocol
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |

```kql
// Reference: FortiOS Traffic Log — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
let lookback = 24h;
// Define countries with known state-sponsored threat actor activity
let SuspiciousCountries = dynamic(["North Korea", "Iran", "Syria", "Cuba"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Only look at allowed/completed connections — these actually reached the destination
| where DeviceAction in ("accept", "close")
// Extract the destination country from FortiGate additional extensions
| extend DstCountry = extract("FTNTFGTdstcountry=([^;\\s]+)", 1, AdditionalExtensions)
// Filter to only traffic destined for suspicious countries
| where DstCountry in (SuspiciousCountries)
| extend
    AlertTitle = "Outbound Traffic to Known Malicious Countries",
    AlertDescription = "Outbound connections detected from internal hosts to countries associated with state-sponsored threat actors or sanctioned regimes.",
    AlertSeverity = "Medium"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          ApplicationProtocol, DstCountry, SentBytes, ReceivedBytes,
          DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b4d2f9e3-5a7c-4b0f-c8d4-2e3f6a9b1c0d
name: "Outbound Traffic to Known Malicious Countries"
description: |
  Detects outbound connections from internal hosts to countries that are commonly associated with state-sponsored threat actors or sanctioned regimes. Connections to sanctioned or high-risk countries may indicate active C2 communication or sanctions violations that require immediate triage and potential blocking. Designed for Fortinet FortiGate firewalls.
severity: Medium
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
  - T1071
query: |
  let lookback = 24h;
  // Define countries with known state-sponsored threat actor activity
  let SuspiciousCountries = dynamic(["North Korea", "Iran", "Syria", "Cuba"]);
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Only look at allowed/completed connections — these actually reached the destination
  | where DeviceAction in ("accept", "close")
  // Extract the destination country from FortiGate additional extensions
  | extend DstCountry = extract("FTNTFGTdstcountry=([^;\\s]+)", 1, AdditionalExtensions)
  // Filter to only traffic destined for suspicious countries
  | where DstCountry in (SuspiciousCountries)
  | extend
      AlertTitle = "Outbound Traffic to Known Malicious Countries",
      AlertDescription = "Outbound connections detected from internal hosts to countries associated with state-sponsored threat actors or sanctioned regimes.",
      AlertSeverity = "Medium"
  | project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
            ApplicationProtocol, DstCountry, SentBytes, ReceivedBytes,
            DestinationUserName, AlertTitle, AlertDescription, AlertSeverity
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
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
customDetails:
  DeviceAction: DeviceAction
  DstCountry: DstCountry
  ApplicationProtocol: ApplicationProtocol
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference:** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log Types and Subtypes:** https://docs.fortinet.com/document/fortigate/7.6.2/fortios-log-message-reference/670197/log-types-and-subtypes
- **Traffic Logging:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/986892/traffic-logging
