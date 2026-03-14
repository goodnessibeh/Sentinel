**Author:** Goodness Caleb Ibeh

# DLP Policy Violation — Sensitive Data Exfiltration

Detects FortiGate DLP policy violations where sensitive data patterns (credit card numbers, SSNs, proprietary document fingerprints, etc.) were identified in outbound traffic. DLP events indicate that sensitive information is leaving the organization, whether intentionally by a malicious insider or accidentally by an unaware employee. The severity and filter type help prioritize which violations need immediate attention.

**Importance:** DLP violations represent potential exposure of regulated or proprietary data and may trigger compliance notification requirements under GDPR, PCI-DSS, HIPAA, or similar regulations.

**MITRE:** T1567 — Exfiltration Over Web Service
**Severity:** High

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Account | Name | DestinationUserName |
| URL | Url | RequestURL |
| File | Name | FileName |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS Log ID 0954024576 (DLP) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/24576/24576
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for DLP-related log entries
| where Activity has "dlp"
// Extract DLP-specific fields from additional extensions
| extend DLPSeverity = extract("FTNTFGTseverity=([^;\\s]+)", 1, AdditionalExtensions)
| extend FilterType = extract("FTNTFGTfiltertype=([^;\\s]+)", 1, AdditionalExtensions)
| extend Profile = extract("FTNTFGTprofile=([^;\\s]+)", 1, AdditionalExtensions)
| extend FileName = extract("FTNTFGTfilename=([^;]+)", 1, AdditionalExtensions)
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
          RequestURL, FileName, FilterType, DLPSeverity, Profile,
          DeviceAction, DestinationUserName, ApplicationProtocol
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: b4d0a7b1-3e5c-4f8d-c6e2-0f1a4b7c9d8e
name: "DLP Policy Violation — Sensitive Data Exfiltration"
description: |
  Detects FortiGate DLP policy violations where sensitive data patterns were identified in outbound traffic. DLP violations represent potential exposure of regulated or proprietary data and may trigger compliance notification requirements under GDPR, PCI-DSS, HIPAA, or similar regulations. Designed for Fortinet FortiGate firewalls.
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
  - Exfiltration
relevantTechniques:
  - T1567
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for DLP-related log entries
  | where Activity has "dlp"
  // Extract DLP-specific fields from additional extensions
  | extend DLPSeverity = extract("FTNTFGTseverity=([^;\\s]+)", 1, AdditionalExtensions)
  | extend FilterType = extract("FTNTFGTfiltertype=([^;\\s]+)", 1, AdditionalExtensions)
  | extend Profile = extract("FTNTFGTprofile=([^;\\s]+)", 1, AdditionalExtensions)
  | extend FileName = extract("FTNTFGTfilename=([^;]+)", 1, AdditionalExtensions)
  | project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
            RequestURL, FileName, FilterType, DLPSeverity, Profile,
            DeviceAction, DestinationUserName, ApplicationProtocol
  | order by TimeGenerated desc
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DestinationIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: RequestURL
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  DeviceAction: DeviceAction
  DLPSeverity: DLPSeverity
  FilterType: FilterType
  Profile: Profile
version: 1.0.0
kind: Scheduled
```

## References

- **FortiOS Log Message Reference (subtype=dlp):** https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/357866/log-message-fields
- **Log ID 0954024576:** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/24576/24576
