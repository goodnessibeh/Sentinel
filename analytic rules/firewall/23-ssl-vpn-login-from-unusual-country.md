**Author:** Goodness Caleb Ibeh

# SSL VPN Login from Unusual Country

Detects successful SSL VPN connections originating from countries not in the organization's allowed list. An attacker who has obtained valid VPN credentials (through phishing, credential dumps, or brute force) will often connect from infrastructure in foreign countries. This is one of the most reliable indicators of compromised credentials being used by an external threat actor.

**Importance:** VPN logins from unexpected countries are a strong indicator of stolen credentials being used by an attacker, especially when the user has no travel history to that region.

**MITRE:** T1078 — Valid Accounts
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| Account | Name | DestinationUserName |

```kql
// Reference: FortiOS Log ID 39947 (SSL VPN Tunnel Up) — https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up
let lookback = 24h;
// Define the countries where legitimate VPN logins are expected
let AllowedCountries = dynamic(["United States", "Canada", "United Kingdom"]);
CommonSecurityLog
// Filter to the last 24 hours of logs
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
// Extract the source country from additional extensions
| extend SrcCountry = extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions)
// Filter out allowed countries and empty/reserved values
| where SrcCountry !in (AllowedCountries) and isnotempty(SrcCountry) and SrcCountry != "Reserved"
| extend
    AlertTitle = "SSL VPN Login from Unusual Country",
    AlertDescription = "Successful SSL VPN connection detected from a country not in the allowed list, indicating potential use of stolen credentials by an external threat actor.",
    AlertSeverity = "Medium"
| project TimeGenerated, SourceIP, DestinationUserName, SrcCountry,
          TunnelType, DeviceAction, AlertTitle, AlertDescription, AlertSeverity
```

**Tuning:** Customize `AllowedCountries` for your organization's geographic footprint.

---

## Sentinel Analytics Rule — YAML

```yaml
id: e7a3d0e4-6b8c-4c1f-f9a5-3b4c7d0e2f1a
name: "SSL VPN Login from Unusual Country"
description: |
  Detects successful SSL VPN connections originating from countries not in the organization's allowed list. VPN logins from unexpected countries are a strong indicator of stolen credentials being used by an attacker, especially when the user has no travel history to that region. Designed for Fortinet FortiGate firewalls.
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
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  let lookback = 24h;
  // Define the countries where legitimate VPN logins are expected
  let AllowedCountries = dynamic(["United States", "Canada", "United Kingdom"]);
  CommonSecurityLog
  // Filter to the last 24 hours of logs
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
  // Extract the source country from additional extensions
  | extend SrcCountry = extract("FTNTFGTsrccountry=([^;\\s]+)", 1, AdditionalExtensions)
  // Filter out allowed countries and empty/reserved values
  | where SrcCountry !in (AllowedCountries) and isnotempty(SrcCountry) and SrcCountry != "Reserved"
  | extend
      AlertTitle = "SSL VPN Login from Unusual Country",
      AlertDescription = "Successful SSL VPN connection detected from a country not in the allowed list, indicating potential use of stolen credentials by an external threat actor.",
      AlertSeverity = "Medium"
  | project TimeGenerated, SourceIP, DestinationUserName, SrcCountry,
            TunnelType, DeviceAction, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: DestinationUserName
customDetails:
  DeviceAction: DeviceAction
  SrcCountry: SrcCountry
  TunnelType: TunnelType
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **SSL VPN Tunnel Up (Log ID 39947):** https://docs.fortinet.com/document/fortigate/7.4.1/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up
- **VPN Logs Overview:** https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/834425/understanding-vpn-related-logs
