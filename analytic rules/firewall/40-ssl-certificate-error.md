**Author:** Goodness Caleb Ibeh

# SSL Certificate Error — Potential MitM or Misconfiguration

Detects SSL certificate errors encountered during FortiGate's SSL inspection, including self-signed certificates, expired certificates, untrusted certificate authorities, and other certificate validation failures. Certificate errors can indicate a man-in-the-middle attack where an attacker is intercepting encrypted traffic with a fraudulent certificate. They can also indicate misconfigured servers or applications, but in either case, the encrypted connection cannot be trusted and the traffic may be compromised.

**Importance:** SSL certificate errors can indicate an active man-in-the-middle attack intercepting encrypted traffic, and even when caused by misconfiguration, they leave users vulnerable to interception.

**MITRE:** T1557 — Adversary-in-the-Middle
**Severity:** Medium

**Entity Mapping:**
| Entity Type | Identifier | Column |
|---|---|---|
| IP | Address | SourceIP |
| IP | Address | DestinationIP |
| Host | HostName | DestinationHostName |

```kql
// Reference: FortiOS SSL/SSH Inspection — https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/929817/ssl-ssh-inspection
let lookback = 24h;
CommonSecurityLog
// Filter to the last 24 hours of logs
| where TimeGenerated > ago(lookback)
// Scope to FortiGate firewall logs only
| where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
// Filter for SSL-related log entries
| where Activity has "ssl"
// Key filter: match certificate error conditions indicating trust failures
| where Message has_any ("self-signed", "expired", "untrusted", "certificate", "cert-error")
// Extract certificate details for investigation context
| extend CertCN = extract("FTNTFGTcertcn=([^;]+)", 1, AdditionalExtensions)
| extend CertError = extract("FTNTFGTcerterror=([^;\\s]+)", 1, AdditionalExtensions)
| extend
    AlertTitle = "SSL Certificate Error — Potential MitM or Misconfiguration",
    AlertDescription = "SSL certificate error detected during FortiGate SSL inspection, which can indicate an active man-in-the-middle attack or misconfigured server.",
    AlertSeverity = "Medium"
| project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
          CertCN, CertError, DeviceAction, Message, AlertTitle, AlertDescription, AlertSeverity
| order by TimeGenerated desc
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: d4e0c7d1-3f5a-4d8b-e6a2-0b1c4d7e9f8a
name: "SSL Certificate Error — Potential MitM or Misconfiguration"
description: |
  Detects SSL certificate errors encountered during FortiGate's SSL inspection, including self-signed certificates, expired certificates, untrusted certificate authorities, and other certificate validation failures. SSL certificate errors can indicate an active man-in-the-middle attack intercepting encrypted traffic, and even when caused by misconfiguration, they leave users vulnerable to interception. Designed for Fortinet FortiGate firewalls.
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
  - Collection
relevantTechniques:
  - T1557
query: |
  let lookback = 24h;
  CommonSecurityLog
  // Filter to the last 24 hours of logs
  | where TimeGenerated > ago(lookback)
  // Scope to FortiGate firewall logs only
  | where DeviceVendor == "Fortinet" and DeviceProduct == "Fortigate"
  // Filter for SSL-related log entries
  | where Activity has "ssl"
  // Key filter: match certificate error conditions indicating trust failures
  | where Message has_any ("self-signed", "expired", "untrusted", "certificate", "cert-error")
  // Extract certificate details for investigation context
  | extend CertCN = extract("FTNTFGTcertcn=([^;]+)", 1, AdditionalExtensions)
  | extend CertError = extract("FTNTFGTcerterror=([^;\\s]+)", 1, AdditionalExtensions)
  | extend
      AlertTitle = "SSL Certificate Error — Potential MitM or Misconfiguration",
      AlertDescription = "SSL certificate error detected during FortiGate SSL inspection, which can indicate an active man-in-the-middle attack or misconfigured server.",
      AlertSeverity = "Medium"
  | project TimeGenerated, SourceIP, DestinationIP, DestinationHostName,
            CertCN, CertError, DeviceAction, Message, AlertTitle, AlertDescription, AlertSeverity
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
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DestinationHostName
customDetails:
  DeviceAction: DeviceAction
  CertCN: CertCN
  CertError: CertError
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```

## References

- **SSL/SSH Inspection:** https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/929817/ssl-ssh-inspection
