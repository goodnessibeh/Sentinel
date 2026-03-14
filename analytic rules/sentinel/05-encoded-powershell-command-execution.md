**Author:** Goodness Caleb Ibeh

# Encoded PowerShell Command Execution

This detection identifies PowerShell processes launched with Base64-encoded command-line arguments, a technique heavily used by attackers to obfuscate malicious payloads. Legitimate administrators rarely use encoded commands, making this a reliable indicator of malicious activity. The query automatically decodes the payload so analysts can immediately see what was executed.

**Importance:** A SOC analyst should investigate because encoded PowerShell is the most common obfuscation technique used in malware droppers, post-exploitation frameworks, and fileless attacks.

**MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |
| Process | CommandLine | ProcessCommandLine |

```kql
DeviceProcessEvents
// 24-hour lookback for encoded PowerShell execution
| where TimeGenerated > ago(24h)
// Filter for PowerShell executables
| where FileName in~ ("powershell.exe", "pwsh.exe")
// Key filter: detect encoded command flags
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ec ")
// Extract the Base64 payload from the command line
| extend EncodedPayload = extract(@"(?i)-[eE](?:nc(?:odedCommand)?|c)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| where isnotempty(EncodedPayload)
// Decode the Base64 payload so analysts can read the actual command
| extend DecodedCommand = base64_decode_tostring(EncodedPayload)
| project TimeGenerated, DeviceName, AccountName,
          ProcessCommandLine, DecodedCommand,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091
name: "Encoded PowerShell Command Execution"
description: |
  This detection identifies PowerShell processes launched with Base64-encoded command-line arguments, a technique heavily used by attackers to obfuscate malicious payloads. Legitimate administrators rarely use encoded commands, making this a reliable indicator of malicious activity.
  A SOC analyst should investigate because encoded PowerShell is the most common obfuscation technique used in malware droppers, post-exploitation frameworks, and fileless attacks.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Execution
relevantTechniques:
  - T1059.001
query: |
  DeviceProcessEvents
  // 24-hour lookback for encoded PowerShell execution
  | where TimeGenerated > ago(24h)
  // Filter for PowerShell executables
  | where FileName in~ ("powershell.exe", "pwsh.exe")
  // Key filter: detect encoded command flags
  | where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "-ec ")
  // Extract the Base64 payload from the command line
  | extend EncodedPayload = extract(@"(?i)-[eE](?:nc(?:odedCommand)?|c)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
  | where isnotempty(EncodedPayload)
  // Decode the Base64 payload so analysts can read the actual command
  | extend DecodedCommand = base64_decode_tostring(EncodedPayload)
  | project TimeGenerated, DeviceName, AccountName,
            ProcessCommandLine, DecodedCommand,
            InitiatingProcessFileName, InitiatingProcessCommandLine
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
  - entityType: Process
    fieldMappings:
      - identifier: CommandLine
        columnName: ProcessCommandLine
version: 1.0.0
kind: Scheduled
```
