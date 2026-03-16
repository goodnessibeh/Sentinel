**Author:** Goodness Caleb Ibeh

# Ransomware Indicators — Mass File Encryption

This detection identifies potential ransomware activity by monitoring for mass file rename operations using known ransomware file extensions, as well as the creation of ransom note files. Ransomware encrypts files and renames them with specific extensions, then drops instructional files telling victims how to pay. Detecting this pattern early — even within a 5-minute window — can enable containment before the entire environment is encrypted.

**Importance:** A SOC analyst should treat this as the highest priority because active ransomware encryption causes immediate, widespread data loss and every second of delay increases the blast radius.

**MITRE:** T1486 — Data Encrypted for Impact

**Severity:** High

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Host | FullName | DeviceName |
| Account | FullName | AccountName |

```kql
// Define known ransomware file extensions
let encryptionExtensions = dynamic([
    ".encrypted", ".locked", ".crypto", ".crypt",
    ".enc", ".rzk", ".WNCRY", ".wnry", ".locky",
    ".cerber", ".zepto", ".thor", ".aaa", ".abc",
    ".xyz", ".zzzzz", ".micro", ".vvv"
]);
let renameThreshold = 50;
DeviceFileEvents
// Short 1-hour window for rapid ransomware detection
| where TimeGenerated > ago(1h)
// Filter for file rename operations (encryption renames files)
| where ActionType == "FileRenamed"
| extend NewExtension = extract(@"(\.\w+)$", 1, FileName)
// Key filter: match ransomware extensions or ransom note filenames
| where NewExtension in (encryptionExtensions) or
        // Detect ransom note creation
        FileName in~ ("README.txt", "DECRYPT_INSTRUCTIONS.txt",
                      "HOW_TO_DECRYPT.txt", "RECOVERY_INSTRUCTIONS.html",
                      "!README!.txt", "_readme.txt")
// Aggregate into 5-minute windows to detect rapid encryption bursts
| summarize
    RenameCount = count(),
    Extensions = make_set(NewExtension, 10),
    FolderPaths = make_set(FolderPath, 10),
    SampleFiles = make_set(FileName, 20)
  by DeviceName, AccountName, InitiatingProcessFileName,
     InitiatingProcessCommandLine, bin(TimeGenerated, 5m)
// Threshold: 50+ renames in 5 minutes indicates active ransomware
| where RenameCount >= renameThreshold
| extend
    AlertTitle = "Ransomware Indicators — Mass File Encryption",
    AlertDescription = "This detection identifies potential ransomware activity by monitoring for mass file rename operations using known ransomware file extensions, as well as the creation of ransom note files.",
    AlertSeverity = "High"
| project TimeGenerated, DeviceName, AccountName, RenameCount,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          Extensions, SampleFiles, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 34d5e6f7-a8b9-4c0d-1e2f-3a4b5c6d7e44
name: "Ransomware Indicators — Mass File Encryption"
description: |
  This detection identifies potential ransomware activity by monitoring for mass file rename operations using known ransomware file extensions, as well as the creation of ransom note files. Detecting this pattern early can enable containment before the entire environment is encrypted.
  A SOC analyst should treat this as the highest priority because active ransomware encryption causes immediate, widespread data loss and every second of delay increases the blast radius.
severity: High
status: Available
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Impact
relevantTechniques:
  - T1486
query: |
  // Define known ransomware file extensions
  let encryptionExtensions = dynamic([
      ".encrypted", ".locked", ".crypto", ".crypt",
      ".enc", ".rzk", ".WNCRY", ".wnry", ".locky",
      ".cerber", ".zepto", ".thor", ".aaa", ".abc",
      ".xyz", ".zzzzz", ".micro", ".vvv"
  ]);
  let renameThreshold = 50;
  DeviceFileEvents
  // Short 1-hour window for rapid ransomware detection
  | where TimeGenerated > ago(1h)
  // Filter for file rename operations (encryption renames files)
  | where ActionType == "FileRenamed"
  | extend NewExtension = extract(@"(\.\w+)$", 1, FileName)
  // Key filter: match ransomware extensions or ransom note filenames
  | where NewExtension in (encryptionExtensions) or
          // Detect ransom note creation
          FileName in~ ("README.txt", "DECRYPT_INSTRUCTIONS.txt",
                        "HOW_TO_DECRYPT.txt", "RECOVERY_INSTRUCTIONS.html",
                        "!README!.txt", "_readme.txt")
  // Aggregate into 5-minute windows to detect rapid encryption bursts
  | summarize
      RenameCount = count(),
      Extensions = make_set(NewExtension, 10),
      FolderPaths = make_set(FolderPath, 10),
      SampleFiles = make_set(FileName, 20)
    by DeviceName, AccountName, InitiatingProcessFileName,
       InitiatingProcessCommandLine, bin(TimeGenerated, 5m)
  // Threshold: 50+ renames in 5 minutes indicates active ransomware
  | where RenameCount >= renameThreshold
  | extend
      AlertTitle = "Ransomware Indicators — Mass File Encryption",
      AlertDescription = "This detection identifies potential ransomware activity by monitoring for mass file rename operations using known ransomware file extensions, as well as the creation of ransom note files.",
      AlertSeverity = "High"
  | project TimeGenerated, DeviceName, AccountName, RenameCount,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            Extensions, SampleFiles, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DeviceName
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
