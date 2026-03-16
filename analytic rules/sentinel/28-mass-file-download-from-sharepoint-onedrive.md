**Author:** Goodness Caleb Ibeh

# Mass File Download from SharePoint/OneDrive

This detection identifies users downloading an unusually high number of files from SharePoint or OneDrive in a short time window. Mass file downloads can indicate data collection by a compromised account, an insider threat staging data for exfiltration, or an attacker harvesting sensitive documents. The query aggregates download activity per user and flags those exceeding a configurable threshold.

**Importance:** A SOC analyst should investigate because mass file downloads from cloud storage typically precede data exfiltration and may indicate a compromised account or malicious insider.

**MITRE:** T1213.002 — Data from Information Repositories: SharePoint

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserId |

```kql
let threshold = 50;
OfficeActivity
// Short 1-hour window to detect burst download activity
| where TimeGenerated > ago(1h)
// Filter for SharePoint and OneDrive workloads
| where OfficeWorkload in ("SharePoint", "OneDrive")
// Key filter: only file download operations
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
// Aggregate download activity per user and source IP
| summarize
    DownloadCount = count(),
    DistinctFiles = dcount(OfficeObjectId),
    Sites = make_set(Site_Url, 5),
    SampleFiles = make_set(SourceFileName, 10)
  by UserId, ClientIP
// Threshold: flag users exceeding the download limit
| where DownloadCount >= threshold
| extend
    AlertTitle = "Mass File Download from SharePoint/OneDrive",
    AlertDescription = "This detection identifies users downloading an unusually high number of files from SharePoint or OneDrive in a short time window.",
    AlertSeverity = "Medium"
| project UserId, ClientIP, DownloadCount, DistinctFiles, Sites, SampleFiles, AlertTitle, AlertDescription, AlertSeverity
```

---

## Sentinel Analytics Rule — YAML

```yaml
id: 28d9e0f1-a2b3-4c4d-5e6f-7a8b9c0d1ec8
name: "Mass File Download from SharePoint/OneDrive"
description: |
  This detection identifies users downloading an unusually high number of files from SharePoint or OneDrive in a short time window. Mass file downloads can indicate data collection by a compromised account, an insider threat staging data for exfiltration, or an attacker harvesting sensitive documents.
  A SOC analyst should investigate because mass file downloads from cloud storage typically precede data exfiltration and may indicate a compromised account or malicious insider.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - Collection
relevantTechniques:
  - T1213.002
query: |
  let threshold = 50;
  OfficeActivity
  // Short 1-hour window to detect burst download activity
  | where TimeGenerated > ago(1h)
  // Filter for SharePoint and OneDrive workloads
  | where OfficeWorkload in ("SharePoint", "OneDrive")
  // Key filter: only file download operations
  | where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
  // Aggregate download activity per user and source IP
  | summarize
      DownloadCount = count(),
      DistinctFiles = dcount(OfficeObjectId),
      Sites = make_set(Site_Url, 5),
      SampleFiles = make_set(SourceFileName, 10)
    by UserId, ClientIP
  // Threshold: flag users exceeding the download limit
  | where DownloadCount >= threshold
  | extend
      AlertTitle = "Mass File Download from SharePoint/OneDrive",
      AlertDescription = "This detection identifies users downloading an unusually high number of files from SharePoint or OneDrive in a short time window.",
      AlertSeverity = "Medium"
  | project UserId, ClientIP, DownloadCount, DistinctFiles, Sites, SampleFiles, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserId
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
