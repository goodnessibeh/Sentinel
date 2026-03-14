# KQL Sentinel — Workbook Dashboards & ARM Templates

> 9 creative dashboard designs with full KQL queries, visualization specifications, and ARM template deployment.

---

## Dashboard Design Principles

1. **Information hierarchy** — KPI tiles at top, trends in middle, detail grids at bottom
2. **Time coherence** — All visualizations share a global time parameter
3. **Progressive disclosure** — Tab navigation for sections, drill-down for detail
4. **Color semantics** — Red=critical, Orange=high, Yellow=medium, Blue=info, Green=good
5. **Gap-free time series** — Always use `make-series` with `default=0` for charts

---

## 1. SOC Command Center

### KPI Tiles — Incident Metrics

```kql
// MTTD (Mean Time to Detect) — minutes from first activity to alert
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| where Status != "Closed"
| extend MTTD = datetime_diff("minute", CreatedTime, FirstActivityTime)
| summarize AvgMTTD = avg(MTTD), MedianMTTD = percentile(MTTD, 50)

// MTTR (Mean Time to Respond) — minutes from creation to close
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| where Status == "Closed"
| extend MTTR = datetime_diff("minute", ClosedTime, CreatedTime)
| summarize AvgMTTR = avg(MTTR), MedianMTTR = percentile(MTTR, 50)

// Open Incidents by Severity
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| where Status in ("New", "Active")
| summarize Count = count() by Severity
| order by case(Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4) asc
```

### Incident Timeline — Timechart

```kql
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| make-series
    IncidentCount = count() default=0
  on CreatedTime from ago({TimeRange}) to now() step 1h
  by Severity
| render timechart with (title="Incidents Over Time")
```

### Severity Distribution — Donut Chart

```kql
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| summarize Count = count() by Severity
| render piechart with (title="Incident Severity Distribution")
```

### Top 10 Alert Rules Firing

```kql
SecurityAlert
| where TimeGenerated > ago({TimeRange})
| summarize AlertCount = count() by AlertName, AlertSeverity
| top 10 by AlertCount desc
| project AlertName, AlertSeverity, AlertCount
```

### Incident Owner Workload — Bar Chart

```kql
SecurityIncident
| where TimeGenerated > ago({TimeRange})
| where Status in ("New", "Active")
| extend OwnerName = tostring(Owner.assignedTo)
| summarize
    OpenCount = count(),
    HighCount = countif(Severity == "High"),
    MediumCount = countif(Severity == "Medium")
  by OwnerName
| order by OpenCount desc
| render barchart with (title="Analyst Workload", kind=stacked)
```

### MITRE ATT&CK Coverage Heatmap

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| mv-expand Tactic = Tactics
| mv-expand Technique = Techniques
| summarize IncidentCount = count() by tostring(Tactic), tostring(Technique)
| order by IncidentCount desc
```

---

## 2. Threat Intelligence Dashboard

### IOC Match Rate — KPI Tile

```kql
let TotalIndicators = toscalar(
    ThreatIntelligenceIndicator
    | where Active == true and ExpirationDateTime > now()
    | summarize count()
);
let MatchedIndicators = toscalar(
    ThreatIntelligenceIndicator
    | where Active == true and ExpirationDateTime > now()
    | where TimeGenerated > ago({TimeRange})
    | join kind=inner (
        SecurityAlert | where TimeGenerated > ago({TimeRange}) | distinct SystemAlertId
    ) on $left.IndicatorId == $right.SystemAlertId
    | summarize dcount(IndicatorId)
);
print TotalIOCs = TotalIndicators, MatchedIOCs = MatchedIndicators,
      HitRate = round(todouble(MatchedIndicators) / todouble(TotalIndicators) * 100, 2)
```

### Indicator Type Distribution — Pie Chart

```kql
ThreatIntelligenceIndicator
| where Active == true and ExpirationDateTime > now()
| extend IndicatorType = case(
    isnotempty(DomainName), "Domain",
    isnotempty(Url), "URL",
    isnotempty(NetworkIP), "IP Address",
    isnotempty(EmailSenderAddress), "Email",
    isnotempty(FileHashValue), "File Hash",
    "Other"
  )
| summarize Count = count() by IndicatorType
| render piechart with (title="IOC Types")
```

### Indicator Freshness — Timechart

```kql
ThreatIntelligenceIndicator
| where Active == true
| make-series
    NewIndicators = count() default=0
  on TimeGenerated from ago(30d) to now() step 1d
| render timechart with (title="New IOCs Per Day")
```

### TI Matches by Source Table

```kql
// IP-based IOC matching across key tables
let MaliciousIPs = ThreatIntelligenceIndicator
| where Active == true and ExpirationDateTime > now()
| where isnotempty(NetworkIP)
| distinct NetworkIP;
union
    (SigninLogs | where TimeGenerated > ago({TimeRange}) | where IPAddress in (MaliciousIPs) | extend SourceTable = "SigninLogs", MatchedIP = IPAddress),
    (CommonSecurityLog | where TimeGenerated > ago({TimeRange}) | where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs) | extend SourceTable = "CommonSecurityLog", MatchedIP = coalesce(SourceIP, DestinationIP)),
    (DeviceNetworkEvents | where TimeGenerated > ago({TimeRange}) | where RemoteIP in (MaliciousIPs) | extend SourceTable = "DeviceNetworkEvents", MatchedIP = RemoteIP)
| summarize MatchCount = count() by SourceTable, MatchedIP
| order by MatchCount desc
```

### Expiring Indicators — Grid with Urgency

```kql
ThreatIntelligenceIndicator
| where Active == true
| where ExpirationDateTime between (now() .. now() + 7d)
| extend DaysUntilExpiry = datetime_diff("day", ExpirationDateTime, now())
| extend Urgency = case(DaysUntilExpiry <= 1, "🔴 Expiring Today", DaysUntilExpiry <= 3, "🟡 Expiring Soon", "🟢 OK")
| project ThreatType, IndicatorType = case(isnotempty(NetworkIP), "IP", isnotempty(DomainName), "Domain", isnotempty(Url), "URL", isnotempty(FileHashValue), "Hash", "Other"),
          Indicator = coalesce(NetworkIP, DomainName, Url, FileHashValue),
          DaysUntilExpiry, ExpirationDateTime, Urgency, Confidence
| order by DaysUntilExpiry asc
```

---

## 3. Identity & Access Dashboard

### Sign-in Anomalies — Timechart with Anomaly Detection

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| make-series FailedLogins = countif(ResultType != 0) default=0
  on TimeGenerated from ago(30d) to now() step 1h
| extend (anomalies, anomalyScore, baseline) = series_decompose_anomalies(FailedLogins, 1.5)
| render anomalychart with (title="Sign-in Failure Anomalies", anomalyColumns=anomalies)
```

### MFA Coverage — KPI Tile

```kql
SigninLogs
| where TimeGenerated > ago({TimeRange})
| where ResultType == 0  // Successful only
| summarize
    TotalSignins = count(),
    MFASignins = countif(AuthenticationRequirement == "multiFactorAuthentication")
| extend MFACoverage = round(todouble(MFASignins) / todouble(TotalSignins) * 100, 1)
| project TotalSignins, MFASignins, MFACoverage
```

### Risky Users — Grid

```kql
SigninLogs
| where TimeGenerated > ago({TimeRange})
| where RiskLevelDuringSignIn in ("medium", "high")
| summarize
    RiskySignins = count(),
    RiskLevels = make_set(RiskLevelDuringSignIn),
    IPAddresses = make_set(IPAddress, 5),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5),
    Apps = make_set(AppDisplayName, 5),
    LastSeen = max(TimeGenerated)
  by UserPrincipalName
| order by RiskySignins desc
```

### Conditional Access Outcomes — Stacked Bar

```kql
SigninLogs
| where TimeGenerated > ago({TimeRange})
| where ResultType == 0
| mv-expand CAPolicy = ConditionalAccessPolicies
| extend PolicyName = tostring(CAPolicy.displayName)
| extend PolicyResult = tostring(CAPolicy.result)
| where PolicyResult != "notApplied"
| summarize Count = count() by PolicyName, PolicyResult
| render barchart with (title="Conditional Access Policy Outcomes", kind=stacked)
```

### Sign-in Heatmap — Hour vs Day

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType != 0
| extend Hour = datetime_part("Hour", TimeGenerated)
| extend DayOfWeek = case(
    dayofweek(TimeGenerated) == 0d, "Sun",
    dayofweek(TimeGenerated) == 1d, "Mon",
    dayofweek(TimeGenerated) == 2d, "Tue",
    dayofweek(TimeGenerated) == 3d, "Wed",
    dayofweek(TimeGenerated) == 4d, "Thu",
    dayofweek(TimeGenerated) == 5d, "Fri",
    "Sat"
  )
| summarize Count = count() by DayOfWeek, Hour
| order by case(DayOfWeek == "Mon", 1, DayOfWeek == "Tue", 2, DayOfWeek == "Wed", 3, DayOfWeek == "Thu", 4, DayOfWeek == "Fri", 5, DayOfWeek == "Sat", 6, 7), Hour
```

### Geographic Sign-in Map

```kql
SigninLogs
| where TimeGenerated > ago({TimeRange})
| where ResultType != 0
| extend Latitude = todouble(LocationDetails.geoCoordinates.latitude)
| extend Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| where isnotnull(Latitude) and isnotnull(Longitude)
| summarize
    FailureCount = count(),
    Users = dcount(UserPrincipalName)
  by Country, City, Latitude, Longitude
```

---

## 4. Network Security Dashboard

### Firewall Block Summary — KPI Tiles

```kql
CommonSecurityLog
| where TimeGenerated > ago({TimeRange})
| where DeviceAction in ("Deny", "Drop", "Block", "Reject")
| summarize
    TotalBlocks = count(),
    UniqueSourceIPs = dcount(SourceIP),
    UniqueDestPorts = dcount(DestinationPort),
    TopProtocol = arg_max(count(), Protocol)
```

### Top Blocked Source IPs — Bar Chart

```kql
CommonSecurityLog
| where TimeGenerated > ago({TimeRange})
| where DeviceAction in ("Deny", "Drop", "Block", "Reject")
| summarize BlockCount = count() by SourceIP
| top 20 by BlockCount desc
| render barchart with (title="Top Blocked Source IPs")
```

### DNS Query Anomalies

```kql
DnsEvents
| where TimeGenerated > ago({TimeRange})
| extend TLD = tostring(split(Name, ".")[-1])
| extend DomainLength = strlen(Name)
| extend SubdomainLength = strlen(tostring(split(Name, ".")[0]))
| summarize
    QueryCount = count(),
    UniqueSubdomains = dcount(tostring(split(Name, ".")[0])),
    AvgDomainLength = avg(DomainLength),
    MaxSubdomainLength = max(SubdomainLength)
  by Name, ClientIP
| where QueryCount > 100 or MaxSubdomainLength > 30 or UniqueSubdomains > 50
| extend Anomaly = case(
    MaxSubdomainLength > 30, "Long Subdomain (Potential Tunneling)",
    UniqueSubdomains > 50, "High Subdomain Diversity",
    QueryCount > 500, "Excessive Queries",
    "High Volume"
  )
| order by QueryCount desc
```

### Geographic Map — Connection Origins

```kql
CommonSecurityLog
| where TimeGenerated > ago({TimeRange})
| where DeviceAction in ("Deny", "Drop", "Block")
| extend GeoInfo = geo_info_from_ip_address(SourceIP)
| extend Country = tostring(GeoInfo.country)
| extend Latitude = todouble(GeoInfo.latitude)
| extend Longitude = todouble(GeoInfo.longitude)
| where isnotnull(Latitude)
| summarize BlockCount = count() by Country, Latitude, Longitude
```

### Protocol Distribution — Donut Chart

```kql
CommonSecurityLog
| where TimeGenerated > ago({TimeRange})
| summarize Count = count() by ApplicationProtocol
| top 10 by Count desc
| render piechart with (title="Protocol Distribution")
```

### Network Traffic Volume — Area Chart

```kql
CommonSecurityLog
| where TimeGenerated > ago({TimeRange})
| make-series
    InboundMB = sum(ReceivedBytes) / 1048576.0 default=0,
    OutboundMB = sum(SentBytes) / 1048576.0 default=0
  on TimeGenerated from ago({TimeRange}) to now() step 1h
| render areachart with (title="Network Traffic Volume (MB)")
```

---

## 5. Endpoint Security Dashboard

### Malware Detections — Timeline

```kql
DeviceEvents
| where TimeGenerated > ago({TimeRange})
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| extend WasRemediated = tostring(parse_json(AdditionalFields).WasRemediated)
| make-series DetectionCount = count() default=0
  on TimeGenerated from ago({TimeRange}) to now() step 1h
| render timechart with (title="Malware Detections Over Time")
```

### Vulnerability Severity Breakdown — Stacked Bar

```kql
DeviceTvmSoftwareVulnerabilities
| where TimeGenerated > ago(1d)
| summarize VulnCount = dcount(CveId) by DeviceName, VulnerabilitySeverityLevel
| top 20 by VulnCount desc
| render barchart with (title="Vulnerabilities by Device", kind=stacked)
```

### Device Compliance Overview — KPI Tiles

```kql
DeviceInfo
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize
    TotalDevices = count(),
    OnboardedDevices = countif(OnboardingStatus == "Onboarded"),
    HealthyDevices = countif(SensorHealthState == "Active")
| extend
    OnboardedPct = round(todouble(OnboardedDevices) / TotalDevices * 100, 1),
    HealthyPct = round(todouble(HealthyDevices) / TotalDevices * 100, 1)
```

### Top Detected Threats — Grid

```kql
DeviceEvents
| where TimeGenerated > ago({TimeRange})
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| extend WasRemediated = tostring(parse_json(AdditionalFields).WasRemediated)
| summarize
    DetectionCount = count(),
    AffectedDevices = dcount(DeviceName),
    DeviceList = make_set(DeviceName, 10),
    RemediatedCount = countif(WasRemediated == "true")
  by ThreatName
| extend RemediationRate = round(todouble(RemediatedCount) / DetectionCount * 100, 1)
| order by DetectionCount desc
```

### Exposure Level Distribution — Pie

```kql
DeviceInfo
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize Count = count() by ExposureLevel
| render piechart with (title="Device Exposure Levels")
```

---

## 6. Email Security Dashboard

### Phish Blocked — KPI Tiles

```kql
EmailEvents
| where TimeGenerated > ago({TimeRange})
| where EmailDirection == "Inbound"
| summarize
    TotalInbound = count(),
    PhishBlocked = countif(ThreatTypes has "Phish" and DeliveryAction != "Delivered"),
    MalwareBlocked = countif(ThreatTypes has "Malware" and DeliveryAction != "Delivered"),
    SpamBlocked = countif(DeliveryAction == "Junked"),
    PhishDelivered = countif(ThreatTypes has "Phish" and DeliveryAction == "Delivered")
| extend BlockRate = round(todouble(PhishBlocked + MalwareBlocked + SpamBlocked) / TotalInbound * 100, 2)
```

### BEC (Business Email Compromise) Indicators

```kql
EmailEvents
| where TimeGenerated > ago({TimeRange})
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where ThreatTypes has "Phish" or Subject has_any ("urgent", "wire transfer", "payment", "invoice", "CEO", "CFO")
| extend SenderDomain = extract(@"@(.+)$", 1, SenderFromAddress)
// Look for display name spoofing or domain lookalikes
| project TimeGenerated, SenderFromAddress, SenderDisplayName, SenderDomain,
          RecipientEmailAddress, Subject, ThreatTypes, DeliveryLocation
| order by TimeGenerated desc
```

### Email Threat Timeline — Stacked Area

```kql
EmailEvents
| where TimeGenerated > ago({TimeRange})
| where EmailDirection == "Inbound"
| where ThreatTypes != ""
| extend ThreatCategory = case(
    ThreatTypes has "Phish", "Phishing",
    ThreatTypes has "Malware", "Malware",
    ThreatTypes has "Spam", "Spam",
    "Other"
  )
| make-series Count = count() default=0
  on TimeGenerated from ago({TimeRange}) to now() step 1h
  by ThreatCategory
| render areachart with (title="Email Threats Over Time")
```

### Attachment Analysis — Grid

```kql
EmailAttachmentInfo
| where TimeGenerated > ago({TimeRange})
| where MalwareFilterVerdict != "none" and MalwareFilterVerdict != ""
| summarize
    Count = count(),
    UniqueFiles = dcount(SHA256),
    Recipients = make_set(RecipientEmailAddress, 5)
  by FileName, FileType, MalwareFilterVerdict
| order by Count desc
```

### Top Phishing Sender Domains

```kql
EmailEvents
| where TimeGenerated > ago({TimeRange})
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish"
| extend SenderDomain = SenderFromDomain
| summarize PhishCount = count(), TargetedUsers = dcount(RecipientEmailAddress)
  by SenderDomain
| top 20 by PhishCount desc
| render barchart with (title="Top Phishing Sender Domains")
```

---

## 7. Cloud Security Posture Dashboard

### Azure Resource Misconfigurations

```kql
// Track risky Azure operations
AzureActivity
| where TimeGenerated > ago({TimeRange})
| where OperationNameValue has_any (
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/WRITE",
    "MICROSOFT.SQL/SERVERS/FIREWALLRULES/WRITE"
  )
| where ActivityStatusValue == "Succeeded"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Resource
```

### Public-Facing Resources

```kql
AzureActivity
| where TimeGenerated > ago({TimeRange})
| where OperationNameValue has "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| extend Properties_d = parse_json(Properties)
| extend Direction = tostring(Properties_d.direction)
| extend Access = tostring(Properties_d.access)
| extend SourceAddressPrefix = tostring(Properties_d.sourceAddressPrefix)
| where Direction == "Inbound" and Access == "Allow"
| where SourceAddressPrefix in ("*", "0.0.0.0/0", "Internet")
| project TimeGenerated, Caller, ResourceGroup, Resource, SourceAddressPrefix
```

### Azure Activity by Risk Level — Timechart

```kql
AzureActivity
| where TimeGenerated > ago({TimeRange})
| extend RiskLevel = case(
    OperationNameValue has "DELETE", "High",
    OperationNameValue has_any ("WRITE", "CREATE", "ACTION"), "Medium",
    "Low"
  )
| make-series OperationCount = count() default=0
  on TimeGenerated from ago({TimeRange}) to now() step 1h
  by RiskLevel
| render timechart with (title="Azure Operations by Risk Level")
```

### Key Vault Access Monitoring

```kql
AzureDiagnostics
| where TimeGenerated > ago({TimeRange})
| where ResourceType == "VAULTS"
| where OperationName in ("SecretGet", "SecretSet", "SecretDelete", "KeyGet", "KeyCreate", "CertificateGet")
| summarize AccessCount = count() by OperationName, CallerIPAddress, identity_claim_upn_s
| order by AccessCount desc
```

### Resource Group Activity — Bubble Chart Data

```kql
AzureActivity
| where TimeGenerated > ago({TimeRange})
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    DeleteOps = countif(OperationNameValue has "DELETE"),
    WriteOps = countif(OperationNameValue has "WRITE")
  by ResourceGroup
| order by OperationCount desc
| take 20
```

---

## 8. User Behavior Analytics Dashboard

### Anomaly Score Distribution

```kql
BehaviorAnalytics
| where TimeGenerated > ago({TimeRange})
| where InvestigationPriority > 0
| summarize
    AvgPriority = avg(InvestigationPriority),
    MaxPriority = max(InvestigationPriority),
    AnomalyCount = count()
  by UserPrincipalName
| order by MaxPriority desc
| take 50
```

### Peer Comparison — User vs Peer Group

```kql
let targetUser = "{SelectedUser}";
let userDept = toscalar(IdentityInfo | where AccountUPN == targetUser | take 1 | project Department);
// User activity
let UserActivity = SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == targetUser
| summarize UserLogins = count(), UserUniqueApps = dcount(AppDisplayName), UserUniqueIPs = dcount(IPAddress);
// Peer group average
let PeerActivity = SigninLogs
| where TimeGenerated > ago(7d)
| join kind=inner (IdentityInfo | where Department == userDept | project AccountUPN) on $left.UserPrincipalName == $right.AccountUPN
| summarize PeerAvgLogins = avg(count()), PeerAvgApps = avg(dcount(AppDisplayName)), PeerAvgIPs = avg(dcount(IPAddress));
UserActivity | extend PeerAvgLogins = toscalar(PeerActivity | project PeerAvgLogins)
```

### Risk Timeline — User Activity Score

```kql
BehaviorAnalytics
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "{SelectedUser}"
| make-series RiskScore = max(InvestigationPriority) default=0
  on TimeGenerated from ago(30d) to now() step 1d
| extend (anomalies, score, baseline) = series_decompose_anomalies(RiskScore, 1.5)
| render anomalychart with (title="User Risk Score Over Time")
```

### Unusual Activity Types — Grid

```kql
BehaviorAnalytics
| where TimeGenerated > ago({TimeRange})
| where InvestigationPriority >= 3
| extend Insights = parse_json(ActivityInsights)
| project TimeGenerated, UserPrincipalName, ActivityType, ActionType,
          InvestigationPriority, SourceIPAddress, SourceDevice,
          DestinationDevice, Insights
| order by InvestigationPriority desc
```

### First-Time Activities — Grid

```kql
BehaviorAnalytics
| where TimeGenerated > ago({TimeRange})
| extend UserInsights = parse_json(UsersInsights)
| where UserInsights.IsFirstTimeUser == true
    or UserInsights.IsFirstTimeConnection == true
    or UserInsights.IsFirstTimeCountry == true
| project TimeGenerated, UserPrincipalName, ActivityType,
          IsFirstTimeUser = tobool(UserInsights.IsFirstTimeUser),
          IsFirstTimeConnection = tobool(UserInsights.IsFirstTimeConnection),
          IsFirstTimeCountry = tobool(UserInsights.IsFirstTimeCountry),
          SourceIPAddress, InvestigationPriority
| order by InvestigationPriority desc
```

---

## 9. Executive Summary Dashboard

### Single-Page KPI Tiles

```kql
// Overall Security Score
let HighIncidents = toscalar(SecurityIncident | where TimeGenerated > ago(24h) | where Severity == "High" | where Status != "Closed" | count);
let MediumIncidents = toscalar(SecurityIncident | where TimeGenerated > ago(24h) | where Severity == "Medium" | where Status != "Closed" | count);
let LowIncidents = toscalar(SecurityIncident | where TimeGenerated > ago(24h) | where Severity == "Low" | where Status != "Closed" | count);
let Score = max_of(0, 100 - (HighIncidents * 15) - (MediumIncidents * 5) - (LowIncidents * 1));
print
    SecurityScore = Score,
    ScoreColor = case(Score >= 80, "Green", Score >= 60, "Yellow", Score >= 40, "Orange", "Red"),
    HighIncidents = HighIncidents,
    MediumIncidents = MediumIncidents,
    LowIncidents = LowIncidents
```

### Trend Comparison — This Week vs Last Week

```kql
let thisWeek = SecurityIncident | where CreatedTime > ago(7d) | summarize ThisWeek = count() by Severity;
let lastWeek = SecurityIncident | where CreatedTime between (ago(14d) .. ago(7d)) | summarize LastWeek = count() by Severity;
thisWeek
| join kind=fullouter (lastWeek) on Severity
| extend Severity = coalesce(Severity, Severity1)
| extend ThisWeek = coalesce(ThisWeek, 0), LastWeek = coalesce(LastWeek, 0)
| extend Change = ThisWeek - LastWeek
| extend TrendArrow = iff(Change > 0, "↑", iff(Change < 0, "↓", "→"))
| extend ChangePercent = iff(LastWeek > 0, round(todouble(Change) / LastWeek * 100, 1), 0.0)
| project Severity, ThisWeek, LastWeek, Change, TrendArrow, ChangePercent
```

### Top 5 Risk Areas — Summary Grid

```kql
union
    (SigninLogs | where TimeGenerated > ago(24h) | where RiskLevelDuringSignIn in ("high", "medium") | summarize Count = count() | extend Area = "Risky Sign-ins"),
    (SecurityAlert | where TimeGenerated > ago(24h) | where AlertSeverity == "High" | summarize Count = count() | extend Area = "High Severity Alerts"),
    (DeviceEvents | where TimeGenerated > ago(24h) | where ActionType == "AntivirusDetection" | summarize Count = count() | extend Area = "Malware Detections"),
    (EmailEvents | where TimeGenerated > ago(24h) | where ThreatTypes has "Phish" | summarize Count = count() | extend Area = "Phishing Emails"),
    (AzureActivity | where TimeGenerated > ago(24h) | where OperationNameValue has "DELETE" | summarize Count = count() | extend Area = "Azure Deletions")
| order by Count desc
```

### Compliance Quick View

```kql
// MFA adoption, device compliance, sign-in success rates
print
    MFACoverage = toscalar(SigninLogs | where TimeGenerated > ago(24h) | where ResultType == 0 | summarize round(todouble(countif(AuthenticationRequirement == "multiFactorAuthentication")) / count() * 100, 1)),
    SigninSuccessRate = toscalar(SigninLogs | where TimeGenerated > ago(24h) | summarize round(todouble(countif(ResultType == 0)) / count() * 100, 1)),
    DeviceOnboardingRate = toscalar(DeviceInfo | where TimeGenerated > ago(1d) | summarize arg_max(TimeGenerated, *) by DeviceId | summarize round(todouble(countif(OnboardingStatus == "Onboarded")) / count() * 100, 1))
```

---

## Workbook JSON Structure

### Complete Workbook Item Types

| Type ID | Element | Description |
|---|---|---|
| 1 | Markdown | Text, headers, descriptions |
| 3 | Query | KQL query with visualization |
| 9 | Parameters | Time range, dropdowns, subscriptions |
| 10 | Metrics | Azure metrics visualization |
| 11 | Links/Tabs | Navigation tabs, links to other workbooks |
| 12 | Group | Container for grouping items |

### Parameter Types

| Type ID | Parameter Type |
|---|---|
| 1 | Text |
| 2 | Drop-down |
| 4 | Time range |
| 5 | Resource picker |
| 6 | Subscription picker |
| 7 | Resource type picker |
| 8 | Resource group picker |

### Visualization Settings

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "<KQL_QUERY>",
    "size": 0,
    "timeContext": { "durationMs": 86400000 },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces",
    "visualization": "timechart",
    "chartSettings": {
      "xAxis": "TimeGenerated",
      "seriesLabelSettings": [
        { "seriesName": "High", "color": "redBright" },
        { "seriesName": "Medium", "color": "orange" },
        { "seriesName": "Low", "color": "blue" }
      ],
      "ySettings": { "numberFormatSettings": { "unit": 0 } }
    },
    "gridSettings": {
      "formatters": [
        {
          "columnMatch": "Count",
          "formatter": 8,
          "formatOptions": {
            "palette": "coldHot",
            "min": 0
          }
        },
        {
          "columnMatch": "Trend",
          "formatter": 9,
          "formatOptions": {
            "palette": "blue"
          }
        },
        {
          "columnMatch": "Severity",
          "formatter": 18,
          "formatOptions": {
            "thresholdsOptions": "icons",
            "thresholdsGrid": [
              { "operator": "==", "thresholdValue": "High", "representation": "Sev1", "text": "{0}{1}" },
              { "operator": "==", "thresholdValue": "Medium", "representation": "Sev2", "text": "{0}{1}" },
              { "operator": "==", "thresholdValue": "Low", "representation": "Sev3", "text": "{0}{1}" },
              { "operator": "Default", "representation": "Sev4", "text": "{0}{1}" }
            ]
          }
        }
      ],
      "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
    },
    "tileSettings": {
      "titleContent": { "columnMatch": "Label", "formatter": 1 },
      "leftContent": { "columnMatch": "Value", "formatter": 12, "numberFormat": { "unit": 0, "options": { "style": "decimal" } } },
      "secondaryContent": { "columnMatch": "Trend", "formatter": 1 },
      "showBorder": true
    },
    "mapSettings": {
      "locInfo": "LatLong",
      "latitude": "Latitude",
      "longitude": "Longitude",
      "sizeSettings": "Count",
      "minSize": 5,
      "maxSize": 40,
      "defaultSize": 10,
      "labelSettings": "Country",
      "legendMetric": "Count",
      "itemColorSettings": {
        "nodeColorField": "Count",
        "colorAggregation": "Sum",
        "type": "heatmap",
        "heatmapPalette": "greenRed"
      }
    }
  }
}
```

### Grid Formatters Reference

| Formatter ID | Type | Description |
|---|---|---|
| 0 | Default | No formatting |
| 1 | Text | Plain text |
| 4 | Bar chart | Inline bar |
| 5 | Heatmap | Color-coded cells |
| 8 | Heatmap (palette) | Color palette heatmap |
| 9 | Sparkline | Inline sparkline from array |
| 10 | Link | Clickable link |
| 12 | Big number | Large numeric display |
| 15 | URL | Clickable URL |
| 18 | Thresholds | Conditional icons/colors |

---

## ARM Template Deployment

### Complete Workbook ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workbookDisplayName": {
      "type": "string",
      "defaultValue": "SOC Command Center",
      "metadata": {
        "description": "Display name of the workbook"
      }
    },
    "workbookId": {
      "type": "string",
      "defaultValue": "[newGuid()]",
      "metadata": {
        "description": "Unique ID for the workbook resource"
      }
    },
    "workspaceResourceId": {
      "type": "string",
      "metadata": {
        "description": "Full resource ID of the Log Analytics workspace"
      }
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]"
    }
  },
  "variables": {
    "workbookContent": {
      "version": "Notebook/1.0",
      "items": [
        {
          "type": 1,
          "content": {
            "json": "# SOC Command Center\nReal-time security operations overview."
          },
          "name": "header"
        },
        {
          "type": 9,
          "content": {
            "version": "KqlParameterItem/1.0",
            "parameters": [
              {
                "id": "timeRange",
                "name": "TimeRange",
                "type": 4,
                "defaultValue": {
                  "durationMs": 86400000
                },
                "typeSettings": {
                  "selectableValues": [
                    { "durationMs": 3600000 },
                    { "durationMs": 14400000 },
                    { "durationMs": 43200000 },
                    { "durationMs": 86400000 },
                    { "durationMs": 259200000 },
                    { "durationMs": 604800000 }
                  ]
                }
              }
            ]
          },
          "name": "parameters"
        },
        {
          "type": 3,
          "content": {
            "version": "KqlItem/1.0",
            "query": "SecurityIncident\n| where TimeGenerated > ago({TimeRange})\n| where Status in ('New', 'Active')\n| summarize Count = count() by Severity\n| order by case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, 4) asc",
            "size": 4,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": "tiles",
            "tileSettings": {
              "titleContent": {
                "columnMatch": "Severity",
                "formatter": 1
              },
              "leftContent": {
                "columnMatch": "Count",
                "formatter": 12,
                "numberFormat": {
                  "unit": 0,
                  "options": { "style": "decimal" }
                }
              },
              "showBorder": true
            }
          },
          "name": "incidentTiles"
        }
      ],
      "isLocked": false
    }
  },
  "resources": [
    {
      "type": "Microsoft.Insights/workbooks",
      "apiVersion": "2022-04-01",
      "name": "[parameters('workbookId')]",
      "location": "[parameters('location')]",
      "kind": "shared",
      "properties": {
        "displayName": "[parameters('workbookDisplayName')]",
        "serializedData": "[string(variables('workbookContent'))]",
        "version": "1.0",
        "sourceId": "[parameters('workspaceResourceId')]",
        "category": "sentinel"
      }
    }
  ],
  "outputs": {
    "workbookId": {
      "type": "string",
      "value": "[resourceId('Microsoft.Insights/workbooks', parameters('workbookId'))]"
    }
  }
}
```

### Multi-Workbook Deployment Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspaceResourceId": {
      "type": "string"
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]"
    }
  },
  "variables": {
    "workbooks": [
      {
        "name": "[guid('soc-command-center')]",
        "displayName": "SOC Command Center",
        "category": "sentinel"
      },
      {
        "name": "[guid('threat-intel')]",
        "displayName": "Threat Intelligence",
        "category": "sentinel"
      },
      {
        "name": "[guid('identity-access')]",
        "displayName": "Identity & Access",
        "category": "sentinel"
      },
      {
        "name": "[guid('network-security')]",
        "displayName": "Network Security",
        "category": "sentinel"
      },
      {
        "name": "[guid('endpoint-security')]",
        "displayName": "Endpoint Security",
        "category": "sentinel"
      },
      {
        "name": "[guid('email-security')]",
        "displayName": "Email Security",
        "category": "sentinel"
      },
      {
        "name": "[guid('cloud-posture')]",
        "displayName": "Cloud Security Posture",
        "category": "sentinel"
      },
      {
        "name": "[guid('user-behavior')]",
        "displayName": "User Behavior Analytics",
        "category": "sentinel"
      },
      {
        "name": "[guid('executive-summary')]",
        "displayName": "Executive Summary",
        "category": "sentinel"
      }
    ]
  },
  "resources": [
    {
      "copy": {
        "name": "workbookCopy",
        "count": "[length(variables('workbooks'))]"
      },
      "type": "Microsoft.Insights/workbooks",
      "apiVersion": "2022-04-01",
      "name": "[variables('workbooks')[copyIndex()].name]",
      "location": "[parameters('location')]",
      "kind": "shared",
      "properties": {
        "displayName": "[variables('workbooks')[copyIndex()].displayName]",
        "serializedData": "{}",
        "version": "1.0",
        "sourceId": "[parameters('workspaceResourceId')]",
        "category": "[variables('workbooks')[copyIndex()].category]"
      }
    }
  ]
}
```

### Deploy Commands

```bash
# Validate template
az deployment group validate \
  --resource-group myResourceGroup \
  --template-file workbook-template.json \
  --parameters workspaceResourceId="/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws-name>"

# Deploy single workbook
az deployment group create \
  --resource-group myResourceGroup \
  --template-file workbook-template.json \
  --parameters workspaceResourceId="/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws-name>" \
  --parameters workbookDisplayName="SOC Command Center"

# Deploy all workbooks
az deployment group create \
  --resource-group myResourceGroup \
  --template-file multi-workbook-template.json \
  --parameters workspaceResourceId="/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws-name>"
```

### GitHub Actions CI/CD Pipeline

```yaml
name: Deploy Sentinel Workbooks

on:
  push:
    branches: [main]
    paths:
      - 'workbooks/**'
      - 'skills/kql-sentinel-specialist/references/workbooks.md'

  workflow_dispatch:
    inputs:
      workbook:
        description: 'Specific workbook to deploy (or "all")'
        required: true
        default: 'all'

permissions:
  id-token: write
  contents: read

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Validate ARM templates
        run: |
          for template in workbooks/*.json; do
            echo "Validating $template..."
            az deployment group validate \
              --resource-group ${{ vars.RESOURCE_GROUP }} \
              --template-file "$template" \
              --parameters workspaceResourceId="${{ vars.WORKSPACE_RESOURCE_ID }}"
          done

  deploy:
    needs: validate
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy workbooks
        run: |
          for template in workbooks/*.json; do
            echo "Deploying $template..."
            az deployment group create \
              --resource-group ${{ vars.RESOURCE_GROUP }} \
              --template-file "$template" \
              --parameters workspaceResourceId="${{ vars.WORKSPACE_RESOURCE_ID }}" \
              --name "workbook-$(basename $template .json)-$(date +%Y%m%d%H%M%S)"
          done

      - name: Verify deployment
        run: |
          az resource list \
            --resource-group ${{ vars.RESOURCE_GROUP }} \
            --resource-type "Microsoft.Insights/workbooks" \
            --query "[].{Name:name, DisplayName:properties.displayName}" \
            --output table
```

### Azure DevOps Pipeline

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - workbooks/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  azureServiceConnection: 'AzureServiceConnection'
  resourceGroup: 'rg-sentinel'
  workspaceResourceId: '/subscriptions/$(subscriptionId)/resourceGroups/$(resourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$(workspaceName)'

stages:
  - stage: Validate
    jobs:
      - job: ValidateTemplates
        steps:
          - task: AzureCLI@2
            displayName: 'Validate ARM Templates'
            inputs:
              azureSubscription: $(azureServiceConnection)
              scriptType: bash
              scriptLocation: inlineScript
              inlineScript: |
                for template in workbooks/*.json; do
                  az deployment group validate \
                    --resource-group $(resourceGroup) \
                    --template-file "$template" \
                    --parameters workspaceResourceId="$(workspaceResourceId)"
                done

  - stage: Deploy
    dependsOn: Validate
    jobs:
      - deployment: DeployWorkbooks
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - checkout: self
                - task: AzureResourceManagerTemplateDeployment@3
                  displayName: 'Deploy Workbooks'
                  inputs:
                    azureResourceManagerConnection: $(azureServiceConnection)
                    resourceGroupName: $(resourceGroup)
                    location: 'eastus'
                    templateLocation: 'Linked artifact'
                    csmFile: 'workbooks/multi-workbook-template.json'
                    overrideParameters: '-workspaceResourceId $(workspaceResourceId)'
```

### Bicep Alternative (Modern IaC)

```bicep
param workbookDisplayName string = 'SOC Command Center'
param workbookId string = newGuid()
param workspaceResourceId string
param location string = resourceGroup().location

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: loadTextContent('workbook-content.json')
    version: '1.0'
    sourceId: workspaceResourceId
    category: 'sentinel'
  }
}

output workbookResourceId string = workbook.id
```
