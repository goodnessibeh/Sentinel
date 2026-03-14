---
name: kql-sentinel-specialist
description: Expert KQL skill for Microsoft Sentinel, Defender XDR, and Azure Monitor. Covers complete KQL syntax, all security log tables, Syslog/CEF parsing, ASIM normalization, detection rule engineering with MITRE ATT&CK mapping, threat hunting, workbook dashboard design, and ARM template deployment. Use when writing KQL queries, building detection rules, creating Sentinel workbooks, or analyzing security logs.
---

# KQL Sentinel Specialist

## Quick Start — Decision Tree

**What are you trying to do?**

| Task | Go To |
|---|---|
| Write a KQL query from scratch | → Core KQL Syntax |
| Find the right table for my data | → Log Tables Quick Reference / `references/tables.md` |
| Parse Syslog, CEF, or custom logs | → Syslog & CEF Parsing / `references/syslog_parsing.md` |
| Build a Sentinel detection rule | → Detection Engineering / `references/detections.md` |
| Hunt for threats | → Threat Hunting Patterns |
| Create a Sentinel workbook | → Workbook Design / `references/workbooks.md` |
| Deploy workbooks via ARM/IaC | → ARM Template Deployment / `references/workbooks.md` |
| Optimize a slow query | → Performance Rules |

---

## Core KQL Syntax

### Query Structure

Every KQL query flows left-to-right through a pipeline:

```kql
TableName
| where TimeGenerated > ago(24h)       // 1. Time filter FIRST
| where Column has "value"              // 2. Filter rows
| extend NewCol = expression            // 3. Compute new columns
| project Col1, Col2, NewCol            // 4. Select columns
| summarize count() by Col1             // 5. Aggregate
| order by count_ desc                  // 6. Sort
| take 100                              // 7. Limit
```

### Tabular Operators (Complete Reference)

| Operator | Purpose | Example |
|---|---|---|
| `where` | Filter rows | `where Status == "Failed"` |
| `extend` | Add computed column | `extend Duration = EndTime - StartTime` |
| `project` | Select/rename columns | `project UserName, IP = IPAddress` |
| `project-away` | Remove columns | `project-away TenantId, Type` |
| `project-rename` | Rename only | `project-rename User = AccountName` |
| `project-reorder` | Reorder columns | `project-reorder TimeGenerated, User, ...` |
| `project-keep` | Keep matching columns | `project-keep *Name*, TimeGenerated` |
| `summarize` | Aggregate | `summarize count() by bin(TimeGenerated, 1h)` |
| `distinct` | Unique values | `distinct UserPrincipalName` |
| `top` | Top N by column | `top 10 by count_ desc` |
| `take` / `limit` | Return N rows | `take 100` |
| `order by` / `sort by` | Sort | `order by TimeGenerated desc` |
| `join` | Combine tables | `join kind=inner (T2) on Key` |
| `union` | Stack tables | `union SecurityEvent, WindowsEvent` |
| `lookup` | Dimension lookup | `lookup kind=leftouter Users on UserId` |
| `mv-expand` | Expand arrays | `mv-expand AlertIds` |
| `mv-apply` | Apply per element | `mv-apply e = Entities on (where e.Type == "account")` |
| `parse` | Extract from string | `parse Message with * "user=" User " "` |
| `parse-where` | Parse + filter | `parse-where Message with "src=" IP:string` |
| `evaluate` | Plugin functions | `evaluate bag_unpack(DynamicCol)` |
| `render` | Visualize | `render timechart` |
| `as` | Name subquery | `T | where x > 0 | as hint.materialized=true T1` |
| `invoke` | Call function | `invoke MyFunction()` |
| `fork` | Parallel branches | `fork (summarize count()) (top 10 by x)` |
| `facet by` | Multi-dim breakdown | `facet by Status, User` |
| `sample` | Random sample | `sample 100` |
| `sample-distinct` | Distinct sample | `sample-distinct 10 of UserName` |
| `search` | Free-text search | `search "malware"` |
| `find` | Find across tables | `find where Account == "admin"` |
| `getschema` | Show schema | `SecurityEvent | getschema` |
| `count` | Count rows | `SecurityEvent | count` |
| `serialize` | Enable row_number | `serialize | extend rn = row_number()` |
| `range` | Generate series | `range x from 1 to 10 step 1` |
| `datatable` | Inline table | `datatable(Name:string, Value:int)["A",1]` |
| `externaldata` | External source | `externaldata(IP:string)[h@"https://..."] with (format="csv")` |
| `print` | Print expression | `print result = strcat("hello", " world")` |

### String Operators (Performance Hierarchy — Use the Fastest That Works)

**CRITICAL: Choose operators from top to bottom. Higher = faster.**

| Operator | Case Sensitive | Description | Performance |
|---|---|---|---|
| `==` | Yes | Exact match | ⚡ Fastest — indexed |
| `has` | No | Whole-term match | ⚡ Very fast — indexed |
| `has_cs` | Yes | Whole-term match (case-sensitive) | ⚡ Very fast — indexed |
| `has_any` | No | Any term in list | ⚡ Fast — indexed |
| `has_all` | No | All terms present | ⚡ Fast — indexed |
| `!has` | No | Negated has | ⚡ Fast |
| `in` | Yes | Exact match in list | ⚡ Fast — indexed |
| `in~` | No | Case-insensitive in | ⚡ Fast |
| `startswith` | No | Prefix match | 🟡 Medium |
| `startswith_cs` | Yes | Prefix match (CS) | 🟡 Medium |
| `endswith` | No | Suffix match | 🟡 Medium |
| `contains` | No | Substring anywhere | 🔴 Slow — full scan |
| `contains_cs` | Yes | Substring (CS) | 🔴 Slow |
| `matches regex` | Yes | Full regex | 🔴 Slowest — full scan |

**Rule: If `has` works, NEVER use `contains`. If `==` works, NEVER use `has`.**

### Numeric and Comparison Operators

```kql
| where Value == 42
| where Value != 0
| where Value > 100
| where Value >= 50 and Value <= 200
| where Value between (10 .. 100)
| where Value !between (0 .. 5)
| where isnotnull(Value)
| where isnotempty(StringCol)
| where isnan(FloatCol)  // NaN check
```

### Logical Operators

```kql
| where A and B
| where A or B
| where not(A)
| where A and (B or C)
```

### DateTime Functions (Complete)

```kql
// Time filtering
| where TimeGenerated > ago(1h)
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-01-31))
| where TimeGenerated > startofday(now())
| where TimeGenerated > startofweek(now())
| where TimeGenerated > startofmonth(now())
| where TimeGenerated > startofyear(now())

// Time extraction
| extend Hour = datetime_part("Hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)        // timespan
| extend DayOfMonth = dayofmonth(TimeGenerated)
| extend DayOfYear = dayofyear(TimeGenerated)
| extend WeekOfYear = week_of_year(TimeGenerated)
| extend MonthOfYear = monthofyear(TimeGenerated)
| extend Year = getyear(TimeGenerated)

// Time binning
| summarize count() by bin(TimeGenerated, 1h)
| summarize count() by bin(TimeGenerated, 5m)
| summarize count() by bin_at(TimeGenerated, 1h, datetime(2024-01-01))

// Time arithmetic
| extend Tomorrow = TimeGenerated + 1d
| extend Duration = EndTime - StartTime
| extend DurationMinutes = datetime_diff("minute", EndTime, StartTime)

// Time formatting
| extend Formatted = format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss")
| extend UnixTime = unixtime_seconds_todatetime(EpochColumn)
| extend Epoch = datetime_to_unixtime(TimeGenerated)

// Time constants
ago(30d), ago(4h), ago(15m), ago(30s)
now(), now(-1d), now(1h)
datetime(2024-06-15T10:30:00Z)
```

### Aggregation Functions (Complete)

```kql
// Counting
count()                          // Row count
countif(Condition)               // Conditional count
dcount(Column)                   // Distinct count (HyperLogLog)
dcountif(Column, Condition)      // Conditional distinct count
count_distinct(Column)           // Exact distinct count (slower)

// Math
sum(Column), sumif(Col, Cond)
avg(Column), avgif(Col, Cond)
min(Column), minif(Col, Cond)
max(Column), maxif(Col, Cond)
stdev(Column), stdevif(Col, Cond)
variance(Column)
percentile(Column, 95)
percentiles(Column, 50, 90, 95, 99)
percentile_array(Column, dynamic([50, 90, 95, 99]))

// Collection
make_list(Column)                // Collect into array
make_list_if(Col, Cond)
make_set(Column)                 // Distinct values array
make_set_if(Col, Cond)
make_bag(DynamicCol)             // Merge property bags

// Statistical
arg_max(Column, *)               // Row with max value (return all columns)
arg_min(Column, *)               // Row with min value
any(Column)                      // Any value (non-deterministic)
take_any(Column)                 // Alias for any

// Time series
make_series count() default=0 on TimeGenerated from ago(7d) to now() step 1h
```

### Join Types

```kql
// Inner — only matching rows from both sides
T1 | join kind=inner (T2) on CommonKey

// Left outer — all rows from left, matching from right (nulls if no match)
T1 | join kind=leftouter (T2) on CommonKey

// Right outer — all rows from right, matching from left
T1 | join kind=rightouter (T2) on CommonKey

// Full outer — all rows from both sides
T1 | join kind=fullouter (T2) on CommonKey

// Left semi — rows from left that have a match in right (no right columns)
T1 | join kind=leftsemi (T2) on CommonKey

// Left anti — rows from left that have NO match in right
T1 | join kind=leftanti (T2) on CommonKey

// Right semi / Right anti — mirror of left variants
T1 | join kind=rightsemi (T2) on CommonKey
T1 | join kind=rightanti (T2) on CommonKey

// Inner unique — deduplicate right side first (DEFAULT if kind omitted)
T1 | join kind=innerunique (T2) on CommonKey

// Join on multiple keys
T1 | join (T2) on Key1, $left.LeftKey == $right.RightKey

// Join hints for performance
T1 | join hint.strategy=shuffle (T2) on Key      // Large-large join
T1 | join hint.strategy=broadcast (T2) on Key     // Small right table
T1 | join hint.num_partitions=4 (T2) on Key       // Partition hint
```

### Advanced Patterns

#### let Statements (Variables, Functions, Tabular)

```kql
// Scalar variable
let threshold = 5;
let lookback = 14d;
let targetUser = "admin@contoso.com";

// Dynamic list
let watchlist = dynamic(["10.0.0.1", "10.0.0.2", "192.168.1.100"]);

// Tabular expression
let FailedLogins = SigninLogs
    | where ResultType != 0
    | where TimeGenerated > ago(1h);

// User-defined function
let GetSeverity = (count:long) {
    case(count > 100, "Critical",
         count > 50, "High",
         count > 10, "Medium",
         "Low")
};

// Function with tabular input
let EnrichWithGeo = (T:(IPAddress:string)) {
    T | extend GeoInfo = geo_info_from_ip_address(IPAddress)
};
```

#### materialize — Cache Intermediate Results

```kql
let cachedData = materialize(
    SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID in (4624, 4625)
);
// Reuse without recomputation
cachedData | where EventID == 4624 | summarize Successes = count();
cachedData | where EventID == 4625 | summarize Failures = count();
```

#### mv-expand and mv-apply

```kql
// Expand dynamic array to rows
SecurityAlert
| mv-expand Entity = Entities
| extend EntityType = tostring(Entity.Type)

// Apply logic per array element
SecurityAlert
| mv-apply Entity = todynamic(Entities) on (
    where Entity.Type == "ip"
    | project IP = tostring(Entity.Address)
)
```

#### Dynamic / JSON Operations

```kql
// Parse JSON
| extend Parsed = parse_json(RawData)
| extend UserName = tostring(Parsed.user.name)
| extend Count = toint(Parsed.stats.count)

// Property bag
| extend Props = bag_pack("user", UserName, "ip", IPAddress)
| evaluate bag_unpack(CustomFields)

// Array operations
| where array_length(Entities) > 0
| extend FirstEntity = Entities[0]
| where set_has_element(IPList, IPAddress)
| extend Combined = array_concat(List1, List2)
| extend Sorted = array_sort_asc(Values)
```

#### parse Operator

```kql
// Simple parse
| parse Message with * "User " UserName " logged in from " IPAddress

// Parse with type hints
| parse Message with "Duration: " Duration:long "ms, Status: " Status:string

// Parse using regex
| parse kind=regex Message with @"src=(?P<SourceIP>\d+\.\d+\.\d+\.\d+)"

// Parse-where (only rows that match)
| parse-where Message with "Failed login for " User " from " IP
```

#### String Functions

```kql
strlen(s), tolower(s), toupper(s), trim(" ", s)
substring(s, start, length)
strcat(s1, s2, s3)                  // Concatenate
strcat_delim("-", s1, s2, s3)       // With delimiter
replace_string(s, old, new)
replace_regex(s, @"\d+", "NUM")     // Regex replace
split(s, delimiter)                  // Returns array
strcat_array(arr, delimiter)         // Array to string
extract(@"pattern(capture)", 1, s)  // Regex extract
extract_all(@"pattern", s)          // All matches
countof(s, "substring")             // Count occurrences
indexof(s, "sub")                   // First position (-1 if not found)
reverse(s)
hash_sha256(s), hash_md5(s)         // Hashing
base64_encode_tostring(s)
base64_decode_tostring(s)
url_encode(s), url_decode(s)
parse_url(s), parse_urlquery(s)
parse_path(s)
parse_json(s), parse_xml(s), parse_csv(s)
ipv4_is_private(ip)                 // Private range check
ipv4_is_in_range(ip, "10.0.0.0/8") // CIDR check
ipv4_compare(ip1, ip2)
format_ipv4(ip, prefix)             // Normalize IP
geo_info_from_ip_address(ip)        // GeoIP lookup
```

#### Conditional Functions

```kql
// iff — ternary
| extend Status = iff(ResultType == 0, "Success", "Failure")

// case — multi-branch
| extend Severity = case(
    Score > 90, "Critical",
    Score > 70, "High",
    Score > 40, "Medium",
    "Low"
  )

// coalesce — first non-null
| extend Name = coalesce(DisplayName, UserPrincipalName, AccountName, "Unknown")

// max_of / min_of — scalar max/min
| extend Latest = max_of(Time1, Time2, Time3)
```

#### Time Series and Anomaly Detection

```kql
// Create time series
SigninLogs
| make-series LoginCount=count() default=0
  on TimeGenerated from ago(30d) to now() step 1h

// Anomaly detection
| extend (anomalies, score, baseline) = series_decompose_anomalies(LoginCount, 1.5)

// Seasonal decomposition
| extend (baseline, seasonal, trend, residual) = series_decompose(LoginCount)

// Forecasting
| extend forecast = series_decompose_forecast(LoginCount, 24) // 24 points ahead

// Statistics on series
| extend (min, min_idx, max, max_idx, avg, stdev, variance) = series_stats(LoginCount)

// Sliding window
| extend MovingAvg = series_fir(LoginCount, repeat(1, 24), true, true) // 24-point moving avg

// Outlier detection
| extend outliers = series_outliers(LoginCount)
```

#### Row-Level Functions

```kql
// Row number
| serialize | extend RowNum = row_number()

// Previous/Next row
| serialize | extend PrevIP = prev(IPAddress), NextIP = next(IPAddress)

// Row cumulative sum
| serialize | extend RunningTotal = row_cumsum(Count)

// Sliding window aggregate
| serialize | extend WindowSum = row_window_session(TimeGenerated, 5m, 1h, Status == "Failed")
```

---

## Performance Rules

**Strict query optimization order — follow ALWAYS:**

### 1. Time Filter FIRST
```kql
// ✅ CORRECT — time filter is the first where clause
TableName
| where TimeGenerated > ago(24h)
| where EventID == 4625

// ❌ WRONG — filtering before time
TableName
| where EventID == 4625
| where TimeGenerated > ago(24h)
```

### 2. Use `has` Before `contains`
```kql
// ✅ FAST — has uses term index
| where CommandLine has "powershell"

// ❌ SLOW — contains does full scan
| where CommandLine contains "powershell"
```

### 3. Project Early, Project Often
```kql
// ✅ Drop unnecessary columns early
SecurityEvent
| where TimeGenerated > ago(1h)
| project TimeGenerated, Account, Computer, EventID
| where EventID == 4625
```

### 4. Filter Before Join
```kql
// ✅ Filter both sides before joining
let Failures = SigninLogs | where TimeGenerated > ago(1h) | where ResultType != 0;
let Users = IdentityInfo | where TimeGenerated > ago(1d) | project AccountUPN, Department;
Failures | join kind=leftouter (Users) on $left.UserPrincipalName == $right.AccountUPN
```

### 5. Use Join Hints
```kql
// For large-to-large joins
| join hint.strategy=shuffle (LargeTable) on Key

// For small right table
| join hint.strategy=broadcast (SmallLookup) on Key
```

### 6. Prefer `summarize` Over `distinct` When Counting
```kql
// ✅ Efficient
| summarize dcount(UserPrincipalName)

// ❌ Less efficient for large datasets
| distinct UserPrincipalName | count
```

### 7. Anti-Patterns to AVOID

| Anti-Pattern | Why It's Bad | Fix |
|---|---|---|
| `contains` when `has` works | Full scan vs indexed | Use `has` |
| `*` in project | Transfers all columns | Name specific columns |
| Joining without time filter | Cross-product explosion | Filter both sides first |
| `search *` | Scans all tables | Target specific table |
| `matches regex` for simple patterns | Full scan | Use `has`/`startswith` |
| Nested `toscalar()` in where | Runs subquery per row | Use `let` + `join` |
| Multiple `extend` that could be one | Extra pipeline steps | Combine extends |
| `order by` before `take` on large data | Sorts everything | Use `top N by col` |

---

## Log Tables Quick Reference

> Full schemas with all columns: see `references/tables.md`

### Windows Security

| Table | Purpose | Key Columns |
|---|---|---|
| `SecurityEvent` | Windows Security Event Log | EventID, Account, Computer, Activity, LogonType |
| `WindowsEvent` | New Windows event format | EventID, EventData (dynamic), Computer |
| `Event` | Windows System/Application log | EventLog, EventID, Source, RenderedDescription |
| `WindowsFirewall` | Windows Firewall logs | Action, Protocol, SourceIP, DestinationIP |

### Identity & Access (Entra ID)

| Table | Purpose | Key Columns |
|---|---|---|
| `SigninLogs` | Interactive sign-ins | UserPrincipalName, ResultType, IPAddress, Location, AppDisplayName |
| `AADNonInteractiveUserSignInLogs` | Non-interactive sign-ins | Same schema as SigninLogs |
| `AADServicePrincipalSignInLogs` | Service principal sign-ins | ServicePrincipalName, IPAddress |
| `AADManagedIdentitySignInLogs` | Managed identity sign-ins | ServicePrincipalName |
| `AuditLogs` | Entra ID directory changes | OperationName, Category, Result, TargetResources, InitiatedBy |
| `IdentityInfo` (UEBA) | User enrichment | AccountUPN, Department, JobTitle, Manager, RiskLevel |

### Microsoft 365

| Table | Purpose | Key Columns |
|---|---|---|
| `OfficeActivity` | M365 audit events | Operation, UserId, ClientIP, OfficeWorkload |
| `EmailEvents` | Email metadata (Defender) | SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction |
| `EmailAttachmentInfo` | Attachment details | FileName, FileType, SHA256, MalwareFilterVerdict |
| `EmailUrlInfo` | URLs in emails | Url, UrlDomain, UrlLocation |
| `EmailPostDeliveryEvents` | Post-delivery actions | Action (ZAP, Manual removal), ActionType |

### Defender for Endpoint

| Table | Purpose | Key Columns |
|---|---|---|
| `DeviceProcessEvents` | Process creation | FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName |
| `DeviceNetworkEvents` | Network connections | RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName |
| `DeviceFileEvents` | File operations | FileName, FolderPath, SHA256, ActionType |
| `DeviceRegistryEvents` | Registry changes | RegistryKey, RegistryValueName, RegistryValueData, ActionType |
| `DeviceLogonEvents` | Device logons | AccountName, LogonType, RemoteIP |
| `DeviceImageLoadEvents` | DLL loads | FileName, FolderPath, SHA256, InitiatingProcessFileName |
| `DeviceEvents` | Misc device events | ActionType, AdditionalFields |
| `DeviceInfo` | Device inventory | DeviceName, OSPlatform, OSVersion, PublicIP |
| `DeviceNetworkInfo` | Network config | NetworkAdapterType, IPAddresses, MacAddress |
| `DeviceTvmSoftwareInventory` | Software inventory | SoftwareName, SoftwareVersion, CveId |
| `DeviceTvmSoftwareVulnerabilities` | Vulnerabilities | CveId, VulnerabilitySeverityLevel |

### Defender for Identity

| Table | Purpose | Key Columns |
|---|---|---|
| `IdentityLogonEvents` | AD logon events | AccountUpn, LogonType, Protocol, DestinationDeviceName |
| `IdentityQueryEvents` | AD queries (LDAP, DNS) | QueryType, QueryTarget, AccountUpn |
| `IdentityDirectoryEvents` | AD directory changes | ActionType, TargetAccountUpn, Application |

### Syslog & Linux

| Table | Purpose | Key Columns |
|---|---|---|
| `Syslog` | Linux syslog | Facility, SeverityLevel, SyslogMessage, HostName, ProcessName |
| `CommonSecurityLog` | CEF-formatted logs | DeviceVendor, DeviceProduct, Activity, SourceIP, DestinationIP |

### Azure Platform

| Table | Purpose | Key Columns |
|---|---|---|
| `AzureActivity` | Azure control plane | OperationNameValue, CategoryValue, Caller, ResourceGroup |
| `AzureDiagnostics` | Azure resource logs | ResourceType, Category, OperationName, ResultType |
| `AzureMetrics` | Azure metrics | MetricName, Average, Total, ResourceId |

### Threat Intelligence

| Table | Purpose | Key Columns |
|---|---|---|
| `ThreatIntelligenceIndicator` | IOCs | ThreatType, DomainName, NetworkIP, Url, FileHashValue, ExpirationDateTime |

### UEBA & Behavior

| Table | Purpose | Key Columns |
|---|---|---|
| `BehaviorAnalytics` | UEBA anomalies | UserPrincipalName, ActivityType, InvestigationPriority, UsersInsights |
| `IdentityInfo` | Identity enrichment | AccountUPN, Department, JobTitle, Manager, City, Country |

### Sentinel Internal

| Table | Purpose | Key Columns |
|---|---|---|
| `SecurityAlert` | All provider alerts | AlertName, AlertSeverity, Entities, Tactics, ProviderName |
| `SecurityIncident` | Sentinel incidents | Title, Severity, Status, Owner, Labels |
| `Watchlist` | Watchlist items | WatchlistAlias, SearchKey, LastUpdatedTimeUTC |
| `_GetWatchlist('alias')` | Query watchlist | Returns watchlist as table |

### ASIM Normalized Tables

| Parser Function | Source Tables | Schema |
|---|---|---|
| `_Im_Authentication()` | SigninLogs, SecurityEvent, Syslog | TargetUsername, SrcIpAddr, EventResult |
| `_Im_NetworkSession()` | CommonSecurityLog, AzureNSG, WindowsFirewall | SrcIpAddr, DstIpAddr, DstPortNumber |
| `_Im_Dns()` | DnsEvents, Syslog, CommonSecurityLog | DnsQuery, DnsResponseName, SrcIpAddr |
| `_Im_ProcessCreate()` | SecurityEvent, DeviceProcessEvents | TargetProcessName, TargetProcessCommandLine, ActorUsername |
| `_Im_FileEvent()` | DeviceFileEvents, SecurityEvent | TargetFileName, TargetFilePath, ActorUsername |
| `_Im_WebSession()` | CommonSecurityLog, AzureDiagnostics | Url, DstIpAddr, HttpStatusCode |
| `_Im_RegistryEvent()` | DeviceRegistryEvents, SecurityEvent | RegistryKey, RegistryValue, ActorUsername |
| `_Im_AuditEvent()` | AuditLogs, AzureActivity | Operation, ActorUsername, Object |

---

## Syslog & CEF Parsing

> Full parsing patterns, facility codes, and ASIM details: see `references/syslog_parsing.md`

### Linux Syslog Quick Patterns

```kql
// SSH authentication failures
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage has "Failed password"
| parse SyslogMessage with * "Failed password for " User " from " SourceIP " port " *

// Sudo usage
Syslog
| where ProcessName == "sudo"
| parse SyslogMessage with * "USER=" TargetUser " ; COMMAND=" Command

// Firewall blocks (iptables/nftables)
Syslog
| where SyslogMessage has "BLOCKED" or SyslogMessage has "DROP"
| parse SyslogMessage with * "SRC=" SrcIP " DST=" DstIP " " * "DPT=" DstPort " " *
```

### CEF Parsing

```kql
// CEF is already parsed into CommonSecurityLog columns
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where Activity has "TRAFFIC"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DeviceAction, ApplicationProtocol, SentBytes, ReceivedBytes

// Map CEF severity to readable
| extend SeverityName = case(
    LogSeverity == 10, "Critical",
    LogSeverity >= 7, "High",
    LogSeverity >= 4, "Medium",
    LogSeverity >= 1, "Low",
    "Informational"
  )
```

### ASIM Parser Usage

```kql
// Use ASIM for vendor-agnostic queries
_Im_Authentication(starttime=ago(1h), eventresult="Failure")
| summarize FailureCount = count() by TargetUsername, SrcIpAddr
| where FailureCount > 10

// ASIM DNS for any source
_Im_Dns(starttime=ago(24h))
| where DnsQuery has_any ("malware.com", "c2server.net")
```

---

## Detection Engineering

> Full detection library with 40+ queries and MITRE mapping: see `references/detections.md`

### Rule Types

| Type | Trigger | Latency | Use Case |
|---|---|---|---|
| **Scheduled** | Runs on interval (5m–14d) | Minutes | Most detections |
| **NRT (Near Real-Time)** | Every ~1 minute | Seconds | High-priority threats |
| **Fusion** | ML correlation | Minutes | Multi-stage attacks |
| **Anomaly** | Statistical baseline | Hours | UEBA-based detections |
| **Threat Intelligence** | IOC matching | Minutes | Known bad indicators |

### Analytics Rule Structure

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Brute Force Against User Account",
    "description": "Detects multiple failed sign-in attempts followed by success",
    "severity": "Medium",
    "enabled": true,
    "query": "<KQL_QUERY>",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT5H",
    "suppressionEnabled": false,
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [
          { "identifier": "FullName", "columnName": "UserPrincipalName" }
        ]
      },
      {
        "entityType": "IP",
        "fieldMappings": [
          { "identifier": "Address", "columnName": "IPAddress" }
        ]
      }
    ]
  }
}
```

### Severity & Confidence Framework

| Severity | Confidence Required | False Positive Tolerance | Example |
|---|---|---|---|
| **Informational** | Low | High | Anomalous but not malicious |
| **Low** | Low-Medium | Medium | Policy violation |
| **Medium** | Medium | Low | Suspicious activity needing triage |
| **High** | High | Very Low | Likely malicious activity |

### Entity Mapping Types

| Entity Type | Identifiers | Example Column |
|---|---|---|
| Account | FullName, Name, UPNSuffix, Sid, AadUserId | UserPrincipalName |
| Host | HostName, FullName, DnsDomain, AzureID | Computer |
| IP | Address | IPAddress |
| URL | Url | RequestUrl |
| FileHash | Algorithm, Value | SHA256 |
| File | Name, Directory | FileName |
| Process | ProcessId, CommandLine | ProcessCommandLine |
| MailMessage | Recipient, Sender, Subject | RecipientEmailAddress |
| Mailbox | MailboxPrimaryAddress | UserPrincipalName |
| CloudApplication | AppId, Name | AppDisplayName |

### Quick Detection Patterns

```kql
// Brute force: multiple failures then success
let threshold = 10;
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| summarize
    FailureCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0),
    IPAddresses = make_set(IPAddress),
    FailureTimes = make_list_if(TimeGenerated, ResultType != 0)
  by UserPrincipalName
| where FailureCount >= threshold and SuccessCount > 0

// Encoded PowerShell execution
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| extend DecodedCommand = base64_decode_tostring(
    extract(@"-[eE](?:nc|ncodedCommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine))

// Impossible travel (simplified)
let timeWindow = 60m;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location = tostring(LocationDetails.city)
| serialize
| extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| where Location != PrevLocation
| where (TimeGenerated - PrevTime) < timeWindow
```

---

## Threat Hunting Patterns

### Methodology: Hypothesis-Driven Hunting

1. **Form hypothesis** — Based on threat intel, MITRE ATT&CK, or anomaly
2. **Identify data sources** — Which tables have the evidence?
3. **Write query** — KQL to find indicators
4. **Analyze results** — Triage findings, pivot on entities
5. **Document** — Record findings, create detection rule if validated

### Key Hunting Queries

```kql
// Rare process execution (baseline deviation)
let baseline = 7d;
let hunting_period = 1d;
let RareProcesses = DeviceProcessEvents
| where TimeGenerated between (ago(baseline) .. ago(hunting_period))
| summarize BaselineCount = count() by FileName
| where BaselineCount < 5;
DeviceProcessEvents
| where TimeGenerated > ago(hunting_period)
| join kind=inner (RareProcesses) on FileName
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName

// DNS beaconing detection (periodic callbacks)
let minBeacons = 50;
DnsEvents
| where TimeGenerated > ago(24h)
| summarize
    QueryCount = count(),
    DistinctHours = dcount(bin(TimeGenerated, 1h)),
    TimeDiffs = make_list(TimeGenerated)
  by Name, ClientIP
| where QueryCount > minBeacons and DistinctHours > 12
// High query count with consistent hourly presence = potential beaconing

// PowerShell download cradle variants
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Net.WebClient", "DownloadString", "DownloadFile",
    "Invoke-WebRequest", "IWR", "wget", "curl",
    "Start-BitsTransfer", "Invoke-RestMethod",
    "Net.Http.HttpClient", "WebRequest"
  )
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

// Living-off-the-land binaries (LOLBins)
let LOLBins = dynamic([
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "cmstp.exe", "msconfig.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
    "csc.exe", "vbc.exe", "jsc.exe", "wscript.exe", "cscript.exe",
    "bitsadmin.exe", "certoc.exe", "desktopimgdownldr.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
    "hh.exe", "ie4uinit.exe", "makecab.exe", "replace.exe",
    "xwizard.exe"
]);
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ (LOLBins)
| where ProcessCommandLine has_any ("http", "ftp", "\\\\", "-decode", "-encode", "-urlcache")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine

// Lateral movement via RDP
DeviceLogonEvents
| where TimeGenerated > ago(24h)
| where LogonType == "RemoteInteractive"
| summarize
    RDPTargets = dcount(DeviceName),
    TargetList = make_set(DeviceName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by AccountName, RemoteIP
| where RDPTargets > 3  // Single account RDP to 3+ machines

// Large file staging (potential exfiltration prep)
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\tmp\\", "\\Downloads\\", "\\Public\\")
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| project TimeGenerated, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessFileName
```

---

## Workbook Design

> Full dashboard designs with KQL + ARM templates: see `references/workbooks.md`

### Visualization Types

| Type | KQL Render | Best For |
|---|---|---|
| Time chart | `render timechart` | Trends over time |
| Bar chart | `render barchart` | Category comparison |
| Pie / Donut | `render piechart` | Distribution/proportion |
| Area chart | `render areachart` | Cumulative trends |
| Scatter | `render scatterchart` | Correlation |
| Table/Grid | (default) | Detailed records |
| Tiles | Workbook tiles | KPI numbers |
| Map | Workbook map viz | Geographic data |

### Parameter System

```json
{
  "type": 1,
  "content": {
    "json": "## Parameters"
  }
},
{
  "type": 9,
  "content": {
    "version": "KqlParameterItem/1.0",
    "parameters": [
      {
        "name": "TimeRange",
        "type": 4,
        "defaultValue": { "durationMs": 86400000 },
        "typeSettings": { "selectableValues": [
          { "durationMs": 3600000, "displayText": "Last 1 hour" },
          { "durationMs": 86400000, "displayText": "Last 24 hours" },
          { "durationMs": 604800000, "displayText": "Last 7 days" }
        ]}
      },
      {
        "name": "Subscription",
        "type": 6,
        "multiSelect": true,
        "typeSettings": { "additionalResourceOptions": ["value::all"] }
      },
      {
        "name": "Workspace",
        "type": 5,
        "query": "Resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id",
        "crossComponentResources": ["{Subscription}"],
        "typeSettings": { "additionalResourceOptions": ["value::1"] }
      }
    ]
  }
}
```

### Conditional Visibility (Tab Navigation)

```json
{
  "type": 9,
  "content": {
    "parameters": [{
      "name": "selectedTab",
      "type": 2,
      "query": "datatable(value:string, label:string)[\n'overview','Overview',\n'incidents','Incidents',\n'hunting','Hunting'\n]",
      "typeSettings": { "showDefault": true }
    }]
  }
},
{
  "type": 12,
  "content": {
    "version": "NotebookGroup/1.0"
  },
  "conditionalVisibility": {
    "parameterName": "selectedTab",
    "comparison": "isEqualTo",
    "value": "overview"
  },
  "name": "overviewGroup"
}
```

### Key Workbook KQL Patterns

```kql
// KPI Tile — Single value with trend arrow
let current = SigninLogs | where TimeGenerated > ago(24h) | where ResultType != 0 | count;
let previous = SigninLogs | where TimeGenerated between (ago(48h)..ago(24h)) | where ResultType != 0 | count;
print
    Value = toscalar(current),
    Trend = iff(toscalar(current) > toscalar(previous), "↑", "↓"),
    Change = toscalar(current) - toscalar(previous)

// Heatmap grid — Hour of day vs Day of week
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType != 0
| extend Hour = datetime_part("Hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated) / 1d
| summarize Count = count() by DayOfWeek, Hour
| order by DayOfWeek asc, Hour asc

// Sparkline in grid
SecurityIncident
| summarize
    Count = count(),
    Trend = make_list(bin(TimeGenerated, 1d))
  by Severity
| extend Sparkline = Trend  // Workbook renders as sparkline column

// Map visualization
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| extend Latitude = todouble(LocationDetails.geoCoordinates.latitude)
| extend Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| summarize FailureCount = count() by Latitude, Longitude, tostring(LocationDetails.countryOrRegion)
```

---

## ARM Template Deployment

> Full ARM templates for all 9 dashboards: see `references/workbooks.md`

### Workbook ARM Template Structure

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workbookDisplayName": {
      "type": "string",
      "defaultValue": "Security Dashboard"
    },
    "workbookId": {
      "type": "string",
      "defaultValue": "[newGuid()]"
    },
    "workspaceResourceId": {
      "type": "string",
      "metadata": {
        "description": "Full resource ID of the Log Analytics workspace"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Insights/workbooks",
      "apiVersion": "2022-04-01",
      "name": "[parameters('workbookId')]",
      "location": "[resourceGroup().location]",
      "kind": "shared",
      "properties": {
        "displayName": "[parameters('workbookDisplayName')]",
        "serializedData": "<ESCAPED_WORKBOOK_JSON>",
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

### Deploy Commands

```bash
# Validate template
az deployment group validate \
  --resource-group <rg-name> \
  --template-file workbook-template.json \
  --parameters workspaceResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>"

# Deploy
az deployment group create \
  --resource-group <rg-name> \
  --template-file workbook-template.json \
  --parameters workspaceResourceId="<workspace-resource-id>"
```

### GitHub Actions CI/CD

```yaml
name: Deploy Sentinel Workbooks
on:
  push:
    branches: [main]
    paths: ['workbooks/**']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Deploy workbooks
        uses: azure/arm-deploy@v2
        with:
          resourceGroupName: ${{ vars.RESOURCE_GROUP }}
          template: ./workbooks/arm-template.json
          parameters: >
            workspaceResourceId=${{ vars.WORKSPACE_RESOURCE_ID }}
```

---

## Appendix: MITRE ATT&CK Tactic to Sentinel Mapping

| MITRE Tactic | Sentinel Tactic Value | Primary Tables |
|---|---|---|
| Reconnaissance | Reconnaissance | AzureActivity, AzureDiagnostics |
| Resource Development | ResourceDevelopment | ThreatIntelligenceIndicator |
| Initial Access | InitialAccess | SigninLogs, EmailEvents, OfficeActivity |
| Execution | Execution | DeviceProcessEvents, SecurityEvent (4688) |
| Persistence | Persistence | AuditLogs, DeviceRegistryEvents, SecurityEvent (4720, 7045) |
| Privilege Escalation | PrivilegeEscalation | SecurityEvent (4672, 4728), AuditLogs |
| Defense Evasion | DefenseEvasion | SecurityEvent (1102), DeviceProcessEvents |
| Credential Access | CredentialAccess | SigninLogs, SecurityEvent (4625, 4648), IdentityLogonEvents |
| Discovery | Discovery | DeviceProcessEvents, IdentityQueryEvents |
| Lateral Movement | LateralMovement | DeviceLogonEvents, SecurityEvent (4624 Type 3/10) |
| Collection | Collection | DeviceFileEvents, OfficeActivity |
| Command and Control | CommandAndControl | DeviceNetworkEvents, DnsEvents, CommonSecurityLog |
| Exfiltration | Exfiltration | DeviceNetworkEvents, DeviceFileEvents |
| Impact | Impact | SecurityEvent (1100, 1102), DeviceProcessEvents |
