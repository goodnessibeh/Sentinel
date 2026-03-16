**Author:** Goodness Caleb Ibeh

# Impossible Travel — Sign-ins from Geographically Distant Locations

This detection finds instances where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible. This is a strong indicator that account credentials have been compromised and are being used by an attacker from a different location. The query uses the Haversine formula to calculate the distance between consecutive sign-in locations.

**Importance:** A SOC analyst should investigate this alert because it reveals likely credential theft — a legitimate user cannot physically be in two distant places within minutes.

**MITRE:** T1078 — Valid Accounts

**Severity:** Medium

**Entity Mapping:**

| Entity Type | Identifier | Column |
|---|---|---|
| Account | FullName | UserPrincipalName |
| IP | Address | IPAddress |
| IP | Address | PrevIP |

```kql
let timeWindow = 2h;
let minDistance = 500; // km — adjust for your org
SigninLogs
// Look back 24 hours for sign-in pairs
| where TimeGenerated > ago(24h)
// Only consider successful sign-ins
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend Lat = todouble(LocationDetails.geoCoordinates.latitude)
| extend Lon = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(City) and isnotnull(Lat)
// Order by user and time to compare consecutive logins
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend
    PrevUser = prev(UserPrincipalName),
    PrevTime = prev(TimeGenerated),
    PrevLat = prev(Lat), PrevLon = prev(Lon),
    PrevCity = prev(City), PrevCountry = prev(Country),
    PrevIP = prev(IPAddress)
// Only compare consecutive rows for the same user
| where UserPrincipalName == PrevUser
| extend TimeDelta = (TimeGenerated - PrevTime) / 1m
// Filter: the two sign-ins must be within the time window
| where TimeDelta < (timeWindow / 1m)
// Haversine approximation to calculate distance in km
| extend DistanceKm = 6371 * acos(
    sin(radians(Lat)) * sin(radians(PrevLat)) +
    cos(radians(Lat)) * cos(radians(PrevLat)) * cos(radians(PrevLon - Lon))
  )
// Threshold: flag only if distance exceeds minimum
| where DistanceKm > minDistance
| extend
    AlertTitle = "Impossible Travel — Sign-ins from Geographically Distant Locations",
    AlertDescription = "This detection finds instances where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible.",
    AlertSeverity = "Medium"
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country,
          PrevIP, PrevCity, PrevCountry, TimeDelta, DistanceKm, AlertTitle, AlertDescription, AlertSeverity
```

**Tuning:** Exclude VPN IPs. Adjust distance/time thresholds. Whitelist known travel patterns.

---

## Sentinel Analytics Rule — YAML

```yaml
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
name: "Impossible Travel — Sign-ins from Geographically Distant Locations"
description: |
  This detection finds instances where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible. This is a strong indicator that account credentials have been compromised and are being used by an attacker from a different location.
  A SOC analyst should investigate this alert because it reveals likely credential theft — a legitimate user cannot physically be in two distant places within minutes.
severity: Medium
status: Available
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |
  let timeWindow = 2h;
  let minDistance = 500; // km — adjust for your org
  SigninLogs
  // Look back 24 hours for sign-in pairs
  | where TimeGenerated > ago(24h)
  // Only consider successful sign-ins
  | where ResultType == 0
  | extend City = tostring(LocationDetails.city)
  | extend Country = tostring(LocationDetails.countryOrRegion)
  | extend Lat = todouble(LocationDetails.geoCoordinates.latitude)
  | extend Lon = todouble(LocationDetails.geoCoordinates.longitude)
  | where isnotempty(City) and isnotnull(Lat)
  // Order by user and time to compare consecutive logins
  | order by UserPrincipalName, TimeGenerated asc
  | serialize
  | extend
      PrevUser = prev(UserPrincipalName),
      PrevTime = prev(TimeGenerated),
      PrevLat = prev(Lat), PrevLon = prev(Lon),
      PrevCity = prev(City), PrevCountry = prev(Country),
      PrevIP = prev(IPAddress)
  // Only compare consecutive rows for the same user
  | where UserPrincipalName == PrevUser
  | extend TimeDelta = (TimeGenerated - PrevTime) / 1m
  // Filter: the two sign-ins must be within the time window
  | where TimeDelta < (timeWindow / 1m)
  // Haversine approximation to calculate distance in km
  | extend DistanceKm = 6371 * acos(
      sin(radians(Lat)) * sin(radians(PrevLat)) +
      cos(radians(Lat)) * cos(radians(PrevLat)) * cos(radians(PrevLon - Lon))
    )
  // Threshold: flag only if distance exceeds minimum
  | where DistanceKm > minDistance
  | extend
      AlertTitle = "Impossible Travel — Sign-ins from Geographically Distant Locations",
      AlertDescription = "This detection finds instances where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible.",
      AlertSeverity = "Medium"
  | project TimeGenerated, UserPrincipalName, IPAddress, City, Country,
            PrevIP, PrevCity, PrevCountry, TimeDelta, DistanceKm, AlertTitle, AlertDescription, AlertSeverity
alertDetailsOverride:
  alertDisplayNameFormat: "{{AlertTitle}}"
  alertDescriptionFormat: "{{AlertDescription}}"
  alertSeverityColumnName: AlertSeverity
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: PrevIP
customDetails:
  AlertTitle: AlertTitle
  AlertDescription: AlertDescription
  AlertSeverity: AlertSeverity
version: 1.0.0
kind: Scheduled
```
