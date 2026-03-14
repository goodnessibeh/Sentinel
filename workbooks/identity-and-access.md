# Identity & Access Dashboard

Sign-in anomalies, MFA coverage, risky users, and conditional access analysis for Microsoft Sentinel. Surfaces authentication failures, geographic anomalies, and policy enforcement gaps.

- **KPI Tiles** — Total sign-ins, failed sign-ins, MFA coverage percentage, and risky sign-in count
- **Sign-in Failure Trend** — Daily time series of failed vs. successful authentications
- **Failed Sign-ins by Reason** — Top 10 failure reasons ranked by occurrence
- **Risky Users** — Users with medium/high risk sign-ins, associated IPs, apps, and risk levels
- **Sign-in Locations Map** — Geographic map of failed sign-in origins with heatmap sizing
- **Conditional Access Outcomes** — Policy evaluation results for successful sign-ins
- **Top Failed Users** — Users with the most authentication failures, with IP and app context

**Author:** Goodness Caleb Ibeh — [LinkedIn](https://linkedin.com/in/caleb-ibeh)

---

## Workbook JSON — Paste into Code Editor (`</>`)

```json
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": {
        "json": "# Identity & Access Dashboard\n---\nSign-in anomalies, MFA coverage, risky users, and conditional access.\nSelect your Sentinel workspace above to load data."
      },
      "name": "title"
    },
    {
      "type": 9,
      "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
          {
            "id": "param-sub",
            "version": "KqlParameterItem/1.0",
            "name": "Subscription",
            "label": "Subscription",
            "type": 6,
            "isRequired": true,
            "typeSettings": {
              "additionalResourceOptions": [],
              "includeAll": false
            }
          },
          {
            "id": "param-workspace",
            "version": "KqlParameterItem/1.0",
            "name": "Workspace",
            "label": "Workspace",
            "type": 5,
            "isRequired": true,
            "query": "resources\n| where type == 'microsoft.operationalinsights/workspaces'\n| project id",
            "crossComponentResources": ["{Subscription}"],
            "typeSettings": {
              "resourceTypeFilter": {
                "microsoft.operationalinsights/workspaces": true
              },
              "additionalResourceOptions": []
            },
            "queryType": 1,
            "resourceType": "microsoft.resourcegraph/resources"
          },
          {
            "id": "param-timerange",
            "version": "KqlParameterItem/1.0",
            "name": "TimeRange",
            "label": "Time Range",
            "type": 4,
            "isRequired": true,
            "typeSettings": {
              "selectableValues": [
                { "durationMs": 86400000 },
                { "durationMs": 259200000 },
                { "durationMs": 604800000 },
                { "durationMs": 1209600000 },
                { "durationMs": 2592000000 },
                { "durationMs": 5184000000 },
                { "durationMs": 7776000000 }
              ],
              "allowCustom": true
            },
            "value": { "durationMs": 2592000000 }
          }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Identity KPIs\nKey sign-in metrics at a glance — total volume, failures, MFA adoption, and risk."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| summarize\n    TotalSignIns = count(),\n    FailedSignIns = countif(ResultType != 0),\n    MFACoverage = round(100.0 * countif(ResultType == 0 and AuthenticationRequirement == 'multiFactorAuthentication') / max(countif(ResultType == 0), 1), 1),\n    RiskySignIns = countif(RiskLevelDuringSignIn in ('high', 'medium'))\n| project\n    pack_array(\n        pack('Metric', 'Total Sign-ins', 'Value', TotalSignIns),\n        pack('Metric', 'Failed Sign-ins', 'Value', FailedSignIns),\n        pack('Metric', 'MFA Coverage %', 'Value', MFACoverage),\n        pack('Metric', 'Risky Sign-ins', 'Value', RiskySignIns)\n    )\n| mv-expand Column1\n| evaluate bag_unpack(Column1)",
        "size": 4,
        "title": "Identity KPIs",
        "noDataMessage": "No sign-in data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "tiles",
        "tileSettings": {
          "titleContent": { "columnMatch": "Metric", "formatter": 1 },
          "leftContent": {
            "columnMatch": "Value",
            "formatter": 12,
            "formatOptions": { "palette": "auto" },
            "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 4 } }
          },
          "showBorder": true
        }
      },
      "name": "identity-kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Sign-in Failure Trend\nDaily breakdown of failed vs. successful sign-ins over time."
      },
      "name": "failure-trend-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| make-series FailedLogins = countif(ResultType != 0) default = 0, SuccessLogins = countif(ResultType == 0) default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
        "size": 1,
        "title": "Sign-in Failure Trend",
        "noDataMessage": "No sign-in data found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "signin-failure-trend"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Failed Sign-ins by Reason\nTop 10 failure reasons for unsuccessful authentication attempts."
      },
      "name": "failure-reason-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| where ResultType != 0\n| summarize FailureCount = count() by ResultDescription\n| top 10 by FailureCount desc",
        "size": 1,
        "title": "Failed Sign-ins by Reason",
        "noDataMessage": "No failed sign-ins found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "failed-signins-by-reason"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Risky Users\nUsers with medium or high risk sign-ins, including associated IPs, applications, and last seen timestamp."
      },
      "name": "risky-users-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| where RiskLevelDuringSignIn in ('medium', 'high')\n| summarize\n    RiskySignins = count(),\n    RiskLevels = make_set(RiskLevelDuringSignIn),\n    IPAddresses = make_set(IPAddress, 5),\n    Apps = make_set(AppDisplayName, 5),\n    LastSeen = max(TimeGenerated)\n  by UserPrincipalName\n| order by RiskySignins desc",
        "size": 0,
        "title": "Risky Users",
        "noDataMessage": "No risky sign-ins found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "RiskySignins",
              "formatter": 8,
              "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "RiskySignins", "sortOrder": 2 }]
        }
      },
      "name": "risky-users-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Sign-in Locations Map\nGeographic distribution of failed sign-in attempts with heatmap sizing by failure count."
      },
      "name": "locations-map-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| where ResultType != 0\n| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude),\n         Longitude = toreal(LocationDetails.geoCoordinates.longitude),\n         Country = tostring(LocationDetails.countryOrRegion)\n| where isnotempty(Latitude) and isnotempty(Longitude)\n| summarize FailureCount = count() by Country, Latitude, Longitude",
        "size": 1,
        "title": "Failed Sign-in Locations",
        "noDataMessage": "No geolocation data available for failed sign-ins.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "map",
        "mapSettings": {
          "locInfo": "LatLong",
          "latitude": "Latitude",
          "longitude": "Longitude",
          "sizeSettings": "FailureCount",
          "sizeAggregation": "Sum",
          "labelSettings": "Country",
          "legendMetric": "FailureCount",
          "legendAggregation": "Sum",
          "itemColorSettings": {
            "type": "heatmap",
            "colorAggregation": "Sum",
            "nodeColorField": "FailureCount",
            "heatmapPalette": "greenRed"
          }
        }
      },
      "name": "signin-locations-map"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Conditional Access Outcomes\nPolicy evaluation results for successful sign-ins, excluding policies that were not applied."
      },
      "name": "conditional-access-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| where ResultType == 0\n| mv-expand CAPolicy = ConditionalAccessPolicies\n| extend PolicyName = tostring(CAPolicy.displayName),\n         PolicyResult = tostring(CAPolicy.result)\n| where PolicyResult != 'notApplied'\n| summarize PolicyCount = count() by PolicyName, PolicyResult",
        "size": 1,
        "title": "Conditional Access Outcomes",
        "noDataMessage": "No conditional access policy data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "conditional-access-bar"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Failed Users\nTop 20 users by failed sign-in count with associated IP addresses and applications."
      },
      "name": "top-failed-users-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SigninLogs\n| where TimeGenerated {TimeRange}\n| where ResultType != 0\n| summarize\n    FailCount = count(),\n    IPs = make_set(IPAddress, 5),\n    Apps = make_set(AppDisplayName, 5)\n  by UserPrincipalName\n| top 20 by FailCount desc",
        "size": 0,
        "title": "Top Failed Users",
        "noDataMessage": "No failed sign-ins found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "FailCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "FailCount", "sortOrder": 2 }]
        }
      },
      "name": "top-failed-users-table"
    }
  ],
  "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
```

---

## How to Deploy

1. **Sentinel > Workbooks > + Add workbook**
2. Click the **`</>`** (code editor) icon
3. Delete all existing JSON, paste the block above
4. Click **Apply** then **Save**
5. Select your **Subscription** and **Workspace** from the dropdowns at the top

---

## Permissions Required

Microsoft Sentinel Reader (or higher) on the workspace.
