# Executive Summary Dashboard

Single-page KPI tiles, risk score, and trend arrows designed for leadership and executive stakeholders. Provides a quick security posture overview without operational noise.

- **Security Score Tile** — Calculated security score based on incident severity weighting with color-coded thresholds
- **Week-over-Week Trend** — Incident comparison between current and previous week with directional arrows
- **Top 5 Risk Areas** — Aggregated risk signals from sign-ins, alerts, malware, phishing, and Azure deletions
- **Compliance Quick View** — MFA coverage, sign-in success rate, and device onboarding KPIs
- **Incident Trend** — Daily incident volume over time broken down by severity
- **Alert Severity Breakdown** — Pie chart of alert severity proportions

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
        "json": "# Executive Summary Dashboard\n---\nSingle-page KPI tiles, risk score, and trend arrows for leadership.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Security Score\nWeighted score: 100 minus (High x15, Medium x5, Low x1). Green >= 80, Yellow >= 60, Orange >= 40, Red < 40."
      },
      "name": "security-score-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status == 'New' or Status == 'Active'\n| summarize\n    HighIncidents = countif(Severity == 'High'),\n    MediumIncidents = countif(Severity == 'Medium'),\n    LowIncidents = countif(Severity == 'Low')\n| extend RawScore = 100 - (HighIncidents * 15) - (MediumIncidents * 5) - (LowIncidents * 1)\n| extend SecurityScore = max_of(RawScore, 0)\n| project SecurityScore, HighIncidents, MediumIncidents, LowIncidents",
        "size": 4,
        "title": "Security Score",
        "noDataMessage": "No incident data available to calculate security score.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "tiles",
        "tileSettings": {
          "titleContent": {
            "columnMatch": "SecurityScore",
            "formatter": 1,
            "formatOptions": {
              "showIcon": true
            }
          },
          "leftContent": {
            "columnMatch": "SecurityScore",
            "formatter": 12,
            "formatOptions": { "palette": "auto" },
            "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 3 } }
          },
          "secondaryContent": {
            "columnMatch": "HighIncidents",
            "formatter": 1,
            "formatOptions": {
              "showIcon": true
            }
          },
          "showBorder": true,
          "colorSettings": {
            "colorConditions": [
              { "operator": ">=", "value": "80", "color": "#107C10" },
              { "operator": ">=", "value": "60", "color": "#FFC000" },
              { "operator": ">=", "value": "40", "color": "#F7630C" },
              { "operator": "Default", "color": "#D13438" }
            ],
            "rowColoring": "SecurityScore"
          }
        }
      },
      "name": "security-score-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Week-over-Week Trend\nCompare this week vs last week incident counts by severity with directional trend arrows."
      },
      "name": "wow-trend-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let ThisWeekStart = startofweek(now());\nlet LastWeekStart = startofweek(now()) - 7d;\nlet thisWeek = SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where CreatedTime >= ThisWeekStart\n| summarize ThisWeek = count() by Severity;\nlet lastWeek = SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where CreatedTime >= LastWeekStart and CreatedTime < ThisWeekStart\n| summarize LastWeek = count() by Severity;\nthisWeek\n| join kind=fullouter lastWeek on Severity\n| extend Severity = coalesce(Severity, Severity1)\n| extend ThisWeek = coalesce(ThisWeek, 0), LastWeek = coalesce(LastWeek, 0)\n| extend Change = ThisWeek - LastWeek\n| extend TrendArrow = case(Change > 0, '\\u2191', Change < 0, '\\u2193', '\\u2192')\n| extend ChangePercent = iff(LastWeek == 0, iff(ThisWeek == 0, 0.0, 100.0), round(todouble(Change) / todouble(LastWeek) * 100, 1))\n| project Severity, ThisWeek, LastWeek, Change, TrendArrow, ChangePercent\n| order by case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, Severity == 'Informational', 4, 5) asc",
        "size": 0,
        "title": "Week-over-Week Trend",
        "noDataMessage": "No incident data available for week-over-week comparison.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "TrendArrow",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "icons",
                "thresholdsGrid": [
                  { "operator": "==", "thresholdValue": "\u2191", "representation": "up", "text": "\u2191", "representationColor": "#D13438" },
                  { "operator": "==", "thresholdValue": "\u2193", "representation": "down", "text": "\u2193", "representationColor": "#107C10" },
                  { "operator": "==", "thresholdValue": "\u2192", "representation": "right", "text": "\u2192", "representationColor": "#5C5C5C" },
                  { "operator": "Default", "representation": "right", "text": "{0}", "representationColor": "#5C5C5C" }
                ]
              }
            },
            {
              "columnMatch": "Severity",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                  { "operator": "==", "thresholdValue": "High", "representation": "redBright", "text": "High" },
                  { "operator": "==", "thresholdValue": "Medium", "representation": "orange", "text": "Medium" },
                  { "operator": "==", "thresholdValue": "Low", "representation": "blue", "text": "Low" },
                  { "operator": "==", "thresholdValue": "Informational", "representation": "gray", "text": "Informational" },
                  { "operator": "Default", "representation": "blue", "text": "{0}" }
                ]
              }
            },
            {
              "columnMatch": "ChangePercent",
              "formatter": 0,
              "numberFormat": { "unit": 1, "options": { "style": "decimal", "maximumFractionDigits": 1 } }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "Severity", "sortOrder": 1 }]
        }
      },
      "name": "wow-trend-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top 5 Risk Areas\nAggregated risk signals from sign-ins, alerts, malware, phishing, and Azure resource deletions."
      },
      "name": "risk-areas-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let riskySignins = SigninLogs\n| where TimeGenerated {TimeRange}\n| where RiskLevelDuringSignIn in ('high', 'medium')\n| summarize Count = count()\n| extend Area = 'Risky Sign-ins';\nlet highAlerts = SecurityAlert\n| where TimeGenerated {TimeRange}\n| where AlertSeverity == 'High'\n| summarize Count = count()\n| extend Area = 'High Severity Alerts';\nlet malwareEvents = DeviceEvents\n| where TimeGenerated {TimeRange}\n| where ActionType == 'AntivirusDetection'\n| summarize Count = count()\n| extend Area = 'Malware Detections';\nlet phishingEmails = EmailEvents\n| where TimeGenerated {TimeRange}\n| where ThreatTypes has 'Phish'\n| summarize Count = count()\n| extend Area = 'Phishing Emails';\nlet azureDeletions = AzureActivity\n| where TimeGenerated {TimeRange}\n| where OperationNameValue has 'delete'\n| summarize Count = count()\n| extend Area = 'Azure Deletions';\nunion riskySignins, highAlerts, malwareEvents, phishingEmails, azureDeletions\n| project Area, Count\n| top 5 by Count desc",
        "size": 0,
        "title": "Top 5 Risk Areas",
        "noDataMessage": "No risk data found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "Count",
              "formatter": 8,
              "formatOptions": { "min": 0, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "Count", "sortOrder": 2 }]
        }
      },
      "name": "top-risk-areas"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Compliance Quick View\nMFA coverage, sign-in success rate, and device onboarding KPIs."
      },
      "name": "compliance-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let mfaCoverage = SigninLogs\n| where TimeGenerated {TimeRange}\n| summarize\n    TotalSignins = count(),\n    MfaSignins = countif(AuthenticationRequirement == 'multiFactorAuthentication')\n| extend Value = round(todouble(MfaSignins) / todouble(TotalSignins) * 100, 1)\n| extend Metric = 'MFA Coverage %'\n| project Metric, Value;\nlet signinSuccess = SigninLogs\n| where TimeGenerated {TimeRange}\n| summarize\n    TotalSignins = count(),\n    SuccessSignins = countif(ResultType == 0)\n| extend Value = round(todouble(SuccessSignins) / todouble(TotalSignins) * 100, 1)\n| extend Metric = 'Sign-in Success Rate %'\n| project Metric, Value;\nlet deviceOnboarding = DeviceInfo\n| where TimeGenerated {TimeRange}\n| summarize\n    TotalDevices = dcount(DeviceId),\n    OnboardedDevices = dcountif(DeviceId, OnboardingStatus == 'Onboarded')\n| extend Value = round(todouble(OnboardedDevices) / todouble(TotalDevices) * 100, 1)\n| extend Metric = 'Device Onboarding Rate %'\n| project Metric, Value;\nunion mfaCoverage, signinSuccess, deviceOnboarding\n| project Metric, Value",
        "size": 4,
        "title": "Compliance Quick View",
        "noDataMessage": "No compliance data available.",
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
            "numberFormat": { "unit": 1, "options": { "maximumSignificantDigits": 4 } }
          },
          "showBorder": true,
          "colorSettings": {
            "colorConditions": [
              { "operator": ">=", "value": "90", "color": "#107C10" },
              { "operator": ">=", "value": "70", "color": "#FFC000" },
              { "operator": ">=", "value": "50", "color": "#F7630C" },
              { "operator": "Default", "color": "#D13438" }
            ],
            "rowColoring": "Value"
          }
        }
      },
      "name": "compliance-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Incident Trend\nDaily incident volume over time broken down by severity."
      },
      "name": "incident-trend-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| make-series IncidentCount = count() default = 0 on CreatedTime from {TimeRange:start} to {TimeRange:end} step 1d by Severity",
        "size": 1,
        "title": "Incident Trend",
        "noDataMessage": "No incidents found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "incident-trend-area"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Alert Severity Breakdown\nProportion of alerts by severity level."
      },
      "name": "alert-breakdown-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| summarize AlertCount = count() by AlertSeverity\n| order by AlertCount desc",
        "size": 3,
        "title": "Alert Severity Breakdown",
        "noDataMessage": "No alerts found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "alert-severity-piechart"
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

Microsoft Sentinel Reader (or higher) on the workspace. Additional tables require: SigninLogs (Azure AD P1/P2), DeviceEvents/DeviceInfo (Microsoft Defender for Endpoint), EmailEvents (Microsoft Defender for Office 365), AzureActivity (Activity Log diagnostic settings).
