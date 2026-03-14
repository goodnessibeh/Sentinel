# User Behavior Analytics Dashboard

Anomaly scores, peer comparison, and risk timeline powered by Microsoft Sentinel UEBA. Surfaces high-priority users, first-time activities, and investigation priority trends.

- **KPI Tiles** — Total anomalies, high priority users, average investigation priority, max priority seen
- **Top Risky Users** — Top 20 users ranked by max investigation priority with heatmap
- **Anomaly Timeline** — Daily anomaly count trend over time
- **Activity Types** — Top 15 activity types generating anomalies
- **First-Time Activities** — Users performing first-time connections, country logins, or new user activity
- **Investigation Priority Distribution** — Pie chart of priority buckets (Critical, High, Medium, Low)
- **User Risk Over Time** — Area chart of daily max investigation priority

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
        "json": "# User Behavior Analytics Dashboard\n---\nAnomaly scores, peer comparison, and risk timeline.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Key Metrics\nOverall anomaly and investigation priority summary from UEBA."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let totalAnomalies = BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| summarize Value = count()\n| extend Metric = 'Total Anomalies';\nlet highPriorityUsers = BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority >= 5\n| summarize Value = dcount(UserPrincipalName)\n| extend Metric = 'High Priority Users';\nlet avgPriority = BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| summarize Value = round(avg(InvestigationPriority), 1)\n| extend Metric = 'Avg Investigation Priority';\nlet maxPriority = BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| summarize Value = max(InvestigationPriority)\n| extend Metric = 'Max Priority Seen';\nunion totalAnomalies, highPriorityUsers, avgPriority, maxPriority\n| project Metric, Value",
        "size": 4,
        "title": "Key Metrics",
        "noDataMessage": "No UEBA anomalies found in the selected time range.",
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
          "showBorder": true,
          "colorSettings": {
            "colorConditions": [
              { "operator": "contains", "value": "Total Anomalies", "color": "#0078D4" },
              { "operator": "contains", "value": "High Priority", "color": "#D13438" },
              { "operator": "contains", "value": "Avg", "color": "#F7630C" },
              { "operator": "contains", "value": "Max", "color": "#8B0000" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Risky Users\nTop 20 users by maximum investigation priority with anomaly count and average priority."
      },
      "name": "risky-users-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| summarize AvgPriority = round(avg(InvestigationPriority), 1), MaxPriority = max(InvestigationPriority), AnomalyCount = count() by UserPrincipalName\n| top 20 by MaxPriority desc\n| project UserPrincipalName, MaxPriority, AvgPriority, AnomalyCount\n| order by MaxPriority desc",
        "size": 0,
        "title": "Top 20 Risky Users",
        "noDataMessage": "No anomalous user behavior found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "MaxPriority",
              "formatter": 8,
              "formatOptions": { "min": 1, "max": 10, "palette": "yellowOrangeRed" }
            },
            {
              "columnMatch": "AnomalyCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 50, "palette": "blue" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "MaxPriority", "sortOrder": 2 }]
        }
      },
      "name": "top-risky-users"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Anomaly Timeline\nDaily count of anomalous behavior events over time."
      },
      "name": "anomaly-timeline-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| make-series AnomalyCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
        "size": 1,
        "title": "Anomaly Timeline",
        "noDataMessage": "No anomalies found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "anomaly-timeline"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Activity Types\nTop 15 activity types generating anomalous behavior."
      },
      "name": "activity-types-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| summarize AnomalyCount = count() by ActivityType\n| top 15 by AnomalyCount desc\n| order by AnomalyCount desc",
        "size": 1,
        "title": "Top 15 Activity Types",
        "noDataMessage": "No activity type data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "activity-types-bar"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## First-Time Activities\nUsers performing first-time connections, country logins, or appearing as new users."
      },
      "name": "first-time-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| extend UserInsights = parse_json(UsersInsights)\n| extend IsFirstTimeUser = tostring(UserInsights.IsFirstTimeUser) == 'true',\n         IsFirstTimeConnection = tostring(UserInsights.IsFirstTimeConnection) == 'true',\n         IsFirstTimeCountry = tostring(UserInsights.IsFirstTimeCountry) == 'true'\n| where IsFirstTimeUser or IsFirstTimeConnection or IsFirstTimeCountry\n| project TimeGenerated, UserPrincipalName, ActivityType, IsFirstTimeUser, IsFirstTimeConnection, IsFirstTimeCountry, SourceIPAddress, InvestigationPriority\n| order by InvestigationPriority desc, TimeGenerated desc",
        "size": 0,
        "title": "First-Time Activities",
        "noDataMessage": "No first-time activities found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "InvestigationPriority",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 10, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "InvestigationPriority", "sortOrder": 2 }]
        }
      },
      "name": "first-time-activities"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Investigation Priority Distribution\nBreakdown of anomalies by priority bucket."
      },
      "name": "priority-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| extend PriorityBucket = case(\n    InvestigationPriority >= 8, 'Critical (8-10)',\n    InvestigationPriority >= 5, 'High (5-7)',\n    InvestigationPriority >= 3, 'Medium (3-4)',\n    'Low (1-2)')\n| summarize AnomalyCount = count() by PriorityBucket\n| order by AnomalyCount desc",
        "size": 3,
        "title": "Investigation Priority Distribution",
        "noDataMessage": "No anomalies found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "priority-distribution-pie"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## User Risk Over Time\nDaily maximum investigation priority trend across all users."
      },
      "name": "risk-over-time-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "BehaviorAnalytics\n| where TimeGenerated {TimeRange}\n| where InvestigationPriority > 0\n| make-series MaxRisk = max(InvestigationPriority) default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
        "size": 1,
        "title": "User Risk Over Time",
        "noDataMessage": "No risk data found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "user-risk-area"
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

Microsoft Sentinel Reader (or higher) on the workspace. UEBA must be enabled under **Sentinel > Entity behavior** for the BehaviorAnalytics table to populate.
