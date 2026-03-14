# SOC Command Center

Real-time security operations overview for Microsoft Sentinel. Provides at-a-glance KPIs, incident trends, alert analysis, and analyst workload distribution.

- **Open Incidents by Severity** — KPI tiles showing New/Active incident counts per severity level
- **MTTD & MTTR** — Mean Time to Detect and Mean Time to Respond metrics
- **Incident Timeline** — Daily incident creation trend broken down by severity
- **Severity Distribution** — Pie chart of incident severity proportions
- **Top Alert Rules** — Highest-firing analytics rules with severity and heatmap
- **Incident Owner Workload** — Analyst assignment distribution for open incidents
- **Alert Activity Over Time** — Area chart of daily alert volume by severity

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
        "json": "# SOC Command Center\n---\nReal-time security operations overview.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Open Incidents by Severity\nCurrent open (New + Active) incidents broken down by severity level."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status == 'New' or Status == 'Active'\n| summarize IncidentCount = count() by Severity\n| order by case(Severity == 'High', 1, Severity == 'Medium', 2, Severity == 'Low', 3, Severity == 'Informational', 4, 5) asc",
        "size": 4,
        "title": "Open Incidents by Severity",
        "noDataMessage": "No open incidents found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "tiles",
        "tileSettings": {
          "titleContent": { "columnMatch": "Severity", "formatter": 1 },
          "leftContent": {
            "columnMatch": "IncidentCount",
            "formatter": 12,
            "formatOptions": { "palette": "auto" },
            "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 3 } }
          },
          "showBorder": true,
          "colorSettings": {
            "colorConditions": [
              { "operator": "==", "value": "High", "color": "#D13438" },
              { "operator": "==", "value": "Medium", "color": "#F7630C" },
              { "operator": "==", "value": "Low", "color": "#0078D4" },
              { "operator": "==", "value": "Informational", "color": "#5C5C5C" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Severity"
          }
        }
      },
      "name": "open-incidents-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## MTTD & MTTR\nMean Time to Detect (first activity to incident creation) and Mean Time to Respond (creation to closure)."
      },
      "name": "mttd-mttr-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let mttd = SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status != 'Closed'\n| where isnotempty(FirstActivityTime) and isnotempty(CreatedTime)\n| extend DetectMinutes = datetime_diff('minute', CreatedTime, FirstActivityTime)\n| where DetectMinutes >= 0\n| summarize AvgMinutes = avg(DetectMinutes)\n| extend Metric = 'MTTD (minutes)', Value = round(AvgMinutes, 1);\nlet mttr = SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status == 'Closed'\n| where isnotempty(CreatedTime) and isnotempty(ClosedTime)\n| extend ResponseMinutes = datetime_diff('minute', ClosedTime, CreatedTime)\n| where ResponseMinutes >= 0\n| summarize AvgMinutes = avg(ResponseMinutes)\n| extend Metric = 'MTTR (minutes)', Value = round(AvgMinutes, 1);\nunion mttd, mttr\n| project Metric, Value",
        "size": 4,
        "title": "MTTD & MTTR",
        "noDataMessage": "No incident data available to calculate MTTD/MTTR.",
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
              { "operator": "contains", "value": "MTTD", "color": "#0078D4" },
              { "operator": "contains", "value": "MTTR", "color": "#107C10" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "mttd-mttr-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Incident Timeline\nDaily incident creation trend by severity."
      },
      "name": "timeline-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| make-series IncidentCount = count() default = 0 on CreatedTime from {TimeRange:start} to {TimeRange:end} step 1d by Severity",
        "size": 1,
        "title": "Incident Timeline",
        "noDataMessage": "No incidents found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "incident-timeline"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Incident Severity Distribution\nProportion of incidents by severity level."
      },
      "name": "severity-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| summarize IncidentCount = count() by Severity\n| order by IncidentCount desc",
        "size": 3,
        "title": "Incident Severity Distribution",
        "noDataMessage": "No incidents found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "severity-piechart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top 10 Alert Rules Firing\nMost active analytics rules by alert count."
      },
      "name": "top-alerts-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| summarize AlertCount = count(), AlertSeverity = take_any(AlertSeverity) by AlertName\n| top 10 by AlertCount desc\n| project AlertName, AlertSeverity, AlertCount\n| order by AlertCount desc",
        "size": 0,
        "title": "Top 10 Alert Rules Firing",
        "noDataMessage": "No alerts found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "AlertSeverity",
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
              "columnMatch": "AlertCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "AlertCount", "sortOrder": 2 }]
        }
      },
      "name": "top-alert-rules"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Incident Owner Workload\nOpen incident distribution by assigned analyst, with High/Medium severity breakdown."
      },
      "name": "workload-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| where TimeGenerated {TimeRange}\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status == 'New' or Status == 'Active'\n| extend AssignedTo = coalesce(Owner.assignedTo, 'Unassigned')\n| where Severity in ('High', 'Medium')\n| summarize IncidentCount = count() by tostring(AssignedTo), Severity\n| order by IncidentCount desc",
        "size": 1,
        "title": "Incident Owner Workload (High & Medium)",
        "noDataMessage": "No open High/Medium incidents with assigned owners found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "owner-workload-bar"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Alert Activity Over Time\nDaily alert volume by severity level."
      },
      "name": "alert-activity-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| make-series AlertCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d by AlertSeverity",
        "size": 1,
        "title": "Alert Activity Over Time",
        "noDataMessage": "No alerts found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "alert-activity-area"
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
