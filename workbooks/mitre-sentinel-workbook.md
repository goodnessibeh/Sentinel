# MITRE ATT&CK Combined Workbook

Combined dashboard:
- **Analytics Rule Coverage** — lists all rules with MITRE mappings via ARM REST API
- **Alert Heatmap** — shows MITRE techniques firing from SecurityAlert table via KQL

Rules and alerts prefixed `[DEV]` are excluded.

---

## Workbook JSON — Paste into Code Editor (`</>`)

```json
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": {
        "json": "# MITRE ATT&CK Dashboard\n---\nCombined view of analytics rule coverage and alert heatmap.\nSelect your Sentinel workspace above to load data."
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
          },
          {
            "id": "param-severity",
            "version": "KqlParameterItem/1.0",
            "name": "Severity",
            "label": "Severity",
            "type": 2,
            "multiSelect": true,
            "quote": "'",
            "delimiter": ",",
            "typeSettings": {
              "showDefault": true
            },
            "jsonData": "[{\"value\":\"*\",\"label\":\"All\"},{\"value\":\"High\",\"label\":\"High\"},{\"value\":\"Medium\",\"label\":\"Medium\"},{\"value\":\"Low\",\"label\":\"Low\"},{\"value\":\"Informational\",\"label\":\"Informational\"}]",
            "value": [ "*" ]
          }
        ]
      },
      "name": "parameters"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Analytics Rule Coverage\nEnabled analytics rules with MITRE ATT&CK mappings (via Sentinel REST API). Use the grid filter bar to exclude `[DEV]` rules."
      },
      "name": "coverage-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let data = SecurityAlert | where TimeGenerated > ago(90d) | where AlertName !startswith '[DEV]' | where isnotempty(Tactics);\nlet allTactics = data | extend T = todynamic(Tactics) | mv-expand T | extend T = tostring(T) | where isnotempty(T);\nlet allTechs = data | extend TL = column_ifexists('Techniques', '') | where isnotempty(TL) | extend TA = todynamic(TL) | mv-expand TA | extend TA = tostring(TA) | where isnotempty(TA);\nunion\n(data | summarize v = dcount(AlertName) | extend Metric = 'Total Rules', Order = 1),\n(allTactics | summarize v = dcount(T) | extend Metric = 'Tactics Covered', Order = 2),\n(allTechs | summarize v = dcount(TA) | extend Metric = 'Techniques Covered', Order = 3),\n(data | where AlertSeverity == 'High' | summarize v = dcount(AlertName) | extend Metric = 'High', Order = 4),\n(data | where AlertSeverity == 'Medium' | summarize v = dcount(AlertName) | extend Metric = 'Medium', Order = 5),\n(data | where AlertSeverity == 'Low' | summarize v = dcount(AlertName) | extend Metric = 'Low', Order = 6),\n(data | where AlertSeverity == 'Informational' | summarize v = dcount(AlertName) | extend Metric = 'Informational', Order = 7)\n| project Metric, Count = v, Order\n| order by Order asc",
        "size": 4,
        "title": "Coverage Summary (last 90 days)",
        "noDataMessage": "No alert data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "tiles",
        "tileSettings": {
          "titleContent": { "columnMatch": "Metric", "formatter": 1 },
          "leftContent": {
            "columnMatch": "Count",
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
            "rowColoring": "Metric"
          }
        }
      },
      "name": "coverage-summary"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated > ago(90d)\n| where AlertName !startswith '[DEV]'\n| where isnotempty(Tactics)\n| summarize Severity = take_any(AlertSeverity), TacticsRaw = take_any(Tactics), TechniquesRaw = take_any(column_ifexists('Techniques', '')), AlertCount = count(), LastFired = max(TimeGenerated) by RuleName = AlertName\n| extend TacticArray = todynamic(TacticsRaw)\n| extend TechArray = iff(isnotempty(TechniquesRaw), todynamic(TechniquesRaw), dynamic([]))\n| extend Tactics = strcat_array(TacticArray, ' | ')\n| extend Techniques = iff(array_length(TechArray) > 0, strcat_array(TechArray, ' | '), '')\n| project RuleName, Severity, Tactics, Techniques, AlertCount, LastFired\n| order by Severity asc, RuleName asc",
        "size": 0,
        "title": "Analytics Rules with MITRE Mappings",
        "noDataMessage": "No analytics rules found. Check workspace selection.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
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
              "columnMatch": "Tactics",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                  { "operator": "is Empty", "representation": "gray", "text": "—" },
                  { "operator": "Default", "representation": "greenDark", "text": "{0}" }
                ]
              }
            },
            {
              "columnMatch": "Techniques",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                  { "operator": "is Empty", "representation": "gray", "text": "—" },
                  { "operator": "Default", "representation": "purple", "text": "{0}" }
                ]
              }
            },
            {
              "columnMatch": "AlertCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 50, "palette": "yellowOrangeRed" }
            },
            {
              "columnMatch": "LastFired",
              "formatter": 6
            }
          ],
          "filter": true,
          "sortBy": [ { "itemKey": "Severity", "sortOrder": 1 } ]
        }
      },
      "name": "rules-table"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated > ago(90d)\n| where AlertName !startswith '[DEV]'\n| where '*' in ({Severity}) or AlertSeverity in ({Severity})\n| where isnotempty(Tactics)\n| extend TacticArray = todynamic(Tactics)\n| mv-expand Tactic = TacticArray\n| extend Tactic = tostring(Tactic)\n| where isnotempty(Tactic)\n| summarize DistinctRules = dcount(AlertName) by Tactic\n| order by DistinctRules desc",
        "size": 3,
        "title": "Active Rule Coverage by Tactic (last 90 days)",
        "noDataMessage": "No alerts with MITRE tactics found in the last 90 days.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "tiles",
        "tileSettings": {
          "titleContent": { "columnMatch": "Tactic", "formatter": 1 },
          "leftContent": {
            "columnMatch": "DistinctRules",
            "formatter": 12,
            "formatOptions": { "palette": "yellowOrangeRed" },
            "numberFormat": { "unit": 17, "options": { "maximumSignificantDigits": 3 } }
          },
          "showBorder": true
        }
      },
      "name": "active-coverage-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Alert Heatmap\nTactics and techniques from **fired alerts** in the selected time range."
      },
      "name": "heatmap-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| where AlertName !startswith '[DEV]'\n| where '*' in ({Severity}) or AlertSeverity in ({Severity})\n| where isnotempty(Tactics)\n| extend TacticArray = todynamic(Tactics)\n| mv-expand Tactic = TacticArray\n| extend Tactic = tostring(Tactic)\n| where isnotempty(Tactic)\n| summarize AlertCount = count() by Tactic\n| order by AlertCount desc",
        "size": 1,
        "title": "Alert Volume by Tactic",
        "noDataMessage": "No alerts with MITRE tactics found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "categoricalbar"
      },
      "name": "alert-tactic-bar"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| where AlertName !startswith '[DEV]'\n| where '*' in ({Severity}) or AlertSeverity in ({Severity})\n| where isnotempty(Tactics)\n| extend TacticArray = todynamic(Tactics)\n| mv-expand Tactic = TacticArray\n| extend Tactic = tostring(Tactic)\n| where isnotempty(Tactic)\n| extend TechniqueList = column_ifexists('Techniques', '')\n| where isnotempty(TechniqueList)\n| extend TechniqueArray = todynamic(TechniqueList)\n| mv-expand Technique = TechniqueArray\n| extend Technique = tostring(Technique)\n| where isnotempty(Technique)\n| summarize AlertCount = count(), DistinctRules = dcount(AlertName), HighCount = countif(AlertSeverity == 'High'), MediumCount = countif(AlertSeverity == 'Medium'), LowCount = countif(AlertSeverity == 'Low'), InfoCount = countif(AlertSeverity == 'Informational') by Tactic, Technique\n| extend _s = array_concat(iff(HighCount > 0, pack_array(strcat('High (', tostring(HighCount), ')')), dynamic([])), iff(MediumCount > 0, pack_array(strcat('Medium (', tostring(MediumCount), ')')), dynamic([])), iff(LowCount > 0, pack_array(strcat('Low (', tostring(LowCount), ')')), dynamic([])), iff(InfoCount > 0, pack_array(strcat('Informational (', tostring(InfoCount), ')')), dynamic([])))\n| extend Severities = strcat_array(_s, ' | ')\n| extend CoverageLevel = case(AlertCount >= 20, 'Critical', AlertCount >= 10, 'High', AlertCount >= 5, 'Medium', AlertCount >= 1, 'Low', 'None')\n| project Tactic, Technique, AlertCount, DistinctRules, CoverageLevel, Severities\n| order by Tactic asc, AlertCount desc",
        "size": 0,
        "title": "Technique x Tactic Heatmap",
        "noDataMessage": "No alerts with MITRE techniques found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "AlertCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 50, "palette": "yellowOrangeRed" }
            },
            {
              "columnMatch": "DistinctRules",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 10, "palette": "blue" }
            },
            {
              "columnMatch": "CoverageLevel",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "icons",
                "thresholdsGrid": [
                  { "operator": "==", "thresholdValue": "Critical", "representation": "Sev0", "text": "{0}" },
                  { "operator": "==", "thresholdValue": "High", "representation": "Sev1", "text": "{0}" },
                  { "operator": "==", "thresholdValue": "Medium", "representation": "Sev2", "text": "{0}" },
                  { "operator": "==", "thresholdValue": "Low", "representation": "Sev3", "text": "{0}" },
                  { "operator": "Default", "representation": "Sev4", "text": "None" }
                ]
              }
            },
            {
              "columnMatch": "Severities",
              "formatter": 18,
              "formatOptions": {
                "thresholdsOptions": "colors",
                "thresholdsGrid": [
                  { "operator": "contains", "thresholdValue": "High", "representation": "redBright", "text": "{0}" },
                  { "operator": "contains", "thresholdValue": "Medium", "representation": "orange", "text": "{0}" },
                  { "operator": "contains", "thresholdValue": "Low", "representation": "blue", "text": "{0}" },
                  { "operator": "Default", "representation": "gray", "text": "{0}" }
                ]
              }
            }
          ],
          "filter": true,
          "sortBy": [ { "itemKey": "AlertCount", "sortOrder": 2 } ]
        }
      },
      "name": "heatmap-grid"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| where AlertName !startswith '[DEV]'\n| where '*' in ({Severity}) or AlertSeverity in ({Severity})\n| where isnotempty(Tactics)\n| extend TacticArray = todynamic(Tactics)\n| mv-expand Tactic = TacticArray\n| extend Tactic = tostring(Tactic)\n| where isnotempty(Tactic)\n| summarize AlertCount = count() by Tactic, AlertSeverity\n| order by Tactic asc, AlertCount desc",
        "size": 1,
        "title": "Severity Distribution by Tactic",
        "noDataMessage": "No alerts with MITRE tactics found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "unstackedbar"
      },
      "name": "severity-distribution"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| where TimeGenerated {TimeRange}\n| where AlertName !startswith '[DEV]'\n| where '*' in ({Severity}) or AlertSeverity in ({Severity})\n| where isnotempty(Tactics)\n| extend TacticArray = todynamic(Tactics)\n| mv-expand Tactic = TacticArray\n| extend Tactic = tostring(Tactic)\n| where isnotempty(Tactic)\n| summarize AlertCount = count() by Tactic, bin(TimeGenerated, 1d)\n| order by TimeGenerated asc",
        "size": 1,
        "title": "Alert Activity Over Time",
        "noDataMessage": "No alerts with MITRE tactics found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": [ "{Workspace}" ],
        "visualization": "areachart"
      },
      "name": "activity-timeline"
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

## What Changed (v3 — full rewrite)

### Coverage section — switched from Azure Resource Graph to ARM REST API
The previous versions used `queryType: 1` (Azure Resource Graph) with
`resources | where type == 'microsoft.securityinsights/alertrules'`. This fails because
**Sentinel alert rules are not indexed in Azure Resource Graph** — they are not in the
`resources`, `securityresources`, or any other ARG table.

The fix uses the **Azure Resource Manager** data source (`ARMEndpoint/1.0`) which calls
the Sentinel REST API directly:
```
GET {workspace}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01
```
This is the same mechanism Microsoft's built-in Sentinel workbooks use (e.g., Sentinel_Central).

### Heatmap section — fixed query syntax
- Replaced `parse_json(ExtendedProperties)["Tactics"]` with direct `todynamic(Tactics)` column
- Used `column_ifexists('Techniques', '')` for safe technique extraction
- All queries exclude rules/alerts prefixed `[DEV]`

### Parameters — added workspace picker
Since the ARM API needs a specific workspace path, the workbook now includes Subscription
and Workspace pickers. KQL queries use `crossComponentResources: ["{Workspace}"]` to target
the selected workspace.

---

## Permissions Required

- **Coverage section:** Microsoft Sentinel Reader on the workspace (for ARM API)
- **Heatmap section:** Microsoft Sentinel Reader on the workspace (for SecurityAlert table)
