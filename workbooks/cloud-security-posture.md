# Cloud Security Posture Dashboard

Azure misconfigurations, resource exposure, and compliance scores for Microsoft Sentinel. Monitors Azure Activity operations, resource deletions, NSG rule changes, Key Vault access, and caller behavior.

- **KPI Tiles** — Total operations, delete operations, failed operations, and distinct callers at a glance
- **Azure Activity by Risk Level** — Time series of operations categorized as High (DELETE), Medium (WRITE/CREATE/ACTION), or Low risk
- **Resource Deletion Activity** — Top callers performing successful delete operations with resource details and heatmap
- **Public-Facing NSG Rule Changes** — Inbound allow rules opened to the internet (0.0.0.0/0, *, Internet)
- **Key Vault Access Monitoring** — Secret, key, and certificate operations by caller with access frequency heatmap
- **Top Active Callers** — Bar chart of the 15 most active Azure callers by operation count
- **Azure Operations Timeline** — Area chart of daily operations by status (Succeeded/Failed)

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
        "json": "# Cloud Security Posture Dashboard\n---\nAzure misconfigurations, resource exposure, and compliance scores.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Azure Operations Overview\nKey performance indicators for Azure activity in the selected time range."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let totalOps = AzureActivity\n| where TimeGenerated {TimeRange}\n| summarize Value = count()\n| extend Metric = 'Total Azure Operations';\nlet deleteOps = AzureActivity\n| where TimeGenerated {TimeRange}\n| summarize Value = countif(OperationNameValue has \"delete\")\n| extend Metric = 'Delete Operations';\nlet failedOps = AzureActivity\n| where TimeGenerated {TimeRange}\n| summarize Value = countif(ActivityStatusValue == \"Failed\")\n| extend Metric = 'Failed Operations';\nlet callers = AzureActivity\n| where TimeGenerated {TimeRange}\n| summarize Value = dcount(Caller)\n| extend Metric = 'Distinct Callers';\nunion totalOps, deleteOps, failedOps, callers\n| project Metric, Value",
        "size": 4,
        "title": "Azure Operations Overview",
        "noDataMessage": "No Azure Activity data found.",
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
              { "operator": "contains", "value": "Total", "color": "#0078D4" },
              { "operator": "contains", "value": "Delete", "color": "#D13438" },
              { "operator": "contains", "value": "Failed", "color": "#F7630C" },
              { "operator": "contains", "value": "Callers", "color": "#107C10" },
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
        "json": "---\n## Azure Activity by Risk Level\nOperations classified by risk: DELETE = High, WRITE/CREATE/ACTION = Medium, all others = Low."
      },
      "name": "risk-level-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureActivity\n| where TimeGenerated {TimeRange}\n| extend RiskLevel = case(\n    OperationNameValue has \"DELETE\", \"High\",\n    OperationNameValue has_any (\"WRITE\", \"CREATE\", \"ACTION\"), \"Medium\",\n    \"Low\")\n| make-series OperationCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d by RiskLevel",
        "size": 1,
        "title": "Azure Activity by Risk Level",
        "noDataMessage": "No Azure Activity data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "risk-level-timechart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Resource Deletion Activity\nTop 15 callers performing successful delete operations, with affected resources and resource groups."
      },
      "name": "deletion-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureActivity\n| where TimeGenerated {TimeRange}\n| where OperationNameValue has \"delete\" and ActivityStatusValue == \"Succeeded\"\n| summarize DeleteCount = count(), Resources = make_set(Resource, 10), ResourceGroups = make_set(ResourceGroup, 5) by Caller, CallerIpAddress\n| top 15 by DeleteCount desc",
        "size": 0,
        "title": "Resource Deletion Activity",
        "noDataMessage": "No successful delete operations found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "DeleteCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "DeleteCount", "sortOrder": 2 }]
        }
      },
      "name": "deletion-table"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Public-Facing NSG Rule Changes\nNSG security rule writes that open inbound access from the internet (source: *, 0.0.0.0/0, or Internet)."
      },
      "name": "nsg-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureActivity\n| where TimeGenerated {TimeRange}\n| where OperationNameValue has \"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE\"\n| extend ParsedProps = parse_json(Properties)\n| extend Direction = tostring(ParsedProps.direction),\n         Access = tostring(ParsedProps.access),\n         SourceAddressPrefix = tostring(ParsedProps.sourceAddressPrefix)\n| where Direction =~ \"Inbound\" and Access =~ \"Allow\" and SourceAddressPrefix in (\"*\", \"0.0.0.0/0\", \"Internet\")\n| project TimeGenerated, Caller, ResourceGroup, Resource, SourceAddressPrefix\n| order by TimeGenerated desc",
        "size": 0,
        "title": "Public-Facing NSG Rule Changes",
        "noDataMessage": "No public-facing NSG rule changes detected.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "filter": true,
          "sortBy": [{ "itemKey": "TimeGenerated", "sortOrder": 2 }]
        }
      },
      "name": "nsg-rule-changes"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Key Vault Access Monitoring\nSecret, key, and certificate operations on Azure Key Vault resources with access frequency heatmap."
      },
      "name": "keyvault-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureDiagnostics\n| where TimeGenerated {TimeRange}\n| where ResourceType == \"VAULTS\"\n| where OperationName in (\"SecretGet\", \"SecretSet\", \"SecretDelete\", \"KeyGet\", \"KeyCreate\", \"CertificateGet\")\n| summarize AccessCount = count() by OperationName, CallerIPAddress, identity_claim_upn_s\n| order by AccessCount desc",
        "size": 0,
        "title": "Key Vault Access Monitoring",
        "noDataMessage": "No Key Vault access data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "AccessCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "AccessCount", "sortOrder": 2 }]
        }
      },
      "name": "keyvault-access"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Active Callers\nThe 15 most active Azure callers by total operation count."
      },
      "name": "callers-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureActivity\n| where TimeGenerated {TimeRange}\n| summarize OperationCount = count() by Caller\n| top 15 by OperationCount desc",
        "size": 1,
        "title": "Top Active Callers",
        "noDataMessage": "No Azure Activity data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart"
      },
      "name": "top-callers-bar"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Azure Operations Timeline\nDaily operation volume by status (Succeeded vs Failed)."
      },
      "name": "operations-timeline-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "AzureActivity\n| where TimeGenerated {TimeRange}\n| make-series OperationCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d by ActivityStatusValue",
        "size": 1,
        "title": "Azure Operations Timeline",
        "noDataMessage": "No Azure Activity data found.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "areachart"
      },
      "name": "operations-timeline-area"
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

Microsoft Sentinel Reader (or higher) on the workspace. Key Vault diagnostics must be enabled and forwarding to the Log Analytics workspace for the Key Vault Access Monitoring panel.
