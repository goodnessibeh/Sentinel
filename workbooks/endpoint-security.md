# Endpoint Security Dashboard

Endpoint security posture overview for Microsoft Defender for Endpoint. Tracks device inventory health, malware detection trends, vulnerability severity distribution, and software exposure across your fleet.

- **KPI Tiles** — Total devices, onboarding percentage, malware detection count, and active sensor health
- **Malware Detection Timeline** — Daily antivirus detection trend over time
- **Top Detected Threats** — Most frequently detected threat names with affected device counts
- **Vulnerability Severity Breakdown** — Stacked bar chart of vulnerability counts by severity level
- **Device Exposure Level Distribution** — Pie chart of device exposure levels across the fleet
- **Top Vulnerable Software** — Highest-risk software by vulnerability count with critical severity breakdown
- **Device OS Distribution** — Pie chart of operating system platforms across managed devices

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
        "json": "# Endpoint Security Dashboard\n---\nEndpoint security posture overview.\nSelect your Sentinel workspace above to load data."
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
        "json": "---\n## Device Health KPIs\nKey metrics for device inventory, onboarding coverage, malware detections, and sensor health."
      },
      "name": "kpi-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "let totalDevices = DeviceInfo\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by DeviceId\n| summarize Value = dcount(DeviceId)\n| extend Metric = 'Total Devices';\nlet onboardedPct = DeviceInfo\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by DeviceId\n| summarize Value = round(toreal(countif(OnboardingStatus == 'Onboarded')) / count() * 100, 1)\n| extend Metric = 'Onboarded %';\nlet malwareDetections = DeviceEvents\n| where TimeGenerated {TimeRange}\n| where ActionType == 'AntivirusDetection'\n| summarize Value = count()\n| extend Metric = 'Malware Detections';\nlet activeSensor = DeviceInfo\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by DeviceId\n| summarize Value = round(toreal(countif(SensorHealthState == 'Active')) / count() * 100, 1)\n| extend Metric = 'Active Sensor %';\nunion totalDevices, onboardedPct, malwareDetections, activeSensor\n| project Metric, Value",
        "size": 4,
        "title": "Device Health KPIs",
        "noDataMessage": "No device data available.",
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
              { "operator": "==", "value": "Total Devices", "color": "#0078D4" },
              { "operator": "==", "value": "Onboarded %", "color": "#107C10" },
              { "operator": "==", "value": "Malware Detections", "color": "#D13438" },
              { "operator": "==", "value": "Active Sensor %", "color": "#008272" },
              { "operator": "Default", "color": "#004578" }
            ],
            "rowColoring": "Metric"
          }
        }
      },
      "name": "device-health-kpi-tiles"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Malware Detection Timeline\nDaily antivirus detection trend over the selected time range."
      },
      "name": "malware-timeline-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceEvents\n| where TimeGenerated {TimeRange}\n| where ActionType == 'AntivirusDetection'\n| make-series DetectionCount = count() default = 0 on TimeGenerated from {TimeRange:start} to {TimeRange:end} step 1d",
        "size": 1,
        "title": "Malware Detection Timeline",
        "noDataMessage": "No antivirus detections found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "timechart"
      },
      "name": "malware-detection-timeline"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Detected Threats\nMost frequently detected threat names with affected device counts."
      },
      "name": "top-threats-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceEvents\n| where TimeGenerated {TimeRange}\n| where ActionType == 'AntivirusDetection'\n| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)\n| where isnotempty(ThreatName)\n| summarize DetectionCount = count(), AffectedDevices = dcount(DeviceName), DeviceList = make_set(DeviceName, 10) by ThreatName\n| order by DetectionCount desc\n| take 15",
        "size": 0,
        "title": "Top Detected Threats",
        "noDataMessage": "No threat detections found in the selected time range.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "DetectionCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "DetectionCount", "sortOrder": 2 }]
        }
      },
      "name": "top-detected-threats"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Vulnerability Severity Breakdown\nDistribution of unique vulnerabilities (CVEs) by severity level."
      },
      "name": "vuln-severity-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceTvmSoftwareVulnerabilities\n| where TimeGenerated > ago(1d)\n| summarize VulnCount = dcount(CveId) by VulnerabilitySeverityLevel\n| order by case(VulnerabilitySeverityLevel == 'Critical', 1, VulnerabilitySeverityLevel == 'High', 2, VulnerabilitySeverityLevel == 'Medium', 3, VulnerabilitySeverityLevel == 'Low', 4, 5) asc",
        "size": 1,
        "title": "Vulnerability Severity Breakdown",
        "noDataMessage": "No vulnerability data available.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "barchart",
        "chartSettings": {
          "seriesLabelSettings": [
            { "seriesName": "Critical", "color": "#D13438" },
            { "seriesName": "High", "color": "#F7630C" },
            { "seriesName": "Medium", "color": "#FFC83D" },
            { "seriesName": "Low", "color": "#0078D4" }
          ]
        }
      },
      "name": "vuln-severity-barchart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Device Exposure Level Distribution\nBreakdown of devices by their computed exposure level."
      },
      "name": "exposure-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceInfo\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by DeviceId\n| summarize Count = count() by ExposureLevel\n| order by Count desc",
        "size": 3,
        "title": "Device Exposure Level Distribution",
        "noDataMessage": "No device exposure data available.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "exposure-level-piechart"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Top Vulnerable Software\nSoftware with the highest vulnerability counts, including critical severity breakdown."
      },
      "name": "top-vuln-software-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceTvmSoftwareVulnerabilities\n| where TimeGenerated > ago(1d)\n| summarize VulnCount = dcount(CveId), AffectedDevices = dcount(DeviceName), CriticalCount = dcountif(CveId, VulnerabilitySeverityLevel == 'Critical') by SoftwareName, SoftwareVendor\n| top 15 by VulnCount desc",
        "size": 0,
        "title": "Top 15 Vulnerable Software",
        "noDataMessage": "No vulnerability data available.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "table",
        "gridSettings": {
          "formatters": [
            {
              "columnMatch": "VulnCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 100, "palette": "yellowOrangeRed" }
            },
            {
              "columnMatch": "CriticalCount",
              "formatter": 8,
              "formatOptions": { "min": 0, "max": 50, "palette": "redBright" }
            }
          ],
          "filter": true,
          "sortBy": [{ "itemKey": "VulnCount", "sortOrder": 2 }]
        }
      },
      "name": "top-vulnerable-software"
    },
    {
      "type": 1,
      "content": {
        "json": "---\n## Device OS Distribution\nOperating system platform breakdown across all managed devices."
      },
      "name": "os-dist-header"
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "DeviceInfo\n| where TimeGenerated > ago(1d)\n| summarize arg_max(TimeGenerated, *) by DeviceId\n| summarize Count = count() by OSPlatform\n| order by Count desc",
        "size": 3,
        "title": "Device OS Distribution",
        "noDataMessage": "No device OS data available.",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"],
        "visualization": "piechart"
      },
      "name": "os-distribution-piechart"
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

Microsoft Sentinel Reader (or higher) on the workspace. Microsoft Defender for Endpoint data tables (DeviceInfo, DeviceEvents, DeviceTvmSoftwareVulnerabilities) must be streaming into the workspace.
