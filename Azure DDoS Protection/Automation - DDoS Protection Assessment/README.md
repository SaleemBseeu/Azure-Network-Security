# Azure DDoS Protection Assessment - Automated Solution

Automated solution that continuously assesses Azure DDoS Protection status across your Azure environment and visualizes results in Grafana.

## What Gets Deployed

| Component | Description |
|-----------|-------------|
| **Azure Automation Account** | Runs the assessment script on a schedule |
| **System Managed Identity** | Secure authentication to Azure resources |
| **Log Analytics Workspace** | Stores assessment results for querying |
| **PowerShell Runbook** | The assessment script |
| **Schedule** | Automated daily/weekly execution |
| **Role Assignments** | Reader on subscription, Log Analytics Contributor |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Automated Assessment                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────────┐                                                  │
│   │  Azure Automation │                                                  │
│   │    (Scheduled)    │                                                  │
│   │                   │                                                  │
│   │  ┌─────────────┐  │     ┌──────────────────┐     ┌──────────────┐  │
│   │  │  Runbook    │──┼────▶│  Log Analytics   │────▶│   Grafana    │  │
│   │  │ (PowerShell)│  │     │  Custom Table    │     │  Dashboard   │  │
│   │  └─────────────┘  │     └──────────────────┘     └──────────────┘  │
│   │         │         │                                                  │
│   │         ▼         │                                                  │
│   │  Managed Identity │                                                  │
│   └─────────┬─────────┘                                                  │
│             │                                                            │
│             ▼                                                            │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     Azure Subscriptions                          │   │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │   │
│   │  │ Sub 1    │  │ Sub 2    │  │ Sub 3    │  │ Sub N    │        │   │
│   │  │ (Reader) │  │ (Reader) │  │ (Reader) │  │ (Reader) │        │   │
│   │  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## One-Click Deployment

### Option 1: Deploy to Azure Button

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Network-Security%2Fmaster%2FAzure%2520DDoS%2520Protection%2FAutomation%2520-%2520DDoS%2520Protection%2520Assessment%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Network-Security%2Fmaster%2FAzure%2520DDoS%2520Protection%2FAutomation%2520-%2520DDoS%2520Protection%2520Assessment%2FcreateUiDefinition.json)

### Option 2: Azure CLI

```bash
# Create resource group
az group create --name rg-ddos-assessment --location eastus

# Deploy the template
az deployment group create \
  --resource-group rg-ddos-assessment \
  --template-file azuredeploy.json \
  --parameters automationAccountName=aa-ddos-assessment \
               logAnalyticsWorkspaceName=law-ddos-assessment \
               scheduleFrequency=Day \
               scheduleInterval=1
```

### Option 3: PowerShell

```powershell
# Create resource group
New-AzResourceGroup -Name "rg-ddos-assessment" -Location "eastus"

# Deploy the template
New-AzResourceGroupDeployment `
    -ResourceGroupName "rg-ddos-assessment" `
    -TemplateFile "azuredeploy.json" `
    -automationAccountName "aa-ddos-assessment" `
    -logAnalyticsWorkspaceName "law-ddos-assessment" `
    -scheduleFrequency "Day" `
    -scheduleInterval 1
```

## Post-Deployment Steps

### 1. Grant Reader Access to Additional Subscriptions

The deployment only grants Reader role on the **deployment subscription**. To scan other subscriptions:

```powershell
# Get the Managed Identity Principal ID (from deployment outputs)
$principalId = "<automation-account-principal-id>"

# Grant Reader on each additional subscription
$subscriptionIds = @(
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222"
)

foreach ($subId in $subscriptionIds) {
    New-AzRoleAssignment `
        -ObjectId $principalId `
        -RoleDefinitionName "Reader" `
        -Scope "/subscriptions/$subId"
}
```

Or via Azure CLI:

```bash
PRINCIPAL_ID="<automation-account-principal-id>"

# For each subscription
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Reader" \
  --scope "/subscriptions/<subscription-id>"
```

### 2. Run Initial Assessment

The scheduled job will run automatically. To run immediately:

1. Go to **Azure Portal** → **Automation Account** → **Runbooks**
2. Select **Check-DDoSProtection**
3. Click **Start**
4. Monitor execution in **Jobs**

### 3. Verify Data in Log Analytics

Wait ~5 minutes after the runbook completes, then run this query:

```kusto
DDoSProtectionAssessment_CL
| take 10
```

## Setting Up Grafana Dashboard

### Prerequisites

- Grafana instance (Azure Managed Grafana or self-hosted)
- Azure Monitor data source configured

### Import Dashboard

1. In Grafana, go to **Dashboards** → **Import**
2. Upload the file `grafana/ddos-assessment-dashboard.json`
3. Select your Azure Monitor data source
4. Select your Log Analytics workspace
5. Click **Import**

### Dashboard Features

| Panel | Description |
|-------|-------------|
| **Total Public IPs** | Count of all discovered Public IPs |
| **Protected IPs** | Count of IPs with DDoS protection |
| **Unprotected IPs** | Count of IPs without protection (High Risk) |
| **Protection Coverage** | Percentage gauge of protected vs total |
| **Protection by SKU** | Pie chart: Network Protection vs IP Protection |
| **By Subscription** | Distribution across subscriptions |
| **Unprotected Table** | Remediation list with details |
| **Protection Trend** | Historical view of coverage over time |
| **Missing Logging** | Protected IPs without diagnostic logging |

## Sample KQL Queries

### Protection Summary

```kusto
DDoSProtectionAssessment_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by PublicIPName_s, SubscriptionId_s
| summarize 
    TotalIPs = count(),
    Protected = countif(DDoSProtected_s == "Yes"),
    Unprotected = countif(DDoSProtected_s == "No"),
    NetworkProtection = countif(DDoSSku_s == "Network Protection"),
    IPProtection = countif(DDoSSku_s == "IP Protection"),
    LoggingConfigured = countif(DiagnosticLogging_s == "Configured")
| extend ProtectionRate = round(100.0 * Protected / TotalIPs, 1)
```

### Unprotected Resources by Subscription

```kusto
DDoSProtectionAssessment_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by PublicIPName_s, SubscriptionId_s
| where DDoSProtected_s == "No"
| summarize 
    UnprotectedCount = count(),
    Resources = make_list(PublicIPName_s, 10)
    by SubscriptionName_s
| order by UnprotectedCount desc
```

### Missing Diagnostic Logging

```kusto
DDoSProtectionAssessment_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by PublicIPName_s, SubscriptionId_s
| where DDoSProtected_s == "Yes" and DiagnosticLogging_s == "Not Configured"
| project 
    SubscriptionName_s,
    PublicIPName_s,
    DDoSSku_s,
    ResourceType_s,
    AssociatedResource_s
```

### Protection Trend Over 30 Days

```kusto
DDoSProtectionAssessment_CL
| where TimeGenerated > ago(30d)
| summarize 
    Protected = dcountif(PublicIPName_s, DDoSProtected_s == "Yes"),
    Unprotected = dcountif(PublicIPName_s, DDoSProtected_s == "No")
    by bin(TimeGenerated, 1d)
| extend ProtectionRate = round(100.0 * Protected / (Protected + Unprotected), 1)
| order by TimeGenerated asc
```

## Alerting

### Create Alert for New Unprotected IPs

```kusto
// Alert when new unprotected IPs are discovered
let yesterday = DDoSProtectionAssessment_CL
| where TimeGenerated between (ago(2d) .. ago(1d))
| where DDoSProtected_s == "No"
| distinct PublicIPName_s, SubscriptionId_s;

DDoSProtectionAssessment_CL
| where TimeGenerated > ago(1d)
| where DDoSProtected_s == "No"
| distinct PublicIPName_s, SubscriptionId_s
| join kind=leftanti yesterday on PublicIPName_s, SubscriptionId_s
```

### Create Alert for Protection Coverage Drop

```kusto
DDoSProtectionAssessment_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by PublicIPName_s, SubscriptionId_s
| summarize 
    Total = count(),
    Protected = countif(DDoSProtected_s == "Yes")
| extend ProtectionRate = 100.0 * Protected / Total
| where ProtectionRate < 80 // Alert if coverage drops below 80%
```

## Customization

### Change Schedule

Modify the schedule in the Automation Account:

1. **Azure Portal** → **Automation Account** → **Schedules**
2. Select **DDoSAssessmentSchedule**
3. Modify frequency/time
4. Save

### Limit Subscription Scope

Update the automation variable:

1. **Automation Account** → **Variables**
2. Select **SubscriptionIdsToScan**
3. Enter comma-separated subscription IDs
4. Save

### Extend Retention

By default, Log Analytics retains data for 90 days. To extend:

```powershell
Set-AzOperationalInsightsWorkspace `
    -ResourceGroupName "rg-ddos-assessment" `
    -Name "law-ddos-assessment" `
    -RetentionInDays 365
```

## Cost Estimate

| Component | Estimated Monthly Cost |
|-----------|------------------------|
| Automation Account (Basic) | ~$0 (500 mins free) |
| Log Analytics | ~$2-5 (depends on data volume) |
| **Total** | **~$2-5/month** |

*Based on scanning 100 subscriptions with 1000 total Public IPs daily*

## Troubleshooting

### Runbook Fails with Authentication Error

- Verify Managed Identity is enabled on Automation Account
- Check Reader role is assigned to subscriptions
- View detailed error in **Jobs** → **Output/Errors**

### No Data in Log Analytics

- Wait 5-10 minutes after runbook completion
- Verify workspace ID/key in Automation Variables
- Check for ingestion errors in Jobs output

### Grafana Shows No Data

- Verify Azure Monitor data source is configured
- Check workspace variable is set correctly
- Test KQL query directly in Log Analytics

## File Structure

```
Automation - DDoS Protection Assessment/
├── azuredeploy.json              # ARM template
├── createUiDefinition.json       # Portal UI definition
├── README.md                     # This file
├── scripts/
│   ├── Check-DDoSProtection-LogAnalytics.ps1   # Automation runbook
│   └── Check-DDoSProtection-Standalone.ps1     # Manual execution
└── grafana/
    └── ddos-assessment-dashboard.json
```

## Manual Script Usage

For quick assessments without automation setup:

```powershell
# Download and run the standalone script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/Azure-Network-Security/master/Azure%20DDoS%20Protection/Automation%20-%20DDoS%20Protection%20Assessment/scripts/Check-DDoSProtection-Standalone.ps1" -OutFile "Check-DDoSProtection.ps1"

# Scan current subscription
.\Check-DDoSProtection.ps1

# Scan all subscriptions with CSV export
.\Check-DDoSProtection.ps1 -AllSubscriptions -ExportPath "DDoS-Report.csv"
```

## Related Resources

- [Azure DDoS Protection Overview](https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview)
- [Azure Automation Documentation](https://learn.microsoft.com/en-us/azure/automation/)
- [Log Analytics Custom Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- [Azure Managed Grafana](https://learn.microsoft.com/en-us/azure/managed-grafana/)
