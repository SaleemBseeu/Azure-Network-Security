<#
.SYNOPSIS
    Azure DDoS Protection Assessment - Azure Automation Runbook Version

.DESCRIPTION
    This runbook assesses Azure DDoS Protection status across all Public IPs and
    sends results to Log Analytics for visualization in Grafana or Azure Workbooks.

    Designed to run as an Azure Automation Runbook with Managed Identity authentication.

.NOTES
    Author: Azure Network Security Team
    Version: 1.0.0

    Custom Log Table: DDoSProtectionAssessment_CL
#>

# Get automation variables
$workspaceId = Get-AutomationVariable -Name 'LogAnalyticsWorkspaceId'
$workspaceKey = Get-AutomationVariable -Name 'LogAnalyticsWorkspaceKey'
$subscriptionFilter = Get-AutomationVariable -Name 'SubscriptionIdsToScan'

# Log Analytics Data Collector API function
function Send-LogAnalyticsData {
    param(
        [string]$WorkspaceId,
        [string]$WorkspaceKey,
        [string]$LogType,
        [string]$JsonBody,
        [string]$TimeStampField = ""
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $JsonBody.Length

    $xHeaders = "x-ms-date:" + $rfc1123date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($WorkspaceKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash

    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $authorization
        "Log-Type"             = $LogType
        "x-ms-date"            = $rfc1123date
        "time-generated-field" = $TimeStampField
    }

    try {
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $JsonBody -UseBasicParsing
        return $response.StatusCode
    }
    catch {
        Write-Error "Failed to send data to Log Analytics: $_"
        return $null
    }
}

# Connect using Managed Identity
Write-Output "Connecting to Azure using Managed Identity..."
try {
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    Write-Output "Successfully connected to Azure"
}
catch {
    Write-Error "Failed to connect using Managed Identity: $_"
    throw
}

# Determine subscriptions to scan
$subscriptionsToScan = @()

if ([string]::IsNullOrWhiteSpace($subscriptionFilter)) {
    Write-Output "Scanning all accessible subscriptions..."
    $subscriptionsToScan = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
}
else {
    Write-Output "Scanning specified subscriptions..."
    $subIds = $subscriptionFilter -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    foreach ($subId in $subIds) {
        try {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
            $subscriptionsToScan += $sub
        }
        catch {
            Write-Warning "Could not access subscription $subId : $_"
        }
    }
}

Write-Output "Found $($subscriptionsToScan.Count) subscription(s) to scan"

# Global results collection
$allResults = @()
$scanTimestamp = [DateTime]::UtcNow.ToString("o")

# Function to get VNET from IP Configuration
function Get-VNetFromIpConfig {
    param(
        [string]$IpConfigId,
        [hashtable]$VnetCache
    )

    $vnetId = $null

    try {
        if ($IpConfigId -match "/providers/Microsoft\.Network/networkInterfaces/") {
            $nicId = $IpConfigId -replace "/ipConfigurations/.*$", ""
            $nic = Get-AzNetworkInterface -ResourceId $nicId -ErrorAction SilentlyContinue
            if ($nic -and $nic.IpConfigurations[0].Subnet) {
                $subnetId = $nic.IpConfigurations[0].Subnet.Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/applicationGateways/([^/]+)") {
            $appGwName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $appGw = Get-AzApplicationGateway -Name $appGwName -ResourceGroupName $rgName -ErrorAction SilentlyContinue
            if ($appGw -and $appGw.GatewayIPConfigurations[0].Subnet) {
                $subnetId = $appGw.GatewayIPConfigurations[0].Subnet.Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/loadBalancers/([^/]+)") {
            $lbName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $lb = Get-AzLoadBalancer -Name $lbName -ResourceGroupName $rgName -ErrorAction SilentlyContinue

            if ($lb) {
                foreach ($frontendConfig in $lb.FrontendIpConfigurations) {
                    if ($frontendConfig.Subnet) {
                        $subnetId = $frontendConfig.Subnet.Id
                        $vnetId = $subnetId -replace "/subnets/.*$", ""
                        break
                    }
                }

                if (-not $vnetId -and $lb.BackendAddressPools) {
                    foreach ($backendPool in $lb.BackendAddressPools) {
                        if ($backendPool.BackendIpConfigurations -and $backendPool.BackendIpConfigurations.Count -gt 0) {
                            $backendNicId = $backendPool.BackendIpConfigurations[0].Id -replace "/ipConfigurations/.*$", ""
                            $backendNic = Get-AzNetworkInterface -ResourceId $backendNicId -ErrorAction SilentlyContinue
                            if ($backendNic -and $backendNic.IpConfigurations[0].Subnet) {
                                $subnetId = $backendNic.IpConfigurations[0].Subnet.Id
                                $vnetId = $subnetId -replace "/subnets/.*$", ""
                                break
                            }
                        }
                    }
                }

                if (-not $vnetId) {
                    return @{
                        VNetId   = $null
                        VNetName = "(External LB)"
                        Status   = "ExternalLB"
                    }
                }
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/azureFirewalls/([^/]+)") {
            $fwName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $fw = Get-AzFirewall -Name $fwName -ResourceGroupName $rgName -ErrorAction SilentlyContinue
            if ($fw -and $fw.IpConfigurations[0].Subnet) {
                $subnetId = $fw.IpConfigurations[0].Subnet.Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/virtualNetworkGateways/([^/]+)") {
            $gwName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $gw = Get-AzVirtualNetworkGateway -Name $gwName -ResourceGroupName $rgName -ErrorAction SilentlyContinue
            if ($gw -and $gw.IpConfigurations[0].Subnet) {
                $subnetId = $gw.IpConfigurations[0].Subnet.Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/bastionHosts/([^/]+)") {
            $bastionName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $bastion = Get-AzBastion -ResourceGroupName $rgName -Name $bastionName -ErrorAction SilentlyContinue
            if ($bastion -and $bastion.IpConfigurations[0].Subnet) {
                $subnetId = $bastion.IpConfigurations[0].Subnet.Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }
        elseif ($IpConfigId -match "/providers/Microsoft\.Network/natGateways/([^/]+)") {
            $natGwName = $Matches[1]
            $rgName = ($IpConfigId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
            $natGw = Get-AzNatGateway -Name $natGwName -ResourceGroupName $rgName -ErrorAction SilentlyContinue
            if ($natGw -and $natGw.Subnets -and $natGw.Subnets.Count -gt 0) {
                $subnetId = $natGw.Subnets[0].Id
                $vnetId = $subnetId -replace "/subnets/.*$", ""
            }
        }

        if ($vnetId) {
            if ($VnetCache.ContainsKey($vnetId)) {
                $vnet = $VnetCache[$vnetId]
            }
            else {
                $vnetRg = ($vnetId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
                $vnetNameFromId = ($vnetId -split "/virtualNetworks/")[1]
                $vnet = Get-AzVirtualNetwork -Name $vnetNameFromId -ResourceGroupName $vnetRg -ErrorAction SilentlyContinue
                $VnetCache[$vnetId] = $vnet
            }

            if ($vnet) {
                return @{
                    VNetId   = $vnetId
                    VNetName = $vnet.Name
                    VNet     = $vnet
                    Status   = "Found"
                }
            }
            else {
                return @{
                    VNetId   = $vnetId
                    VNetName = "(Access Denied)"
                    Status   = "AccessDenied"
                }
            }
        }
    }
    catch {
        return @{
            VNetId       = $null
            VNetName     = "(Error)"
            Status       = "Error"
            ErrorMessage = $_.Exception.Message
        }
    }

    return @{
        VNetId   = $null
        VNetName = "(Not Found)"
        Status   = "NotFound"
    }
}

# Function to check diagnostic settings
function Get-DDoSDiagnosticStatus {
    param([string]$ResourceId)

    try {
        $diagSettings = Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        if (-not $diagSettings -or $diagSettings.Count -eq 0) {
            return @{
                Configured        = $false
                HasAnyDiagSettings = $false
                Categories        = @()
                Destination       = "None"
            }
        }

        $enabledCategories = @()
        $ddosLogsFound = 0
        $destinations = @()
        $hasAllLogs = $false

        foreach ($setting in $diagSettings) {
            if ($setting.WorkspaceId) { $destinations += "Log Analytics" }
            if ($setting.StorageAccountId) { $destinations += "Storage" }
            if ($setting.EventHubAuthorizationRuleId) { $destinations += "Event Hub" }

            $logs = if ($setting.PSObject.Properties['Logs']) { $setting.Logs }
            elseif ($setting.PSObject.Properties['Log']) { $setting.Log }
            else { @() }

            foreach ($log in $logs) {
                if (-not [string]::IsNullOrEmpty($log.CategoryGroup)) {
                    if ($log.Enabled -and $log.CategoryGroup -eq 'allLogs') {
                        $hasAllLogs = $true
                        $enabledCategories += "allLogs"
                    }
                }
                if (-not [string]::IsNullOrEmpty($log.Category)) {
                    if ($log.Enabled) {
                        $enabledCategories += $log.Category
                        $categoryLower = $log.Category.ToLower()
                        if ($categoryLower -match 'ddos') {
                            $ddosLogsFound++
                        }
                    }
                }
            }
        }

        $isDdosLoggingConfigured = $hasAllLogs -or ($ddosLogsFound -gt 0)

        return @{
            Configured          = $isDdosLoggingConfigured
            HasAnyDiagSettings  = $true
            DDoSCategoriesFound = $ddosLogsFound
            Categories          = $enabledCategories | Select-Object -Unique
            Destination         = if ($destinations.Count -gt 0) { ($destinations | Select-Object -Unique) -join ", " } else { "None" }
        }
    }
    catch {
        return @{
            Configured        = $false
            HasAnyDiagSettings = $false
            Categories        = @()
            Destination       = "Error: $($_.Exception.Message)"
        }
    }
}

# Process each subscription
foreach ($subscription in $subscriptionsToScan) {
    Write-Output "Scanning subscription: $($subscription.Name)"

    try {
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Failed to set context for $($subscription.Name): $_"
        continue
    }

    $publicIPs = Get-AzPublicIpAddress

    if ($publicIPs.Count -eq 0) {
        Write-Output "  No Public IPs found"
        continue
    }

    Write-Output "  Found $($publicIPs.Count) Public IP(s)"

    $vnetCache = @{}

    foreach ($pip in $publicIPs) {
        $result = @{
            TimeGenerated      = $scanTimestamp
            SubscriptionId     = $subscription.Id
            SubscriptionName   = $subscription.Name
            PublicIPName       = $pip.Name
            ResourceGroup      = $pip.ResourceGroupName
            Location           = $pip.Location
            IPAddress          = if ($pip.IpAddress) { $pip.IpAddress } else { "(Dynamic)" }
            IPSku              = $pip.Sku.Name
            Allocation         = $pip.PublicIpAllocationMethod
            DDoSProtected      = "No"
            RiskLevel          = "High"
            DDoSSku            = "None"
            DDoSPlanName       = "N/A"
            VNetName           = "-"
            AssociatedResource = "Not attached"
            ResourceType       = "Unattached"
            DiagnosticLogging  = "N/A"
            LogDestination     = "N/A"
        }

        $protectionMode = $pip.DdosSettings.ProtectionMode

        # Determine associated resource
        if ($pip.IpConfiguration) {
            $ipConfigId = $pip.IpConfiguration.Id

            if ($ipConfigId -match "/networkInterfaces/([^/]+)") {
                $result.ResourceType = "VM/NIC"
                $result.AssociatedResource = $Matches[1]
            }
            elseif ($ipConfigId -match "/applicationGateways/([^/]+)") {
                $result.ResourceType = "Application Gateway"
                $result.AssociatedResource = $Matches[1]
            }
            elseif ($ipConfigId -match "/loadBalancers/([^/]+)") {
                $result.ResourceType = "Load Balancer"
                $result.AssociatedResource = $Matches[1]
            }
            elseif ($ipConfigId -match "/azureFirewalls/([^/]+)") {
                $result.ResourceType = "Azure Firewall"
                $result.AssociatedResource = $Matches[1]
            }
            elseif ($ipConfigId -match "/virtualNetworkGateways/([^/]+)") {
                $result.ResourceType = "VPN/ER Gateway"
                $result.AssociatedResource = $Matches[1]
            }
            elseif ($ipConfigId -match "/bastionHosts/([^/]+)") {
                $result.ResourceType = "Bastion"
                $result.AssociatedResource = $Matches[1]
            }

            $vnetInfo = Get-VNetFromIpConfig -IpConfigId $ipConfigId -VnetCache $vnetCache
            $result.VNetName = $vnetInfo.VNetName
        }
        elseif ($pip.NatGateway) {
            $result.ResourceType = "NAT Gateway"
            $result.AssociatedResource = ($pip.NatGateway.Id -split "/")[-1]

            $vnetInfo = Get-VNetFromIpConfig -IpConfigId $pip.NatGateway.Id -VnetCache $vnetCache
            $result.VNetName = $vnetInfo.VNetName
        }

        # Evaluate protection status
        if ([string]::IsNullOrEmpty($protectionMode)) {
            $protectionMode = "VirtualNetworkInherited"
        }

        switch ($protectionMode) {
            "Enabled" {
                if ($pip.DdosSettings.DdosProtectionPlan -and $pip.DdosSettings.DdosProtectionPlan.Id) {
                    $result.DDoSProtected = "Yes"
                    $result.DDoSSku = "Network Protection"
                    $result.DDoSPlanName = ($pip.DdosSettings.DdosProtectionPlan.Id -split "/")[-1]
                    $result.RiskLevel = "Low"
                }
                else {
                    $result.DDoSProtected = "Yes"
                    $result.DDoSSku = "IP Protection"
                    $result.RiskLevel = "Low"
                }
            }
            "VirtualNetworkInherited" {
                if ($vnetInfo -and $vnetInfo.VNet -and $vnetInfo.VNet.DdosProtectionPlan) {
                    $result.DDoSProtected = "Yes"
                    $result.DDoSSku = "Network Protection"
                    $result.DDoSPlanName = ($vnetInfo.VNet.DdosProtectionPlan.Id -split "/")[-1]
                    $result.RiskLevel = "Low"
                }
                else {
                    $result.DDoSProtected = "No"
                    $result.DDoSSku = "VNET not protected"
                    $result.RiskLevel = "High"
                }
            }
            "Disabled" {
                $result.DDoSProtected = "No"
                $result.DDoSSku = "Disabled"
                $result.RiskLevel = "High"
            }
        }

        # Check diagnostic settings for protected IPs
        if ($result.DDoSProtected -eq "Yes") {
            $diagStatus = Get-DDoSDiagnosticStatus -ResourceId $pip.Id
            if ($diagStatus.Configured) {
                $result.DiagnosticLogging = "Configured"
            }
            else {
                $result.DiagnosticLogging = "Not Configured"
            }
            $result.LogDestination = $diagStatus.Destination
        }

        $allResults += $result
    }
}

# Send results to Log Analytics
if ($allResults.Count -gt 0) {
    Write-Output "Sending $($allResults.Count) results to Log Analytics..."

    $json = $allResults | ConvertTo-Json -Depth 10

    # Handle single result (ConvertTo-Json doesn't wrap single object in array)
    if ($allResults.Count -eq 1) {
        $json = "[$json]"
    }

    $statusCode = Send-LogAnalyticsData -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType "DDoSProtectionAssessment" -JsonBody $json -TimeStampField "TimeGenerated"

    if ($statusCode -eq 200) {
        Write-Output "Successfully sent data to Log Analytics"
    }
    else {
        Write-Error "Failed to send data to Log Analytics. Status code: $statusCode"
    }

    # Output summary
    $summary = @{
        TotalPublicIPs       = $allResults.Count
        Protected            = ($allResults | Where-Object { $_.DDoSProtected -eq "Yes" }).Count
        NetworkProtection    = ($allResults | Where-Object { $_.DDoSSku -eq "Network Protection" }).Count
        IPProtection         = ($allResults | Where-Object { $_.DDoSSku -eq "IP Protection" }).Count
        NotProtected         = ($allResults | Where-Object { $_.DDoSProtected -eq "No" }).Count
        DiagnosticsConfigured = ($allResults | Where-Object { $_.DiagnosticLogging -eq "Configured" }).Count
        HighRisk             = ($allResults | Where-Object { $_.RiskLevel -eq "High" }).Count
    }

    Write-Output "`n=== Assessment Summary ==="
    Write-Output "Total Public IPs: $($summary.TotalPublicIPs)"
    Write-Output "Protected: $($summary.Protected) (Network: $($summary.NetworkProtection), IP: $($summary.IPProtection))"
    Write-Output "Not Protected: $($summary.NotProtected)"
    Write-Output "Diagnostics Configured: $($summary.DiagnosticsConfigured)"
    Write-Output "High Risk: $($summary.HighRisk)"
}
else {
    Write-Output "No Public IPs found across all subscriptions"
}

Write-Output "`nAssessment completed successfully"
