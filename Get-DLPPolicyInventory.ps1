#Requires -Version 7.2
<#
.SYNOPSIS
    Exports DLP policy definitions, rules, and Copilot location coverage from Purview

.DESCRIPTION
    Retrieves all DLP compliance policies and their associated rules to build a
    DLP coverage map. For each policy: enabled status, workloads, enforcement mode,
    and whether the Copilot location is enabled. For each rule: SIT conditions,
    actions, confidence thresholds, and severity.

    The key output for Classify is: for each SIT found in Content Explorer, is there
    a DLP policy covering that SIT on SharePoint? If not, that's a finding.

.PARAMETER AADTenantName
    The AAD/Entra tenant name (e.g., 'contoso' for contoso.onmicrosoft.com).

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.PARAMETER UserPrincipalName
    Optional UPN for interactive IPPS authentication. When omitted, the script
    prompts for a UPN and uses interactive user sign-in.

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Interactive user sign-in
    Required Module: ExchangeOnlineManagement
    Required Role: Compliance Administrator
    Cadence: Weekly
    Estimated Runtime: Under 5 minutes
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$AADTenantName,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,

    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [string]$UserPrincipalName
)

. (Join-Path $PSScriptRoot 'Shared\DiscoveryConfig.ps1')

Use-DiscoveryDefaults -CliParameters @{
    AADTenantName    = $AADTenantName
    CloudEnvironment = $CloudEnvironment
} -Required @('AADTenantName', 'CloudEnvironment') `
  -Defaults @{ CloudEnvironment = 'Commercial' } `
  -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $UserPrincipalName = Read-Host 'Enter UPN for interactive IPPS sign-in'
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        throw 'A UserPrincipalName is required for interactive DLP policy export.'
    }
}

# Check for required module
$requiredModules = @('ExchangeOnlineManagement')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Required module '$module' is not installed." -ForegroundColor Yellow
        $install = Read-Host "Would you like to install it now? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y') {
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-Host "Module '$module' installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install module '$module': $_"
                exit 1
            }
        }
        else {
            Write-Error "Required module '$module' is not installed. Exiting."
            exit 1
        }
    }
}

Import-Module ExchangeOnlineManagement

# Connect to Security & Compliance PowerShell
function Connect-IPPSCompliance {
    param (
        [string]$CloudEnvironment,
        [string]$UserPrincipalName
    )

    try {
        $connectionParams = @{
            UserPrincipalName = $UserPrincipalName
        }

        if ($CloudEnvironment -eq 'GCCH') {
            $connectionParams['ConnectionUri'] = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            $connectionParams['AzureADAuthorizationEndpointUri'] = 'https://login.microsoftonline.us/organizations'
        }

        Write-Host "Connecting to Security & Compliance PowerShell ($CloudEnvironment) with interactive user authentication..." -ForegroundColor Cyan
        Connect-IPPSSession @connectionParams
        Write-Host "Successfully connected to IPPS" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Security & Compliance PowerShell: $_"
        exit 1
    }
}

function Test-IppsDlpCmdletAvailability {
    $getPolicyCommand = Get-Command -Name 'Get-DlpCompliancePolicy' -ErrorAction SilentlyContinue
    $getRuleCommand = Get-Command -Name 'Get-DlpComplianceRule' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HasGetDlpCompliancePolicy = $null -ne $getPolicyCommand
        HasGetDlpComplianceRule = $null -ne $getRuleCommand
    }
}

# Main execution
try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "=== DLP Policy Inventory ===" -ForegroundColor Cyan
    Write-Host "Tenant (AAD): $AADTenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host ""

    # Connect to IPPS
    Connect-IPPSCompliance -CloudEnvironment $CloudEnvironment `
        -UserPrincipalName $UserPrincipalName

    $syncedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $ippsCmdlets = Test-IppsDlpCmdletAvailability

    if (-not $ippsCmdlets.HasGetDlpCompliancePolicy) {
        throw 'Get-DlpCompliancePolicy is not available in this IPPS session. This tenant or role assignment does not expose DLP policy cmdlets in the current connection.'
    }

    if (-not $ippsCmdlets.HasGetDlpComplianceRule) {
        throw 'Get-DlpComplianceRule is not available in this IPPS session. This tenant or role assignment does not expose DLP rule cmdlets in the current connection.'
    }

    # --- Export DLP Policies ---
    Write-Host "Retrieving DLP compliance policies..." -ForegroundColor Cyan
    $policies = Get-DlpCompliancePolicy

    $policyResults = @()

    if ($policies) {
        Write-Host "Found $($policies.Count) DLP policies" -ForegroundColor Green

        foreach ($policy in $policies) {
            # Determine workloads from location properties
            $workloads = @()
            if ($policy.SharePointLocation)       { $workloads += 'SPO' }
            if ($policy.OneDriveLocation)          { $workloads += 'ODB' }
            if ($policy.ExchangeLocation)          { $workloads += 'EXO' }
            if ($policy.TeamsLocation)             { $workloads += 'Teams' }
            if ($policy.EndpointDlpLocation)       { $workloads += 'Endpoints' }

            # Check for Copilot location
            $copilotEnabled = $false
            if ($policy.PSObject.Properties.Name -contains 'ThirdPartyAppDlpLocation') {
                $copilotEnabled = [bool]$policy.ThirdPartyAppDlpLocation
            }
            if ($policy.PSObject.Properties.Name -contains 'M365CopilotLocation') {
                $copilotEnabled = [bool]$policy.M365CopilotLocation
            }
            if ($copilotEnabled) { $workloads += 'Copilot' }

            $policyResults += [PSCustomObject]@{
                PolicyName             = $policy.Name
                PolicyId               = $policy.Guid
                IsEnabled              = $policy.Enabled
                Mode                   = $policy.Mode
                Workloads              = ($workloads | ConvertTo-Json -Compress)
                CopilotLocationEnabled = $copilotEnabled
                SyncedAt               = $syncedAt
            }
        }
    }
    else {
        Write-Host "No DLP policies found in tenant" -ForegroundColor Yellow
    }

    # --- Export DLP Rules ---
    Write-Host "Retrieving DLP compliance rules..." -ForegroundColor Cyan
    $rules = Get-DlpComplianceRule

    $ruleResults = @()

    if ($rules) {
        Write-Host "Found $($rules.Count) DLP rules" -ForegroundColor Green

        foreach ($rule in $rules) {
            # Extract SIT conditions
            $sitConditions = @()
            if ($rule.ContentContainsSensitiveInformation) {
                foreach ($sitConfig in $rule.ContentContainsSensitiveInformation) {
                    $sitConditions += @{
                        Name            = $sitConfig.Name
                        MinCount        = $sitConfig.MinCount
                        MaxCount        = $sitConfig.MaxCount
                        MinConfidence   = $sitConfig.MinConfidence
                        MaxConfidence   = $sitConfig.MaxConfidence
                    }
                }
            }

            # Extract actions
            $actions = @()
            if ($rule.BlockAccess)               { $actions += 'BlockAccess' }
            if ($rule.NotifyUser)                { $actions += 'NotifyUser' }
            if ($rule.GenerateIncidentReport)    { $actions += 'GenerateIncidentReport' }
            if ($rule.EncryptContent)            { $actions += 'EncryptContent' }

            $ruleResults += [PSCustomObject]@{
                PolicyName    = $rule.ParentPolicyName
                RuleName      = $rule.Name
                SITConditions = ($sitConditions | ConvertTo-Json -Compress -Depth 5)
                Actions       = ($actions -join ', ')
                Severity      = $rule.AlertProperties.Severity
                SyncedAt      = $syncedAt
            }
        }
    }
    else {
        Write-Host "No DLP rules found in tenant" -ForegroundColor Yellow
    }

    # Export results
    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($policyResults.Count -gt 0) {
        $policiesFile = Join-Path $outputPath "DLP_Policies.csv"
        $policyResults | Export-Csv -Path $policiesFile -NoTypeInformation
        Write-Host "Policies exported to: $policiesFile" -ForegroundColor Green
    }

    if ($ruleResults.Count -gt 0) {
        $rulesFile = Join-Path $outputPath "DLP_Rules.csv"
        $ruleResults | Export-Csv -Path $rulesFile -NoTypeInformation
        Write-Host "Rules exported to: $rulesFile" -ForegroundColor Green
    }

    # Summary
    Write-Host "`n=== DLP Inventory Summary ===" -ForegroundColor Cyan
    Write-Host "Total policies: $($policyResults.Count)" -ForegroundColor Yellow
    $enabledCount = ($policyResults | Where-Object { $_.IsEnabled -eq $true }).Count
    Write-Host "Enabled policies: $enabledCount" -ForegroundColor Yellow
    $copilotCount = ($policyResults | Where-Object { $_.CopilotLocationEnabled -eq $true }).Count
    Write-Host "Policies with Copilot location: $copilotCount" -ForegroundColor $(if($copilotCount -gt 0){'Green'}else{'Red'})
    Write-Host "Total rules: $($ruleResults.Count)" -ForegroundColor Yellow

    $stopwatch.Stop()
    Write-Host "`nDLP inventory completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Security & Compliance PowerShell" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
    }
}
