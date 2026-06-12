#Requires -Version 7.2
<#
.SYNOPSIS
    Exports auto-sensitivity-labeling policy definitions and rules from Purview

.DESCRIPTION
    Retrieves all auto-sensitivity-labeling policies, their status (Simulation,
    Enabled, Disabled), target labels, and the SIT conditions that trigger labeling.

    For Classify: if a site has sensitive content but auto-labeling is active for
    that SIT type, the risk is lower. If there's no auto-labeling AND no manual
    labeling AND the SIT exists — that's a high-severity finding.

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
        throw 'A UserPrincipalName is required for interactive auto-label policy export.'
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

function Test-IppsAutoLabelCmdletAvailability {
    $getPolicyCommand = Get-Command -Name 'Get-AutoSensitivityLabelPolicy' -ErrorAction SilentlyContinue
    $getRuleCommand = Get-Command -Name 'Get-AutoSensitivityLabelRule' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HasGetAutoSensitivityLabelPolicy = $null -ne $getPolicyCommand
        HasGetAutoSensitivityLabelRule = $null -ne $getRuleCommand
    }
}

# Main execution
try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "=== Auto-Labeling Policy Inventory ===" -ForegroundColor Cyan
    Write-Host "Tenant (AAD): $AADTenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host ""

    # Connect to IPPS
    Connect-IPPSCompliance -CloudEnvironment $CloudEnvironment `
        -UserPrincipalName $UserPrincipalName

    $syncedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $ippsCmdlets = Test-IppsAutoLabelCmdletAvailability

    if (-not $ippsCmdlets.HasGetAutoSensitivityLabelPolicy) {
        throw 'Get-AutoSensitivityLabelPolicy is not available in this IPPS session. This tenant or role assignment does not expose auto-label policy cmdlets in the current connection.'
    }

    if (-not $ippsCmdlets.HasGetAutoSensitivityLabelRule) {
        throw 'Get-AutoSensitivityLabelRule is not available in this IPPS session. This tenant or role assignment does not expose auto-label rule cmdlets in the current connection.'
    }

    # --- Export Auto-Labeling Policies ---
    Write-Host "Retrieving auto-sensitivity-labeling policies..." -ForegroundColor Cyan
    $policies = Get-AutoSensitivityLabelPolicy

    $policyResults = @()

    if ($policies) {
        Write-Host "Found $($policies.Count) auto-labeling policies" -ForegroundColor Green

        # Get rules for all policies
        Write-Host "Retrieving auto-sensitivity-labeling rules..." -ForegroundColor Cyan
        $allRules = Get-AutoSensitivityLabelRule

        foreach ($policy in $policies) {
            # Determine workloads
            $workloads = @()
            if ($policy.SharePointLocation)  { $workloads += 'SPO' }
            if ($policy.OneDriveLocation)    { $workloads += 'ODB' }
            if ($policy.ExchangeLocation)    { $workloads += 'EXO' }

            # Determine status
            $status = 'Disabled'
            if ($policy.Mode -eq 'Enable') {
                $status = 'Enabled'
            }
            elseif ($policy.Mode -eq 'TestWithNotifications' -or $policy.Mode -eq 'TestWithoutNotifications') {
                $status = 'Simulation'
            }

            # Get SIT conditions from associated rules
            $policyRules = $allRules | Where-Object { $_.ParentPolicyName -eq $policy.Name }
            $sitConditions = @()
            foreach ($rule in $policyRules) {
                if ($rule.ContentContainsSensitiveInformation) {
                    foreach ($sitConfig in $rule.ContentContainsSensitiveInformation) {
                        $sitConditions += @{
                            Name          = $sitConfig.Name
                            MinCount      = $sitConfig.MinCount
                            MinConfidence = $sitConfig.MinConfidence
                        }
                    }
                }
            }

            # Site scope (included/excluded sites)
            $siteScope = @{
                Included = @($policy.SharePointLocation | Where-Object { $_ })
                Excluded = @($policy.SharePointLocationException | Where-Object { $_ })
            }

            $policyResults += [PSCustomObject]@{
                PolicyName      = $policy.Name
                PolicyId        = $policy.Guid
                Status          = $status
                TargetLabelName = $policy.ApplySensitivityLabel
                TargetLabelId   = $policy.ApplySensitivityLabel
                Workloads       = ($workloads | ConvertTo-Json -Compress)
                SITConditions   = ($sitConditions | ConvertTo-Json -Compress -Depth 5)
                SiteScope       = ($siteScope | ConvertTo-Json -Compress -Depth 3)
                SyncedAt        = $syncedAt
            }
        }
    }
    else {
        Write-Host "No auto-labeling policies found in tenant" -ForegroundColor Yellow
    }

    # Export results
    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($policyResults.Count -gt 0) {
        $outputFile = Join-Path $outputPath "AutoLabelPolicies.csv"
        $policyResults | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== Auto-Labeling Policy Summary ===" -ForegroundColor Cyan
        Write-Host "Total policies: $($policyResults.Count)" -ForegroundColor Yellow

        $enabledCount = ($policyResults | Where-Object { $_.Status -eq 'Enabled' }).Count
        $simCount = ($policyResults | Where-Object { $_.Status -eq 'Simulation' }).Count
        $disabledCount = ($policyResults | Where-Object { $_.Status -eq 'Disabled' }).Count
        Write-Host "Enabled: $enabledCount | Simulation: $simCount | Disabled: $disabledCount" -ForegroundColor Yellow

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo auto-labeling policies to export." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nAuto-labeling inventory completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
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
