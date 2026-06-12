#Requires -Version 7.2
<#
.SYNOPSIS
    Exports Purview retention policy and rule inventory from Security & Compliance PowerShell

.DESCRIPTION
    Retrieves retention compliance policies and their associated rules to build an
    inventory of retention coverage, workloads, modes, and rule settings.

    This script intentionally follows the isolated IPPS pattern used elsewhere in
    the repo to avoid the known module/session conflict with PnP.PowerShell and
    Microsoft.Graph modules. Run it only in the dedicated IPPS runner or in a
    fresh PowerShell session.

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
        throw 'A UserPrincipalName is required for interactive retention policy export.'
    }
}

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

function Test-IppsRetentionCmdletAvailability {
    $getPolicyCommand = Get-Command -Name 'Get-RetentionCompliancePolicy' -ErrorAction SilentlyContinue
    $getRuleCommand = Get-Command -Name 'Get-RetentionComplianceRule' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HasGetRetentionCompliancePolicy = $null -ne $getPolicyCommand
        HasGetRetentionComplianceRule   = $null -ne $getRuleCommand
    }
}

function Convert-PolicyLocationsToWorkloads {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    $workloads = @()

    if ($Policy.ExchangeLocation) { $workloads += 'EXO' }
    if ($Policy.SharePointLocation) { $workloads += 'SPO' }
    if ($Policy.OneDriveLocation) { $workloads += 'ODB' }
    if ($Policy.ModernGroupLocation) { $workloads += 'M365Group' }
    if ($Policy.TeamsChannelLocation) { $workloads += 'TeamsChannel' }
    if ($Policy.TeamsChatLocation) { $workloads += 'TeamsChat' }
    if ($Policy.SkypeLocation) { $workloads += 'Skype' }
    if ($Policy.PublicFolderLocation) { $workloads += 'PublicFolder' }

    return $workloads
}

try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "=== Retention Policy Inventory ===" -ForegroundColor Cyan
    Write-Host "Tenant (AAD): $AADTenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host "" 

    Connect-IPPSCompliance -CloudEnvironment $CloudEnvironment `
        -UserPrincipalName $UserPrincipalName

    $syncedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $ippsCmdlets = Test-IppsRetentionCmdletAvailability

    if (-not $ippsCmdlets.HasGetRetentionCompliancePolicy) {
        throw 'Get-RetentionCompliancePolicy is not available in this IPPS session. This tenant or role assignment does not expose retention policy cmdlets in the current connection.'
    }

    if (-not $ippsCmdlets.HasGetRetentionComplianceRule) {
        throw 'Get-RetentionComplianceRule is not available in this IPPS session. This tenant or role assignment does not expose retention rule cmdlets in the current connection.'
    }

    Write-Host "Retrieving retention compliance policies..." -ForegroundColor Cyan
    $policies = @(Get-RetentionCompliancePolicy)

    Write-Host "Retrieving retention compliance rules..." -ForegroundColor Cyan
    $rules = @(Get-RetentionComplianceRule)

    $policyResults = @()
    $ruleResults = @()

    if ($policies.Count -gt 0) {
        Write-Host "Found $($policies.Count) retention policies" -ForegroundColor Green

        foreach ($policy in $policies) {
            $workloads = Convert-PolicyLocationsToWorkloads -Policy $policy

            $policyResults += [PSCustomObject]@{
                PolicyName                  = $policy.Name
                PolicyId                    = $policy.Guid
                Enabled                     = $policy.Enabled
                Mode                        = $policy.Mode
                Workloads                   = ($workloads | ConvertTo-Json -Compress)
                ExchangeLocation            = ($policy.ExchangeLocation | ConvertTo-Json -Compress -Depth 5)
                SharePointLocation          = ($policy.SharePointLocation | ConvertTo-Json -Compress -Depth 5)
                OneDriveLocation            = ($policy.OneDriveLocation | ConvertTo-Json -Compress -Depth 5)
                ModernGroupLocation         = ($policy.ModernGroupLocation | ConvertTo-Json -Compress -Depth 5)
                TeamsChannelLocation        = ($policy.TeamsChannelLocation | ConvertTo-Json -Compress -Depth 5)
                TeamsChatLocation           = ($policy.TeamsChatLocation | ConvertTo-Json -Compress -Depth 5)
                ExchangeLocationException   = ($policy.ExchangeLocationException | ConvertTo-Json -Compress -Depth 5)
                SharePointLocationException = ($policy.SharePointLocationException | ConvertTo-Json -Compress -Depth 5)
                OneDriveLocationException   = ($policy.OneDriveLocationException | ConvertTo-Json -Compress -Depth 5)
                ModernGroupLocationException = ($policy.ModernGroupLocationException | ConvertTo-Json -Compress -Depth 5)
                TeamsChannelLocationException = ($policy.TeamsChannelLocationException | ConvertTo-Json -Compress -Depth 5)
                TeamsChatLocationException  = ($policy.TeamsChatLocationException | ConvertTo-Json -Compress -Depth 5)
                Comment                     = $policy.Comment
                Priority                    = $policy.Priority
                SyncedAt                    = $syncedAt
            }
        }
    }
    else {
        Write-Host "No retention policies found in tenant" -ForegroundColor Yellow
    }

    if ($rules.Count -gt 0) {
        Write-Host "Found $($rules.Count) retention rules" -ForegroundColor Green

        foreach ($rule in $rules) {
            $ruleResults += [PSCustomObject]@{
                PolicyName                    = $rule.ParentPolicyName
                RuleName                      = $rule.Name
                RuleId                        = $rule.Guid
                Disabled                      = $rule.Disabled
                RetentionDurationDisplayHint  = $rule.RetentionDurationDisplayHint
                RetentionComplianceAction     = $rule.RetentionComplianceAction
                ExpirationDateOption          = $rule.ExpirationDateOption
                ContentMatchQuery             = $rule.ContentMatchQuery
                ApplyComplianceTag            = $rule.ApplyComplianceTag
                PublishComplianceTag          = $rule.PublishComplianceTag
                RecordLabel                   = $rule.RecordLabel
                EventType                     = $rule.EventType
                PriorityCleanup               = $rule.PriorityCleanup
                SyncedAt                      = $syncedAt
            }
        }
    }
    else {
        Write-Host "No retention rules found in tenant" -ForegroundColor Yellow
    }

    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($policyResults.Count -gt 0) {
        $policiesFile = Join-Path $outputPath 'RetentionPolicies.csv'
        $policyResults | Export-Csv -Path $policiesFile -NoTypeInformation
        Write-Host "Policies exported to: $policiesFile" -ForegroundColor Green
    }
    else {
        Write-Host "No retention policies to export." -ForegroundColor Yellow
    }

    if ($ruleResults.Count -gt 0) {
        $rulesFile = Join-Path $outputPath 'RetentionPolicyRules.csv'
        $ruleResults | Export-Csv -Path $rulesFile -NoTypeInformation
        Write-Host "Rules exported to: $rulesFile" -ForegroundColor Green
    }
    else {
        Write-Host "No retention rules to export." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nRetention inventory completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
    }
}